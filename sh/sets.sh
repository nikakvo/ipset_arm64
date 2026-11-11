#!/system/bin/sh
# shellcheck shell=sh disable=SC2034
#
# sh/sets.sh - the ipset sets this module manages itself.
#
# Every managed set is named ipsa_* (reserved: the advanced toolkit refuses
# that prefix). Per address family (4 / 6):
#
#   ipsa_lan<f>     fixed special-purpose ranges: loopback, private LAN,
#                   carrier NAT, link-local, multicast... Never blocked.
#   ipsa_allow<f>   the user's allowlist (ip-allowlist.txt). Always wins
#                   over every blocklist.
#   ipsa_user<f>    the user's own blocklist (ip-blocklist.txt).
#   ipsa_out<f>     list:set - everything that blocks outgoing traffic
#   ipsa_in<f>      list:set - everything that blocks incoming traffic
#                   The firewall rules only ever reference these two; a list
#                   joins one or both (its direction), and joins or leaves
#                   without touching iptables.
#
# Contents are replaced atomically: a new set is filled next to the live
# one and swapped in, so there is never a moment with an empty list.

LAN4="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/3"
LAN6="::/128 ::1/128 fe80::/10 fc00::/7 ff00::/8 2001:db8::/32"

ALLOW_MAX=65536
USER_MAX=262144

fam_name() { if [ "$1" = "6" ]; then echo inet6; else echo inet; fi; }

set_exists() { "$IPSET" list -n 2>/dev/null | grep -qx "$1"; }

set_count() { # entries of a set; 0 when it does not exist
  _sc2=$("$IPSET" list -t "$1" 2>/dev/null | sed -n 's/^Number of entries: *//p' | head -n 1)
  echo "${_sc2:-0}"
  unset _sc2
}

# ── Entry parsing ────────────────────────────────────────────────────────────
# Reads a list file on stdin and prints the entries of one family, one per
# line. Comments (#...) and blank lines are skipped; invalid lines are
# counted on stderr as "invalid=N". IPv4 is checked exactly; IPv6 loosely
# (characters, prefix length) and ipset has the final word.
#   /0 is refused on purpose: hash:net cannot hold it, and "block the whole
#   internet" is what the master switch is for.
_parse_awk='
function v4ok(a,   p, n, i) {
  n = split(a, p, ".")
  if (n != 4) return 0
  for (i = 1; i <= 4; i++) {
    if (p[i] !~ /^[0-9]+$/ || length(p[i]) > 3 || p[i] + 0 > 255) return 0
  }
  return 1
}
{
  sub(/#.*/, "")
  gsub(/[ \t\r]/, "")
  if ($0 == "") next
  e = $0; a = e; pf = ""
  s = index(e, "/")
  if (s > 0) { a = substr(e, 1, s - 1); pf = substr(e, s + 1) }
  if (pf != "" && pf !~ /^[0-9]+$/) { bad++; next }
  n = pf + 0
  if (index(a, ":") > 0) {
    if (a !~ /^[0-9a-fA-F:.]+$/ || length(a) > 45 || (pf != "" && (n < 1 || n > 128))) { bad++; next }
    if (fam == 6) print tolower(e)
  } else {
    if (!v4ok(a) || (pf != "" && (n < 1 || n > 32))) { bad++; next }
    if (fam == 4) print e
  }
}
END { if (bad > 0) printf "invalid=%d\n", bad > "/dev/stderr" }
'

parse_entries() { # <family 4|6>  (stdin -> stdout)
  awk -v fam="$1" "$_parse_awk"
}

# Family of one entry: prints 4 or 6, returns 1 when it is not an address.
entry_family() {
  _ef_e=$1
  case "$_ef_e" in '' | *[!0-9a-fA-F.:/]*) unset _ef_e; return 1 ;; esac
  if [ -n "$(echo "$_ef_e" | parse_entries 4 2>/dev/null)" ]; then echo 4
  elif [ -n "$(echo "$_ef_e" | parse_entries 6 2>/dev/null)" ]; then echo 6
  else unset _ef_e; return 1
  fi
  unset _ef_e
}

# Canonical form for comparing list lines: lower case, no full-length prefix.
entry_canon() {
  echo "$1" | awk '{ e = tolower($0); sub(/\/32$/, "", e); if (index(e, ":")) sub(/\/128$/, "", e); print e }'
}

# ── Loading ──────────────────────────────────────────────────────────────────
# Fill <set> (hash:net, <family>) from the entries on stdin, atomically.
# Prints "loaded=N rejected=M". Returns 1 if the set could not be built -
# the live set is then left exactly as it was.
set_load() { # <set> <family 4|6> <maxelem>
  _sl_set=$1; _sl_fam=$(fam_name "$2"); _sl_max=$3
  _sl_tmp="${_sl_set}_n"
  _sl_in="$RUN/load.$$.in"
  _sl_bat="$RUN/load.$$.bat"
  mkdir -p "$RUN"
  cat > "$_sl_in"
  "$IPSET" destroy "$_sl_tmp" 2>/dev/null
  if ! "$IPSET" create "$_sl_tmp" hash:net family "$_sl_fam" maxelem "$_sl_max" 2>/dev/null; then
    rm -f "$_sl_in"
    unset _sl_set _sl_fam _sl_max _sl_tmp _sl_in _sl_bat
    return 1
  fi
  awk -v s="$_sl_tmp" 'NF { print "add " s " " $1 }' "$_sl_in" > "$_sl_bat"
  _sl_rej=0
  if ! "$IPSET" restore -exist < "$_sl_bat" 2>/dev/null; then
    # One bad line aborts a restore. Start again one entry at a time, so a
    # typo in a list costs that line, not the whole list.
    "$IPSET" flush "$_sl_tmp" 2>/dev/null
    while read -r _sl_e; do
      [ -n "$_sl_e" ] || continue
      "$IPSET" add "$_sl_tmp" "$_sl_e" -exist 2>/dev/null || _sl_rej=$((_sl_rej + 1))
    done < "$_sl_in"
  fi
  rm -f "$_sl_in" "$_sl_bat"
  if set_exists "$_sl_set"; then
    if ! "$IPSET" swap "$_sl_tmp" "$_sl_set" 2>/dev/null; then
      "$IPSET" destroy "$_sl_tmp" 2>/dev/null
      unset _sl_set _sl_fam _sl_max _sl_tmp _sl_rej _sl_e
      return 1
    fi
    "$IPSET" destroy "$_sl_tmp" 2>/dev/null
  else
    "$IPSET" rename "$_sl_tmp" "$_sl_set" 2>/dev/null || {
      "$IPSET" destroy "$_sl_tmp" 2>/dev/null
      unset _sl_set _sl_fam _sl_max _sl_tmp _sl_rej _sl_e
      return 1
    }
  fi
  echo "loaded=$(set_count "$_sl_set") rejected=$_sl_rej"
  unset _sl_set _sl_fam _sl_max _sl_tmp _sl_rej _sl_e
  return 0
}

# Load one family of a list file into its set. Logs what happened.
list_load() { # <allow|user> <family>
  case "$1" in
    allow) _ll_file=$ALLOW_FILE; _ll_max=$ALLOW_MAX ;;
    *)     _ll_file=$BLOCK_FILE; _ll_max=$USER_MAX ;;
  esac
  _ll_set="ipsa_$1$2"
  _ll_err="$RUN/parse.$$.err"
  if [ -f "$_ll_file" ]; then
    _ll_res=$(parse_entries "$2" < "$_ll_file" 2> "$_ll_err" | set_load "$_ll_set" "$2" "$_ll_max")
  else
    _ll_res=$(: | set_load "$_ll_set" "$2" "$_ll_max")
  fi
  _ll_rc=$?
  _ll_bad=$(sed -n 's/^invalid=//p' "$_ll_err" 2>/dev/null)
  rm -f "$_ll_err"
  if [ "$_ll_rc" -ne 0 ]; then
    log_error "could not load $_ll_set"
  else
    case "$_ll_res" in *"rejected=0"*) : ;; *) log_warn "$_ll_set: ipset refused some entries ($_ll_res)" ;; esac
    # The invalid count covers both families, so report it once, with v4,
    # and only when it changed - not on every reload of the same file.
    if [ "$2" = "4" ] && [ "${_ll_bad:-0}" != "$(cat "$RUN/invalid.$1" 2>/dev/null || echo 0)" ]; then
      [ -n "$_ll_bad" ] && log_warn "${_ll_file##*/}: $_ll_bad invalid line(s) ignored"
      echo "${_ll_bad:-0}" > "$RUN/invalid.$1"
    fi
  fi
  unset _ll_file _ll_max _ll_set _ll_err _ll_res _ll_bad
  return "$_ll_rc"
}

# ── Managed sets ─────────────────────────────────────────────────────────────
MANAGED_SETS="ipsa_lan4 ipsa_allow4 ipsa_user4 ipsa_out4 ipsa_in4 ipsa_dnsc4 ipsa_wgs4 ipsa_lan6 ipsa_allow6 ipsa_user6 ipsa_out6 ipsa_in6 ipsa_dnsc6 ipsa_wgs6"

# The managed sets that do not exist, space separated, in MM. One
# "ipset list -n", the rest without forks (the watchdog runs it every tick).
managed_missing_v() {
  _mm_have="
$("$IPSET" list -n 2>/dev/null)
"
  MM=""
  for _mm_s in $MANAGED_SETS; do
    case "$_mm_have" in
      *"
$_mm_s
"*) : ;;
      *) MM="${MM:+$MM }$_mm_s" ;;
    esac
  done
  unset _mm_have _mm_s
}
managed_missing() { # prints the managed sets that do not exist
  managed_missing_v
  for _mm_s in $MM; do echo "$_mm_s"; done
  unset _mm_s
}

_lan_load() { # <family>
  if [ "$1" = "6" ]; then _lan_l=$LAN6; else _lan_l=$LAN4; fi
  # shellcheck disable=SC2086
  printf '%s\n' $_lan_l | set_load "ipsa_lan$1" "$1" 1024 >/dev/null
  _lan_rc=$?
  unset _lan_l
  return "$_lan_rc"
}

# Make sure every managed set exists with the right content. Creates what
# is missing (so the firewall rules always have something to reference),
# reloads the fixed LAN ranges, and reloads the lists only when <reload>
# is 1 or their set had to be created. Returns 1 if anything failed.
sets_ensure() { # [reload 0|1]
  _se_rc=0
  for _se_f in 4 6; do
    _se_fn=$(fam_name "$_se_f")
    _lan_load "$_se_f" || { _se_rc=1; log_error "could not build ipsa_lan$_se_f"; }
    for _se_l in allow user; do
      if [ "${1:-0}" = "1" ] || ! set_exists "ipsa_$_se_l$_se_f"; then
        list_load "$_se_l" "$_se_f" || _se_rc=1
      fi
    done
    for _se_d in out in; do
      if ! set_exists "ipsa_$_se_d$_se_f"; then
        "$IPSET" create "ipsa_$_se_d$_se_f" list:set size 64 2>/dev/null ||
          { _se_rc=1; log_error "could not create ipsa_$_se_d$_se_f"; }
      fi
    done
    link_set "ipsa_user$_se_f" "$_se_f" "$(dir_of user)" || _se_rc=1
    if ! set_exists "ipsa_dnsc$_se_f"; then
      "$IPSET" create "ipsa_dnsc$_se_f" hash:net family "$(fam_name "$_se_f")" 2>/dev/null ||
        { _se_rc=1; log_error "could not create ipsa_dnsc$_se_f"; }
      rm -f "$RUN/dnsc.mtime"   # new, empty set: fill it below
    fi
    if ! set_exists "ipsa_wgs$_se_f"; then
      "$IPSET" create "ipsa_wgs$_se_f" hash:net family "$(fam_name "$_se_f")" 2>/dev/null ||
        { _se_rc=1; log_error "could not create ipsa_wgs$_se_f"; }
      rm -f "$RUN/wgs.stamp"    # new, empty set: fill it below
    fi
  done
  unset _se_f _se_fn _se_l _se_d
  return "$_se_rc"
}

# ── Directions ───────────────────────────────────────────────────────────────
# out, in or both for a list id (a source id, or "user" for your own list).
dir_of() {
  _do_d=both
  for _do_i in $(echo "$DIRECTIONS" | tr ',' ' '); do
    [ "${_do_i%%:*}" = "$1" ] && _do_d=${_do_i#*:}
  done
  echo "$_do_d"
  unset _do_d _do_i
}

# Make <set> a member of ipsa_out<f> and/or ipsa_in<f> as <dir> says, and
# of no other. Returns 1 if a membership could not be set.
link_set() { # <set> <family> <out|in|both>
  _lk_rc=0
  for _lk_a in out in; do
    case "$3" in
      both | "$_lk_a") "$IPSET" add "ipsa_$_lk_a$2" "$1" -exist 2>/dev/null || _lk_rc=1 ;;
      *) "$IPSET" del "ipsa_$_lk_a$2" "$1" 2>/dev/null ;;
    esac
  done
  unset _lk_a
  return "$_lk_rc"
}

# Is <set> linked exactly as <dir> says?
linked_as() { # <set> <family> <out|in|both>
  for _la2_a in out in; do
    if "$IPSET" test "ipsa_$_la2_a$2" "$1" >/dev/null 2>&1; then _la2_h=1; else _la2_h=0; fi
    case "$3" in both | "$_la2_a") _la2_w=1 ;; *) _la2_w=0 ;; esac
    [ "$_la2_h" = "$_la2_w" ] || { unset _la2_a _la2_h _la2_w; return 1; }
  done
  unset _la2_a _la2_h _la2_w
  return 0
}

# Destroy every managed set (uninstall). The firewall rules that reference
# them must be gone first, or the kernel refuses.
sets_destroy_managed() {
  for _sd_f in 4 6; do
    for _sd_s in "ipsa_out$_sd_f" "ipsa_in$_sd_f" "ipsa_block$_sd_f" "ipsa_dnsc$_sd_f" "ipsa_wgs$_sd_f" "ipsa_allow$_sd_f" "ipsa_user$_sd_f" "ipsa_lan$_sd_f"; do
      "$IPSET" destroy "$_sd_s" 2>/dev/null
      "$IPSET" destroy "${_sd_s}_n" 2>/dev/null
    done
  done
  unset _sd_f _sd_s
}

# ── Allow / block list files ─────────────────────────────────────────────────
list_file() { if [ "$1" = "allow" ]; then echo "$ALLOW_FILE"; else echo "$BLOCK_FILE"; fi; }

list_has() { # <allow|user> <entry>  (canonical comparison)
  _lh_f=$(list_file "$1")
  [ -f "$_lh_f" ] || { unset _lh_f; return 1; }
  _lh_c=$(entry_canon "$2")
  awk -v c="$_lh_c" '
    { sub(/#.*/, ""); gsub(/[ \t\r]/, ""); if ($0 == "") next
      e = tolower($0); sub(/\/32$/, "", e); if (index(e, ":")) sub(/\/128$/, "", e)
      if (e == c) { f = 1; exit } }
    END { exit !f }' "$_lh_f"
  _lh_rc=$?
  unset _lh_f _lh_c
  return "$_lh_rc"
}

# Would ipset accept this entry? Tried on a scratch set, never the live one.
entry_ipset_ok() { # <entry> <family>
  _eo_s="ipsa_chk${2}_$$"
  "$IPSET" destroy "$_eo_s" 2>/dev/null
  "$IPSET" create "$_eo_s" hash:net family "$(fam_name "$2")" 2>/dev/null || { unset _eo_s; return 1; }
  "$IPSET" add "$_eo_s" "$1" 2>/dev/null
  _eo_rc=$?
  "$IPSET" destroy "$_eo_s" 2>/dev/null
  unset _eo_s
  return "$_eo_rc"
}

# Add entries to a list file and reload its sets. Prints key=value.
# Nothing is written unless every entry is valid.
list_add() { # <allow|user> <entry...>
  _la_l=$1; shift
  _la_f=$(list_file "$_la_l")
  _la_new=""; _la_dup=0
  for _la_e in "$@"; do
    _la_fam=$(entry_family "$_la_e") || { echo "error=invalid address or network: $_la_e"; unset _la_l _la_f _la_new _la_dup _la_e _la_fam; return 1; }
    entry_ipset_ok "$_la_e" "$_la_fam" || { echo "error=ipset refused: $_la_e"; unset _la_l _la_f _la_new _la_dup _la_e _la_fam; return 1; }
    if list_has "$_la_l" "$_la_e"; then _la_dup=$((_la_dup + 1)); continue; fi
    _la_new="$_la_new $_la_e"
  done
  _la_n=0
  if [ -n "$_la_new" ]; then
    [ -f "$_la_f" ] || : > "$_la_f"
    # a file edited on a PC may lack the final newline
    [ -s "$_la_f" ] && [ -n "$(tail -c 1 "$_la_f" 2>/dev/null)" ] && echo >> "$_la_f"
    for _la_e in $_la_new; do echo "$_la_e" >> "$_la_f"; _la_n=$((_la_n + 1)); done
    list_load "$_la_l" 4 >/dev/null
    list_load "$_la_l" 6 >/dev/null
    mirror_to_sd "${_la_f##*/}"
  fi
  echo "added=$_la_n"
  echo "already_listed=$_la_dup"
  unset _la_l _la_f _la_new _la_dup _la_e _la_fam _la_n
  return 0
}

list_del() { # <allow|user> <entry...>
  _ld_l=$1; shift
  _ld_f=$(list_file "$_ld_l")
  _ld_n=0; _ld_miss=0
  for _ld_e in "$@"; do
    if ! list_has "$_ld_l" "$_ld_e"; then _ld_miss=$((_ld_miss + 1)); continue; fi
    _ld_c=$(entry_canon "$_ld_e")
    awk -v c="$_ld_c" '
      { l = $0; e = l; sub(/#.*/, "", e); gsub(/[ \t\r]/, "", e)
        e = tolower(e); sub(/\/32$/, "", e); if (index(e, ":")) sub(/\/128$/, "", e)
        if (e != "" && e == c) next
        print l }' "$_ld_f" > "$_ld_f.tmp" && mv -f "$_ld_f.tmp" "$_ld_f"
    _ld_n=$((_ld_n + 1))
  done
  if [ "$_ld_n" -gt 0 ]; then
    list_load "$_ld_l" 4 >/dev/null
    list_load "$_ld_l" 6 >/dev/null
    mirror_to_sd "${_ld_f##*/}"
  fi
  echo "removed=$_ld_n"
  echo "not_listed=$_ld_miss"
  unset _ld_l _ld_f _ld_n _ld_miss _ld_e _ld_c
  return 0
}

list_count() { # <allow|user> -> entries in the file (both families)
  _lc_f=$(list_file "$1")
  if [ -f "$_lc_f" ]; then
    { parse_entries 4 < "$_lc_f"; parse_entries 6 < "$_lc_f"; } 2>/dev/null | grep -c .
  else
    echo 0
  fi
  unset _lc_f
}

# ── Advanced toolkit sets (owned.list / sets.save) ──────────────────────────
own_list() { [ -s "$OWNED" ] && grep -v '^$' "$OWNED"; return 0; }
own_has()  { grep -qx "$1" "$OWNED" 2>/dev/null; }
own_add()  { own_has "$1" || echo "$1" >> "$OWNED"; }
own_remove() {
  grep -vx "$1" "$OWNED" > "$OWNED.tmp" 2>/dev/null
  mv -f "$OWNED.tmp" "$OWNED"
}

# Family of an existing set for iptables purposes: 4, 6, or "any" for the
# types without an address family (hash:mac, bitmap:port, list:set).
set_family() {
  _sf_h=$("$IPSET" list -t "$1" 2>/dev/null) || { unset _sf_h; return 1; }
  case "$_sf_h" in
    *"family inet6"*) echo 6 ;;
    *"family inet"*) echo 4 ;;
    *"Type: bitmap:ip"*) echo 4 ;;
    *) echo any ;;
  esac
  unset _sf_h
}

# Save the owned sets to sets.save. A set that is in the manifest but not
# loaded right now (it failed to restore at boot, say) keeps its previous
# saved copy - saving must never quietly delete a list from disk.
user_sets_save() {
  mkdir -p "$DATA"
  : > "$STATE.tmp"
  _us_have=$("$IPSET" list -n 2>/dev/null)
  _us_kept=0
  for _us_n in $(own_list); do
    if echo "$_us_have" | grep -qx "$_us_n"; then
      "$IPSET" save "$_us_n" >> "$STATE.tmp" 2>/dev/null
    elif [ -f "$STATE" ]; then
      awk -v n="$_us_n" '($1 == "create" || $1 == "add") && $2 == n' "$STATE" >> "$STATE.tmp"
      _us_kept=$((_us_kept + 1))
    fi
  done
  mv -f "$STATE.tmp" "$STATE"
  [ "$_us_kept" -gt 0 ] && log_warn "saved state: kept the previous copy of $_us_kept set(s) that are not loaded right now"
  unset _us_have _us_kept _us_n
  return 0
}

# Load sets.save. -exist: a set that already exists is filled, not an error.
user_sets_restore() {
  [ -s "$STATE" ] || return 0
  if "$IPSET" restore -exist < "$STATE" 2>/dev/null; then return 0; fi
  # One bad block aborts the whole restore; retry set by set so one broken
  # set costs only itself.
  _ur_bad=0
  for _ur_n in $(awk '$1 == "create" { print $2 }' "$STATE"); do
    awk -v n="$_ur_n" '($1 == "create" || $1 == "add") && $2 == n' "$STATE" |
      "$IPSET" restore -exist 2>/dev/null || { _ur_bad=$((_ur_bad + 1)); log_error "could not restore set $_ur_n"; }
  done
  unset _ur_n
  [ "$_ur_bad" -eq 0 ]
  _ur_rc=$?
  unset _ur_bad
  return "$_ur_rc"
}

# ── sdcard sync ──────────────────────────────────────────────────────────────
# Called by the watchdog with the lock held. A newer copy on the sdcard is a
# user edit: take it and reload the list. A newer copy in $DATA is the
# module's own write: mirror it out. A missing sdcard copy is seeded.
# What it did goes to SY_OUT, one line per action (empty when nothing
# changed); sd_sync prints it. One stat for all four files per call.
# Comment out entries wider than /8 (IPv4) or /16 (IPv6) in <file>; prints
# how many. Only for the allowlist taken from the sdcard copy. An entry that
# was already in <previous copy> (added in the WebUI, or kept from before)
# stays: only new wide entries written on the sdcard are refused.
sd_refuse_wide() { # <file> [previous copy]
  [ -f "${2:-}" ] || set -- "$1" /dev/null
  awk '
    function key(x) { sub(/#.*/, "", x); gsub(/[ \t\r]/, "", x); return tolower(x) }
    FILENAME == ARGV[1] { k = key($0); if (k != "") old[k] = 1; next }
    {
      l = $0; e = key(l); w = 0
      s = index(e, "/")
      if (e != "" && s > 0 && !(e in old)) {
        p = substr(e, s + 1) + 0
        if (e ~ /:/) { if (p < 16) w = 1 } else if (p < 8) w = 1
      }
      if (w) { print "# refused (wider than /8 or /16, from the sdcard copy): " e; n++ } else print l
    }
    END { print n + 0 > "/dev/stderr" }' "$2" "$1" > "$1.tmp" 2> "$1.n"
  first_line "$1.n"
  # rewrite only when something was refused: the file keeps the sdcard
  # copy's mtime otherwise (a rewrite would look like a new edit)
  case "$FL" in '' | 0) FL=0 ;; *) cat "$1.tmp" > "$1" ;; esac
  echo "$FL"
  rm -f "$1.tmp" "$1.n"
}
_sy_mt() { # <path> -> MT, from the stat output in _sy_st
  case "$_sy_st" in
    *" $1"*) MT=${_sy_st%%" $1"*}; MT=${MT##*"
"} ;;
    *) MT=$(mtime_of "$1") ;;
  esac
}
# The real shared storage is mounted (FUSE) a few seconds after the watchdog
# starts; before that /storage/emulated/0 can exist as an empty mount point.
# Seeding there would write into that hidden folder, and the first sync
# after the mount would then overwrite the real sdcard copies (seen on the
# phone at every boot). Android/ exists only on the mounted storage.
sd_ready() { [ -d "${SD_DIR%/*}/Android" ]; }
sd_sync_v() {
  SY_OUT=""
  sd_ready || return 0
  _sy_st=""
  for _sy_n in $SD_FILES; do _sy_st="$_sy_st $DATA/$_sy_n $SD_DIR/$_sy_n"; done
  # shellcheck disable=SC2086  # fixed paths without spaces
  _sy_st=$(stat -c '%Y %n' $_sy_st 2>/dev/null)
  for _sy_n in $SD_FILES; do
    _sy_d="$DATA/$_sy_n"; _sy_s="$SD_DIR/$_sy_n"
    [ -f "$_sy_d" ] || : > "$_sy_d"
    if [ ! -f "$_sy_s" ]; then
      mirror_to_sd "$_sy_n" && SY_OUT="${SY_OUT:+$SY_OUT
}seeded $_sy_s"
      continue
    fi
    _sy_mt "$_sy_d"; _sy_md=$MT; _sy_mt "$_sy_s"; _sy_ms=$MT
    if [ "$_sy_ms" -gt "$_sy_md" ]; then
      case "$_sy_n" in ip-allowlist.txt) _sy_l=allow ;; *) _sy_l=user ;; esac
      # the allowlist as it was before this edit (see sd_refuse_wide)
      [ "$_sy_l" = "allow" ] && cp -f "$_sy_d" "$RUN/sd.prev" 2>/dev/null
      cp -f "$_sy_s" "$_sy_d" 2>/dev/null || continue
      touch -r "$_sy_s" "$_sy_d" 2>/dev/null
      if [ "$_sy_l" = "allow" ]; then
        # Any app with "All files access" can write the sdcard copy. A very
        # wide allowlist entry from there (0.0.0.0/1 + 128.0.0.0/1 lets
        # everything through) is refused: commented out in both copies.
        _sy_w=$(sd_refuse_wide "$_sy_d" "$RUN/sd.prev")
        rm -f "$RUN/sd.prev"
        if [ "${_sy_w:-0}" -gt 0 ]; then
          mirror_to_sd "$_sy_n"
          log_warn "sdcard: refused $_sy_w allowlist entr$([ "$_sy_w" = 1 ] && echo y || echo ies) wider than /8 (IPv4) or /16 (IPv6) - add such ranges in the WebUI if you really mean it"
        fi
      fi
      list_load "$_sy_l" 4 >/dev/null
      list_load "$_sy_l" 6 >/dev/null
      SY_OUT="${SY_OUT:+$SY_OUT
}applied edit of $_sy_s ($(list_count "$_sy_l") entries)"
    elif [ "$_sy_md" -gt "$_sy_ms" ]; then
      mirror_to_sd "$_sy_n"
    fi
  done
  unset _sy_n _sy_d _sy_s _sy_md _sy_ms _sy_l _sy_st _sy_w MT
}
sd_sync() { sd_sync_v; [ -n "$SY_OUT" ] && echo "$SY_OUT"; return 0; }
