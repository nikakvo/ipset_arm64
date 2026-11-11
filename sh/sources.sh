#!/system/bin/sh
# shellcheck shell=sh disable=SC2034
#
# sh/sources.sh - downloadable blocklists.
#
# Each source is a list of networks from the internet. It is downloaded,
# cleaned, checked and kept in $CACHE/<id>.txt; the copy in the kernel is
# the set ipsa_src_<id>, a member of ipsa_out<f> and/or ipsa_in<f> (its
# direction, see DIRECTIONS). The firewall rules only reference those, so a
# source joining, leaving, changing direction or being refreshed never
# touches iptables.
#
#   - A download that fails, or yields fewer entries than the source's
#     floor, never replaces the last good copy: the list must never
#     silently shrink because one download went wrong.
#   - Special-purpose ranges (LAN, loopback, carrier NAT, multicast...)
#     are removed from every source - edge-router lists contain them.
#   - Downloads run without the module lock (they can take minutes); only
#     loading the result into the kernel takes it.

# id | family | group | label | format | url | floor | description
SRC_CATALOG='firehol-level1|4|FireHOL|Level 1|netset|https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset|3000|Recommended. Botnets, malware control servers, hijacked networks - chosen for a minimum of false positives.
firehol-level2|4|FireHOL|Level 2|netset|https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset|8000|Attacks seen in the last 48 hours. Some false positives possible.
firehol-level3|4|FireHOL|Level 3|netset|https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset|5000|Attackers, spyware and malware seen in the last 30 days. More false positives.
firehol-level4|4|FireHOL|Level 4|netset|https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level4.netset|80000|Aggressive and very large (~160,000 networks). Expect false positives.
firehol-webclient|4|FireHOL|Web client|netset|https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webclient.netset|200|A small list of addresses web browsers and apps should never talk to.
spamhaus-dropv6|6|Spamhaus|DROPv6|spamhaus|https://www.spamhaus.org/drop/drop_v6.json|10|Recommended. IPv6 networks hijacked or operated by professional cyber-crime. Data (c) The Spamhaus Project.'

SRC_ATTEMPT_MIN=3600      # automatic attempts on one source: at least 1 h apart
UPDATE_LOCK="$RUN/update.lock"
UPDATE_LOG="$RUN/update.log"
UPDATE_RESULT="$RUN/update.result"
LAST_UPDATE="$DATA/cache/.last_update"   # the last update's outcome, kept across reboots

# ── Catalog ──────────────────────────────────────────────────────────────────
# Ids, families and set names are read from the catalog once, when this
# file is sourced (no forks): the watchdog looks them up every tick.
_src_setname() { # <id> -> SS=ipsa_src_<id with - as _>
  SS="ipsa_src_"; _sn_t=$1
  while :; do
    case "$_sn_t" in
      *-*) SS="$SS${_sn_t%%-*}_"; _sn_t=${_sn_t#*-} ;;
      *) SS="$SS$_sn_t"; break ;;
    esac
  done
  unset _sn_t
}
SRC_IDS=""      # one id per line, catalog order
SRC_MAP=" "     # " <id>:<family>:<set> ..."
while IFS='|' read -r _sc_i _sc_f _sc_r; do
  [ -n "$_sc_i" ] || continue
  _src_setname "$_sc_i"
  SRC_IDS="${SRC_IDS:+$SRC_IDS
}$_sc_i"
  SRC_MAP="$SRC_MAP$_sc_i:$_sc_f:$SS "
done <<EOF
$SRC_CATALOG
EOF
unset _sc_i _sc_f _sc_r SS

# <id> -> SF (family) and SS (set name); returns 1 for an unknown id.
src_lookup() {
  case "$SRC_MAP" in
    *" $1:"*)
      SS=${SRC_MAP#* "$1":}; SS=${SS%% *}
      SF=${SS%%:*}; SS=${SS#*:}
      return 0 ;;
  esac
  SF=""; _src_setname "$1"
  return 1
}

src_ids() { echo "$SRC_IDS"; }
src_known() { case "$SRC_MAP" in *" $1:"*) return 0 ;; esac; return 1; }
src_field() { # <id> <field number>
  echo "$SRC_CATALOG" | awk -F'|' -v id="$1" -v n="$2" '$1 == id { print $n; exit }'
}
src_family() { src_lookup "$1"; echo "$SF"; }
src_set() { src_lookup "$1"; echo "$SS"; }
src_file() { echo "$CACHE/$1.txt"; }
src_meta() { echo "$CACHE/$1.meta"; }

# Enabled ids, one per line, in catalog order (unknown ids are ignored).
src_enabled() {
  [ "$SOURCES" = "none" ] && return 0
  for _se_i in $SRC_IDS; do
    case ",$SOURCES," in *",$_se_i,"*) echo "$_se_i" ;; esac
  done
  unset _se_i
}
src_is_enabled() {
  [ "$SOURCES" = "none" ] && return 1
  src_known "$1" || return 1
  case ",$SOURCES," in *",$1,"*) return 0 ;; esac
  return 1
}

meta_get() { # <id> <key>
  sed -n "s/^$2=//p" "$(src_meta "$1")" 2>/dev/null | head -n 1
}

# ── Cleaning ─────────────────────────────────────────────────────────────────
# IPv4 entries that overlap a special-purpose range are dropped whole (a
# /8 that contains 10.0.0.0/8 would block the LAN just the same).
filter_special4() {
  awk -v lan="$LAN4" '
    function ip2n(s,  p) { split(s, p, "."); return ((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4] }
    function lo_of(c,  a, b, x, r, k) {
      a = c; b = 32
      if (index(c, "/")) { split(c, r, "/"); a = r[1]; b = r[2] + 0 }
      # no ^ or %: busybox awk built without its math library has neither
      x = ip2n(a); SZ = 1
      for (k = b; k < 32; k++) SZ = SZ * 2
      return int(x / SZ) * SZ
    }
    BEGIN { n = split(lan, L, " "); for (i = 1; i <= n; i++) { lo[i] = lo_of(L[i]); hi[i] = lo[i] + SZ - 1 } }
    { a = lo_of($1); z = a + SZ - 1
      for (i = 1; i <= n; i++) if (a <= hi[i] && z >= lo[i]) next
      print $1 }'
}

# IPv6: the special ranges are few and short prefixes; anything inside them,
# or a network so wide it would contain them (shorter than /16), is dropped.
filter_special6() {
  awk '{
    e = tolower($1); p = 128
    if (index(e, "/")) { split(e, r, "/"); p = r[2] + 0 }
    if (p < 16) next
    if (e ~ /^(fe[89ab]|f[cd]|ff)/) next
    if (e ~ /^::/ || e ~ /^0*:/) next
    if (e ~ /^2001:0*db8:/) next
    print $1 }'
}

# Raw download -> clean entry list (one per line, sorted, unique).
src_clean() { # <id> <raw file>  -> stdout
  _sc_fam=$(src_family "$1")
  case "$(src_field "$1" 5)" in
    spamhaus)
      # NDJSON: one {"cidr":"...","sblid":...} per line, then a metadata line
      sed -n 's/.*"cidr"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$2" ;;
    *)
      cat "$2" ;;
  esac | parse_entries "$_sc_fam" 2>/dev/null | {
    if [ "$_sc_fam" = "6" ]; then filter_special6; else filter_special4; fi
  } | sort -u
  unset _sc_fam
}

# ── Download ─────────────────────────────────────────────────────────────────
# Fetch one source into the cache. Does not take the module lock and does
# not touch the kernel. Prints one line of result; returns 1 on failure (the
# previous cache, if any, stays in place).
src_fetch() { # <id>
  _sf_id=$1
  mkdir -p "$CACHE" "$RUN"
  _sf_raw="$RUN/dl.$_sf_id.raw"
  _sf_new="$RUN/dl.$_sf_id.new"
  _sf_meta=$(src_meta "$_sf_id")
  _sf_floor=$(src_field "$_sf_id" 7)
  _sf_url=$(src_field "$_sf_id" 6)
  _sf_err=""

  if ! dl "$_sf_url" "$_sf_raw"; then
    _sf_err="download failed (no connection, or no working curl/wget)"
  else
    src_clean "$_sf_id" "$_sf_raw" > "$_sf_new"
    _sf_n=$(grep -c . "$_sf_new")
    if [ "$_sf_n" -lt "$_sf_floor" ]; then
      _sf_err="only $_sf_n entries (expected at least $_sf_floor) - source format changed or download truncated"
    fi
  fi

  if [ -n "$_sf_err" ]; then
    rm -f "$_sf_raw" "$_sf_new"
    # keep the last good copy's facts, record the failure next to them
    {
      grep -vE '^(status|error|failed_at)=' "$_sf_meta" 2>/dev/null
      echo "status=fail"
      echo "error=$_sf_err"
      echo "failed_at=$(clock_sane && date +%s || echo 0)"
    } > "$_sf_meta.tmp"
    mv -f "$_sf_meta.tmp" "$_sf_meta"
    echo "$_sf_id: FAILED - $_sf_err$([ -s "$(src_file "$_sf_id")" ] && echo " (keeping the last good copy)")"
    unset _sf_id _sf_raw _sf_new _sf_meta _sf_floor _sf_url _sf_err _sf_n
    return 1
  fi

  _sf_stamp=""
  if [ "$(src_field "$_sf_id" 5)" = "spamhaus" ]; then
    _sf_stamp=$(sed -n 's/.*"timestamp"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' "$_sf_raw" | tail -n 1)
  fi
  mv -f "$_sf_new" "$(src_file "$_sf_id")"
  rm -f "$_sf_raw"
  {
    echo "status=ok"
    echo "count=$_sf_n"
    echo "updated=$(clock_sane && date +%s || echo 0)"
    echo "from=download"
    if [ -n "$_sf_stamp" ]; then echo "source_timestamp=$_sf_stamp"; fi
  } > "$_sf_meta.tmp"
  mv -f "$_sf_meta.tmp" "$_sf_meta"
  echo "$_sf_id: ok - $_sf_n entries"
  unset _sf_id _sf_raw _sf_new _sf_meta _sf_floor _sf_url _sf_err _sf_n _sf_stamp
  return 0
}

# ── Kernel ───────────────────────────────────────────────────────────────────
# Load a source's cache into its set and link it for its direction.
# The caller holds the lock.
src_load() { # <id>
  _sl2_f=$(src_family "$1"); _sl2_s=$(src_set "$1"); _sl2_c=$(src_file "$1")
  [ -s "$_sl2_c" ] || { unset _sl2_f _sl2_s _sl2_c; return 1; }
  _sl2_n=$(grep -c . "$_sl2_c")
  _sl2_max=65536
  while [ "$_sl2_max" -lt $((_sl2_n + _sl2_n / 4)) ]; do _sl2_max=$((_sl2_max * 2)); done
  # maxelem is fixed at creation: a list that outgrew its set gets a new one
  if set_exists "$_sl2_s"; then
    _sl2_cur=$("$IPSET" list -t "$_sl2_s" 2>/dev/null | sed -n 's/.*maxelem \([0-9]*\).*/\1/p')
    if [ "${_sl2_cur:-0}" -lt "$_sl2_max" ]; then
      link_set "$_sl2_s" "$_sl2_f" none
      "$IPSET" destroy "$_sl2_s" 2>/dev/null
    fi
  fi
  if ! set_load "$_sl2_s" "$_sl2_f" "$_sl2_max" < "$_sl2_c" >/dev/null; then
    log_error "source $1: could not load into the kernel"
    unset _sl2_f _sl2_s _sl2_c _sl2_n _sl2_max _sl2_cur
    return 1
  fi
  link_set "$_sl2_s" "$_sl2_f" "$(dir_of "$1")"
  unset _sl2_f _sl2_s _sl2_c _sl2_n _sl2_max _sl2_cur
  return 0
}

src_unload() { # <id>
  _su_s=$(src_set "$1")
  link_set "$_su_s" "$(src_family "$1")" none
  "$IPSET" destroy "$_su_s" 2>/dev/null
  "$IPSET" destroy "${_su_s}_n" 2>/dev/null
  unset _su_s
}

src_in_kernel() { # <id> : its set is loaded (linked for some direction)
  src_lookup "$1"
  "$IPSET" test "ipsa_out$SF" "$SS" >/dev/null 2>&1 ||
    "$IPSET" test "ipsa_in$SF" "$SS" >/dev/null 2>&1
}

# Bring the kernel in line with SOURCES: load enabled sources that are not
# loaded (from cache), unload disabled ones. Cheap when nothing changed.
# The caller holds the lock.
sources_sync() {
  for _ss_i in $(src_ids); do
    if src_is_enabled "$_ss_i"; then
      if set_exists "$(src_set "$_ss_i")"; then
        # loaded: only make sure the direction is right
        linked_as "$(src_set "$_ss_i")" "$(src_family "$_ss_i")" "$(dir_of "$_ss_i")" && continue
        link_set "$(src_set "$_ss_i")" "$(src_family "$_ss_i")" "$(dir_of "$_ss_i")" &&
          log_info "source $_ss_i: now blocks $(dir_of "$_ss_i")" && continue
      fi
      [ -s "$(src_file "$_ss_i")" ] || continue
      src_load "$_ss_i" && log_info "source $_ss_i: loaded $(set_count "$(src_set "$_ss_i")") entries"
    elif set_exists "$(src_set "$_ss_i")"; then
      src_unload "$_ss_i"
      log_info "source $_ss_i: disabled, unloaded (cache kept)"
    fi
  done
  unset _ss_i
}

sources_destroy_all() {
  for _sda_i in $(src_ids); do src_unload "$_sda_i"; done
  unset _sda_i
}

# ── Update job ───────────────────────────────────────────────────────────────
# One updater at a time (separate from the module lock).
UPDATE_PENDING="$RUN/update.pending"
update_running() {
  first_line "$UPDATE_LOCK/pid"; _ur_p=$FL
  if [ -n "$_ur_p" ] && [ -d "/proc/$_ur_p" ]; then unset _ur_p; return 0; fi
  unset _ur_p
  # spawned, but the worker has not taken its lock yet (a few ms; 30 s at
  # most, in case it died before that)
  if [ -f "$UPDATE_PENDING" ]; then
    _ur_t=$(cat "$UPDATE_PENDING" 2>/dev/null)
    case "$_ur_t" in '' | *[!0-9]*) _ur_t=0 ;; esac
    [ $(( $(mono_now) - _ur_t )) -lt 30 ] && { unset _ur_t; return 0; }
    rm -f "$UPDATE_PENDING"
  fi
  unset _ur_t
  return 1
}

update_lock() {
  mkdir -p "$RUN"
  if ! mkdir "$UPDATE_LOCK" 2>/dev/null; then
    _ul_p=$(cat "$UPDATE_LOCK/pid" 2>/dev/null)
    if [ -n "$_ul_p" ] && [ -d "/proc/$_ul_p" ]; then unset _ul_p; return 1; fi
    unset _ul_p
    rm -rf "$UPDATE_LOCK"
    mkdir "$UPDATE_LOCK" 2>/dev/null || return 1
  fi
  echo $$ > "$UPDATE_LOCK/pid"
  rm -f "$UPDATE_PENDING"
}
update_unlock() { [ "$(cat "$UPDATE_LOCK/pid" 2>/dev/null)" = "$$" ] && rm -rf "$UPDATE_LOCK"; }

# Remember an automatic attempt, for spacing: "<mono> <consecutive fails>"
_attempt_file() { echo "$RUN/attempt.$1"; }
attempt_note() { # <id> <ok|fail>
  _an_f=0
  if [ "$2" = "fail" ]; then
    _an_f=$(cut -d' ' -f2 "$(_attempt_file "$1")" 2>/dev/null)
    _an_f=$(( ${_an_f:-0} + 1 ))
  fi
  echo "$(mono_now) $_an_f" > "$(_attempt_file "$1")"
  unset _an_f
}

# Start the updater detached. <mode> manual|auto, then ids (default: enabled).
# The check and the pending marker are one step under a short spawn lock
# (mkdir is atomic), so two callers at the same moment (the watchdog's
# automatic update and a tap in the WebUI) never both start a worker, and
# the second one never empties the log of the first.
UPDATE_SPAWN_LOCK="$RUN/update.spawn"
update_spawn() { # <mode> [ids...]
  if ! mkdir "$UPDATE_SPAWN_LOCK" 2>/dev/null; then
    # left by a caller that was killed in these few ms: stale after 30 s
    _us_age=$(( $(date +%s) - $(mtime_of "$UPDATE_SPAWN_LOCK") ))
    if [ "$_us_age" -ge 30 ] || [ "$_us_age" -lt -30 ]; then
      rmdir "$UPDATE_SPAWN_LOCK" 2>/dev/null
      mkdir "$UPDATE_SPAWN_LOCK" 2>/dev/null || { unset _us_age; return 1; }
    else
      unset _us_age; return 1
    fi
    unset _us_age
  fi
  if update_running; then rmdir "$UPDATE_SPAWN_LOCK" 2>/dev/null; return 1; fi
  : > "$UPDATE_LOG"
  rm -f "$UPDATE_RESULT"
  mono_now > "$UPDATE_PENDING"
  if command -v setsid >/dev/null 2>&1; then
    setsid sh "$MODDIR/ctl.sh" _update "$@" < /dev/null >> "$UPDATE_LOG" 2>&1 &
  else
    nohup sh "$MODDIR/ctl.sh" _update "$@" < /dev/null >> "$UPDATE_LOG" 2>&1 &
  fi
  rmdir "$UPDATE_SPAWN_LOCK" 2>/dev/null
  return 0
}

# Which enabled sources an automatic update should fetch now (space
# separated, empty = none). Nothing at all while AUTO_UPDATE=off: the module
# never downloads on its own unless the user switched this on. When on, a
# source without any cache is fetched first (retries after 2 min, 10 min,
# then hourly); a cached one follows the interval by the wall clock once it
# is sane, and never more than once an hour per source.
auto_due() {
  case "$AUTO_UPDATE" in
    daily) _ad_int=86400 ;;
    weekly) _ad_int=604800 ;;
    *) return 0 ;;
  esac
  _ad_now=$(mono_now)
  _ad_out=""
  for _ad_i in $(src_enabled); do
    _ad_last=""; _ad_fails=0
    if [ -f "$(_attempt_file "$_ad_i")" ]; then
      read -r _ad_last _ad_fails < "$(_attempt_file "$_ad_i")"
    fi
    if [ ! -s "$(src_file "$_ad_i")" ]; then
      case "${_ad_fails:-0}" in 0) _ad_gap=0 ;; 1) _ad_gap=120 ;; 2) _ad_gap=600 ;; *) _ad_gap=3600 ;; esac
      if [ -z "$_ad_last" ] || [ $((_ad_now - _ad_last)) -ge "$_ad_gap" ]; then _ad_out="$_ad_out $_ad_i"; fi
      continue
    fi
    clock_sane || continue
    [ -n "$_ad_last" ] && [ $((_ad_now - _ad_last)) -lt "$SRC_ATTEMPT_MIN" ] && continue
    _ad_up=$(meta_get "$_ad_i" updated)
    case "$_ad_up" in '' | *[!0-9]*) _ad_up=0 ;; esac
    [ $(( $(date +%s) - _ad_up )) -ge "$_ad_int" ] && _ad_out="$_ad_out $_ad_i"
  done
  echo "${_ad_out# }"
  unset _ad_now _ad_out _ad_int _ad_i _ad_last _ad_fails _ad_gap _ad_up
}

# When will the next automatic update start (wall-clock seconds), or
# nothing if automatic updates are off or the clock is not set yet. The
# same rules as auto_due: a list is due one interval after its last good
# download, a list without any copy at once, and never sooner than the
# spacing after the previous attempt. The watchdog looks once a minute, so
# the real start is up to a minute later.
auto_next() {
  case "$AUTO_UPDATE" in
    daily) _an2_int=86400 ;;
    weekly) _an2_int=604800 ;;
    *) return 0 ;;
  esac
  clock_sane || { unset _an2_int; return 0; }
  _an2_now=$(date +%s); _an2_mono=$(mono_now); _an2_best=""
  for _an2_i in $(src_enabled); do
    if [ -s "$(src_file "$_an2_i")" ]; then
      _an2_up=$(meta_get "$_an2_i" updated)
      case "$_an2_up" in '' | *[!0-9]*) _an2_up=0 ;; esac
      _an2_n=$((_an2_up + _an2_int)); _an2_gap=$SRC_ATTEMPT_MIN
    else
      _an2_n=$_an2_now; _an2_gap=0
    fi
    if [ -f "$(_attempt_file "$_an2_i")" ]; then
      read -r _an2_last _an2_fails < "$(_attempt_file "$_an2_i")"
      if [ ! -s "$(src_file "$_an2_i")" ]; then
        case "${_an2_fails:-0}" in 0) _an2_gap=0 ;; 1) _an2_gap=120 ;; 2) _an2_gap=600 ;; *) _an2_gap=3600 ;; esac
      fi
      _an2_e=$((_an2_now + _an2_last + _an2_gap - _an2_mono))
      [ "$_an2_e" -gt "$_an2_n" ] && _an2_n=$_an2_e
    fi
    if [ -z "$_an2_best" ] || [ "$_an2_n" -lt "$_an2_best" ]; then _an2_best=$_an2_n; fi
  done
  if [ -n "$_an2_best" ]; then
    [ "$_an2_best" -lt "$_an2_now" ] && _an2_best=$_an2_now
    echo "$_an2_best"
  fi
  unset _an2_int _an2_now _an2_mono _an2_best _an2_i _an2_up _an2_n _an2_gap _an2_last _an2_fails _an2_e
}

# ── Migration of the r9 / r10-stage1 threat feed ────────────────────────────
# The old feed was a hand-style set (feed_firehol_level1) with rules in the
# advanced toolkit. It becomes the firehol-level1 source: its entries seed
# the cache (no download needed), its rules and set are removed. Runs once.
LEGACY_FEED="feed_firehol_level1"
LEGACY_MARK="$DATA/.legacy_feed_migrated"

# Step 1, before the chains are rebuilt: files only.
legacy_feed_migrate_files() {
  [ -f "$LEGACY_MARK" ] && return 0
  if own_has "$LEGACY_FEED" || grep -q "|$LEGACY_FEED|" "$RULES" 2>/dev/null; then
    mkdir -p "$CACHE"
    if [ ! -s "$(src_file firehol-level1)" ] && [ -s "$STATE" ]; then
      awk -v n="$LEGACY_FEED" '$1 == "add" && $2 == n { print $3 }' "$STATE" | parse_entries 4 2>/dev/null |
        filter_special4 | sort -u > "$(src_file firehol-level1).tmp"
      if [ -s "$(src_file firehol-level1).tmp" ]; then
        mv -f "$(src_file firehol-level1).tmp" "$(src_file firehol-level1)"
        printf 'status=ok\ncount=%s\nupdated=0\nfrom=legacy-feed\n' \
          "$(grep -c . "$(src_file firehol-level1)")" > "$(src_meta firehol-level1)"
      fi
      rm -f "$(src_file firehol-level1).tmp"
    fi
    _lm_n=$(grep -c "|$LEGACY_FEED|" "$RULES" 2>/dev/null)
    grep -v "|$LEGACY_FEED|" "$RULES" > "$RULES.tmp" 2>/dev/null
    mv -f "$RULES.tmp" "$RULES"
    if ! src_is_enabled firehol-level1; then
      if [ "$SOURCES" = "none" ]; then set_setting SOURCES firehol-level1
      else set_setting SOURCES "firehol-level1,$SOURCES"; fi
      load_settings
    fi
    log_info "migration: the old threat feed is now the firehol-level1 source ($_lm_n old rule(s) removed)"
    : > "$RUN/legacy_feed_pending"
    unset _lm_n
  fi
  : > "$LEGACY_MARK"
}

# Step 2, after the chains no longer reference it: the old set itself.
legacy_feed_migrate_set() {
  [ -f "$RUN/legacy_feed_pending" ] || return 0
  if set_exists "$LEGACY_FEED" && ! "$IPSET" destroy "$LEGACY_FEED" 2>/dev/null; then
    return 0   # still referenced somewhere; the next apply tries again
  fi
  own_remove "$LEGACY_FEED"
  if [ -f "$STATE" ]; then
    awk -v n="$LEGACY_FEED" '!(($1 == "create" || $1 == "add") && $2 == n)' "$STATE" > "$STATE.tmp" &&
      mv -f "$STATE.tmp" "$STATE"
  fi
  rm -f "$DATA/feed_firehol_level1.meta" "$CACHE/firehol_level1.netset" "$RUN/legacy_feed_pending"
}

# Entries of a source's cache, optionally only those containing <filter>
# (plain text, address characters only), at most <limit>.
src_entries() { # <id> [filter] [limit]
  _sx_f=$(src_file "$1")
  [ -s "$_sx_f" ] || return 0
  if [ -n "${2:-}" ]; then grep -F -- "$2" "$_sx_f"; else cat "$_sx_f"; fi | head -n "${3:-500}"
  unset _sx_f
}
