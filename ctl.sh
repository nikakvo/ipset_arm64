#!/system/bin/sh
# ctl.sh - command-line control for ipset-arm64.
#
#   su -c '/system/bin/sh /data/adb/modules/ipset_arm64/ctl.sh status'
#
# Output is key=value, one per line. ok=1 / ok=0 (+ error=...) on every
# command that changes something. Exit code 0 = ok, 1 = failed, 2 = usage.
#
# Commands:
#   poll                      cheap state, for a dashboard refreshing often
#   status                    full check (capabilities, chains, sets, counts)
#   apply                     rebuild sets and firewall rules now
#   enable | disable          master switch (persistent)
#   pause <minutes> | resume  suspend enforcement for 1..1440 minutes
#   set <KEY> <VALUE>         change a setting (see settings.conf)
#   settings                  print the settings in effect
#   allow add|del <ip/cidr...>   allowlist (always wins)
#   allow list
#   block add|del <ip/cidr...>   your own blocklist
#   block list
#   sources                   the source catalog with state of each list
#   sources set <id,id|none>  choose the enabled sources
#   sources enable|disable <id>
#   sources dir <id|user> <out|in|both>   which traffic a list blocks
#   sources view <id> [filter]            the networks in a list (max 500)
#   update [id...]            download lists now (background; default: enabled)
#   update-status             is an update running, and how the last one went
#   check <ip>                which lists hold this address, and the verdict
#   probe <ip> [port]         open a real TCP connection from this phone
#                             (default port 443) and say whether it got
#                             through, and whether this module stopped it
#   log [lines]               module log (default 200 lines)
#   log-clear

MODDIR=${0%/*}
case "$MODDIR" in
  /*) : ;;
  *) MODDIR="$(cd "$MODDIR" 2>/dev/null && pwd)" ;;
esac

if [ ! -f "$MODDIR/sh/common.sh" ]; then
  echo "ok=0"
  echo "error=sh/common.sh missing - reflash the module"
  exit 1
fi
# shellcheck source=/dev/null
. "$MODDIR/sh/common.sh"

if [ "$(id -u 2>/dev/null)" != "0" ]; then
  echo "ok=0"
  echo "error=must run as root"
  exit 1
fi

mkdir -p "$DATA" "$RUN"
load_settings
trap 'lock_release; update_unlock' EXIT
trap 'lock_release; update_unlock; exit 1' INT TERM HUP PIPE

fail() { echo "ok=0"; echo "error=$*"; exit 1; }
usage() { echo "ok=0"; echo "error=usage: $*"; exit 2; }

need_lock() {
  lock_get 30 || fail "busy - another operation is still running, try again"
}

need_ipset() {
  [ -n "$IPSET" ] && "$IPSET" --version >/dev/null 2>&1 || fail "ipset binary not found or not runnable"
}

yn() { if "$@" >/dev/null 2>&1; then echo 1; else echo 0; fi; }

health_get() { sed -n "s/^$1=//p" "$HEALTH_FILE" 2>/dev/null | head -n 1; }

watchdog_pid() {
  _wp=$(cat "$WATCHDOG_PIDFILE" 2>/dev/null)
  if [ -n "$_wp" ] && tr '\0' ' ' 2>/dev/null < "/proc/$_wp/cmdline" | grep -q 'service\.sh'; then
    echo "$_wp"
  fi
  unset _wp
}

# Overall state from the family results:
#   protected | partial | paused | disabled | error
overall_state() {
  if [ "$ENABLED" != "1" ]; then echo disabled; return; fi
  if is_paused; then echo paused; return; fi
  _os4=$(fam_state 4); _os6=$(fam_state 6)
  case "$_os4" in
    ok | ok-drop) : ;;
    *) echo error; unset _os4 _os6; return ;;
  esac
  case "$_os6" in
    ok | ok-drop) echo protected ;;
    off) if [ "$IPV6" = "1" ]; then echo partial; else echo protected; fi ;;
    *) echo partial ;;
  esac
  unset _os4 _os6
}

# A settings change that needs no rebuild: tell the watchdog it is handled.
_settings_seen() { conf_stamp > "$APPLIED_CONF_MTIME"; }

# After a change: apply, then report what the firewall is actually in.
apply_and_report() {
  if rules_apply; then echo "ok=1"; else echo "ok=0"; echo "error=IPv4 firewall rules could not be applied (see log)"; fi
  echo "state=$(overall_state)"
  echo "ipv4=$(fam_state 4)"
  echo "ipv6=$(fam_state 6)"
}

# ── poll ─────────────────────────────────────────────────────────────────────
# Everything the dashboard shows, cheaply: one iptables call per family and
# one ipset call. Packet counters count since the rules were last applied
# (every apply rebuilds the chains).
_hits() { # <family> -> "out in fwd adv"
  # r11: counters from "iptables-save -c" (no xtables lock), not "-L -v"
  ipt_dump "$1" -c | awk '
    $1 !~ /^\[/ || $2 != "-A" { next }
    {
      c = $3
      if (c !~ /^IPSA_/) next
      t = ""
      for (k = 4; k < NF; k++) if ($k == "-j") { t = $(k + 1); break }
      if (t != "REJECT" && t != "DROP") next
      n = $1; sub(/^\[/, "", n); sub(/:.*/, "", n)
      if (c ~ /^IPSA_ADV_/) adv += n
      else if (index($0, "ipsa_out") || index($0, "ipsa_in")) {
        if (c == "IPSA_OUT") o += n; else if (c == "IPSA_IN") i += n; else if (c == "IPSA_FWD") f += n
      }
    }
    END { printf "%d %d %d %d\n", o, i, f, adv }'
}

cmd_poll() {
  echo "state=$(overall_state)"
  echo "ipv4=$(fam_state 4)"
  echo "ipv6=$(fam_state 6)"
  echo "enabled=$ENABLED"
  echo "paused_left=$(pause_left)"
  _p_w=$(watchdog_pid)
  echo "watchdog=$([ -n "$_p_w" ] && echo running || echo stopped)"
  _p_t=$(health_get tick_at)
  case "$_p_t" in '' | *[!0-9]*) echo "tick_age=" ;; *) echo "tick_age=$(( $(mono_now) - _p_t ))" ;; esac
  echo "repairs=$(health_get repairs)"
  _p_ap=$(cat "$RUN/applied_at" 2>/dev/null)
  case "$_p_ap" in '' | *[!0-9]*) echo "applied_ago=" ;; *) echo "applied_ago=$(( $(mono_now) - _p_ap ))" ;; esac
  echo "auto_update=$AUTO_UPDATE"
  echo "update_running=$(yn update_running)"
  echo "now=$(clock_sane && date +%s)"
  echo "auto_next=$(auto_next)"
  for _p_k in wall mode ok fail failed; do
    echo "last_update_$_p_k=$(sed -n "s/^$_p_k=//p" "$LAST_UPDATE" 2>/dev/null | head -n 1)"
  done

  # entries per set, from one listing of all set headers
  "$IPSET" list -t 2>/dev/null | awk '/^Name:/ { n = $2 } /^Number of entries:/ { print n, $4 }' > "$RUN/poll.$$.counts"
  _p_cnt() { awk -v n="$1" '$1 == n { print $2; f = 1 } END { if (!f) print 0 }' "$RUN/poll.$$.counts"; }
  _p_e4=0; _p_e6=0; _p_on=0; _p_ld=0
  for _p_i in $(src_enabled); do
    _p_on=$((_p_on + 1))
    _p_c=$(_p_cnt "$(src_set "$_p_i")")
    [ "$_p_c" -gt 0 ] && _p_ld=$((_p_ld + 1))
    if [ "$(src_family "$_p_i")" = "6" ]; then _p_e6=$((_p_e6 + _p_c)); else _p_e4=$((_p_e4 + _p_c)); fi
  done
  _p_u4=$(_p_cnt ipsa_user4); _p_u6=$(_p_cnt ipsa_user6)
  echo "sources_enabled=$_p_on"
  echo "sources_loaded=$_p_ld"
  echo "entries4=$((_p_e4 + _p_u4))"
  echo "entries6=$((_p_e6 + _p_u6))"
  echo "block_entries=$((_p_u4 + _p_u6))"
  echo "allow_entries=$(( $(_p_cnt ipsa_allow4) + $(_p_cnt ipsa_allow6) ))"
  rm -f "$RUN/poll.$$.counts"
  # nothing to block at all: no list loaded and the own blocklist empty
  if [ "$_p_ld" -eq 0 ] && [ $((_p_u4 + _p_u6)) -eq 0 ]; then echo "lists_empty=1"; else echo "lists_empty=0"; fi

  # shellcheck disable=SC2046
  set -- $(_hits 4)
  _p_o=${1:-0}; _p_in=${2:-0}; _p_f=${3:-0}; _p_a=${4:-0}
  if v6_supported && [ "$IPV6" = "1" ]; then
    # shellcheck disable=SC2046
    set -- $(_hits 6)
    _p_o=$((_p_o + ${1:-0})); _p_in=$((_p_in + ${2:-0})); _p_f=$((_p_f + ${3:-0})); _p_a=$((_p_a + ${4:-0}))
  fi
  echo "blocked_out=$_p_o"
  echo "blocked_in=$_p_in"
  echo "blocked_fwd=$_p_f"
  echo "adv_hits=$_p_a"
  echo "version=$(sed -n 's/^version=//p' "$MODPROP" 2>/dev/null)"
  unset _p_k _p_w _p_t _p_ap _p_e4 _p_e6 _p_on _p_ld _p_i _p_c _p_u4 _p_u6 _p_o _p_in _p_f _p_a
}

# ── status ───────────────────────────────────────────────────────────────────

kcfg() { # <SYMBOL> -> y / m / n / ?
  if [ -r /proc/config.gz ]; then
    _kc=$(zcat /proc/config.gz 2>/dev/null | sed -n "s/^CONFIG_$1=//p")
    echo "${_kc:-n}"
    unset _kc
  else
    echo "?"
  fi
}

cmd_status() {
  echo "version=$(sed -n 's/^version=//p' "$MODPROP" 2>/dev/null)"
  echo "version_code=$(sed -n 's/^versionCode=//p' "$MODPROP" 2>/dev/null)"
  echo "ipset_binary=$IPSET"
  echo "ipset_version=$("$IPSET" --version 2>/dev/null | head -n 1 | sed 's/^ipset //; s/,.*//')"
  echo "iptables=${IPT4:-missing}"
  echo "ip6tables=${IPT6:-missing}"
  echo "iptables_restore=$([ -n "$RST4" ] && echo 1 || echo 0)"
  echo "ip6tables_restore=$([ -n "$RST6" ] && echo 1 || echo 0)"
  echo "kernel=$(uname -r 2>/dev/null)"
  echo "kcfg_ip_set=$(kcfg IP_SET)"
  echo "kcfg_xt_set=$(kcfg NETFILTER_XT_SET)"
  echo "kcfg_ip6_reject=$(kcfg IP6_NF_TARGET_REJECT)"
  echo "selinux=$(getenforce 2>/dev/null || echo unknown)"

  _s_w=$(watchdog_pid)
  echo "watchdog=$([ -n "$_s_w" ] && echo running || echo stopped)"
  echo "watchdog_pid=${_s_w:-}"
  echo "state=$(overall_state)"
  echo "enabled=$ENABLED"
  echo "paused_left=$(pause_left)"
  echo "ipv4=$(fam_state 4)"
  echo "ipv6=$(fam_state 6)"
  for _s_f in 4 6; do
    [ "$_s_f" = "6" ] && ! v6_supported && continue
    for _s_p in $IPSA_JUMPS; do
      _s_b=${_s_p%%:*}; _s_c=${_s_p#*:}
      echo "jump${_s_f}_$(echo "$_s_b" | tr 'A-Z' 'a-z')=$([ "$(jump_count "$_s_f" "$_s_b" "$_s_c")" -gt 0 ] && echo 1 || echo 0)"
    done
  done
  echo "out_target=$OUT_TARGET"
  echo "forward_block=$FORWARD_BLOCK"
  echo "ipv6_setting=$IPV6"
  _s_now=$(mono_now)
  _s_ap=$(cat "$RUN/applied_at" 2>/dev/null)
  echo "applied_ago=$([ -n "$_s_ap" ] && echo $((_s_now - _s_ap)))"
  echo "repairs=$(health_get repairs)"
  echo "last_repair=$(health_get last_repair)"

  for _s_f in 4 6; do
    for _s_n in lan allow user; do
      echo "count_${_s_n}${_s_f}=$(set_count "ipsa_$_s_n$_s_f")"
    done
  done
  echo "allow_entries=$(list_count allow)"
  echo "block_entries=$(list_count user)"
  echo "missing_sets=$(managed_missing | tr '\n' ' ' | sed 's/ $//')"

  echo "sources_enabled=$(src_enabled | tr '\n' ',' | sed 's/,$//')"
  _s_miss=""
  for _s_n in $(src_enabled); do src_in_kernel "$_s_n" || _s_miss="$_s_miss,$_s_n"; done
  echo "sources_not_loaded=${_s_miss#,}"
  echo "auto_update=$AUTO_UPDATE"
  echo "update_running=$(yn update_running)"
  if [ "$DNSCRYPT_ALLOW" != "1" ]; then echo "dnscrypt=off"
  elif dnsc_present; then echo "dnscrypt=found"
  else echo "dnscrypt=absent"; fi
  echo "dnscrypt_setting=$DNSCRYPT_ALLOW"
  echo "dnscrypt_addrs=$(( $(set_count ipsa_dnsc4) + $(set_count ipsa_dnsc6) ))"
  if [ "$WGSHIELD_ALLOW" != "1" ]; then echo "wgshield=off"
  elif wgs_present; then echo "wgshield=found"
  else echo "wgshield=absent"; fi
  echo "wgshield_setting=$WGSHIELD_ALLOW"
  echo "wgshield_addrs=$(( $(set_count ipsa_wgs4) + $(set_count ipsa_wgs6) ))"
  first_line "$RUN/wgs.hostnames"
  echo "wgshield_hostnames=${FL:-0}"
  lanc_keys
  echo "adv_sets=$(own_list | grep -c .)"
  echo "adv_rules=$(grep -c . "$RULES" 2>/dev/null || echo 0)"
  _s_sk=$(cat "$RUN"/adv_skipped.* 2>/dev/null | sort -u | grep -c .)
  _s_rj=$(cat "$RUN"/adv_rejected.* 2>/dev/null | grep -c .)
  echo "adv_rules_skipped=$_s_sk"
  echo "adv_rules_rejected=$_s_rj"
  unset _s_w _s_f _s_p _s_b _s_c _s_now _s_ap _s_n _s_sk _s_rj _s_miss
  echo "ok=1"
}

# ── check ────────────────────────────────────────────────────────────────────
cmd_check() {
  _c_ip=$1
  [ -n "$_c_ip" ] || usage "check <ip>"
  _c_f=$(entry_family "$_c_ip") || fail "not an IPv4/IPv6 address: $_c_ip"
  intest() { "$IPSET" test "$1" "$_c_ip" >/dev/null 2>&1 && echo 1 || echo 0; }
  _c_lan=$(intest "ipsa_lan$_c_f")
  _c_allow=$(intest "ipsa_allow$_c_f")
  _c_user=$(intest "ipsa_user$_c_f")
  _c_dnsc=$(intest "ipsa_dnsc$_c_f")
  _c_wgs=$(intest "ipsa_wgs$_c_f")
  echo "ok=1"
  echo "ip=$_c_ip"
  echo "family=$_c_f"
  echo "in_lan=$_c_lan"
  echo "in_allowlist=$_c_allow"
  echo "in_blocklist=$_c_user"
  echo "dnscrypt_resolver=$_c_dnsc"
  echo "wgshield_server=$_c_wgs"
  echo "note_checked=your lists and the enabled sources that are loaded"
  # Advanced sets are matched by your own rules, before any of the above.
  _c_adv=""
  for _c_n in $(own_list); do
    _c_sf=$(set_family "$_c_n") || continue
    [ "$_c_sf" = "$_c_f" ] || continue
    [ "$(intest "$_c_n")" = "1" ] && _c_adv="$_c_adv,$_c_n"
  done
  echo "in_advanced_sets=${_c_adv#,}"
  # which lists hold it, and for which traffic each of them blocks
  _c_blocked_by=""; _c_in_by=""; _c_listed=""
  if [ "$_c_user" = "1" ]; then
    _c_listed="blocklist"
    case "$(dir_of user)" in both | out) _c_blocked_by="blocklist" ;; esac
    case "$(dir_of user)" in both | in) _c_in_by="blocklist" ;; esac
  fi
  for _c_n in $(src_enabled); do
    [ "$(src_family "$_c_n")" = "$_c_f" ] || continue
    [ "$(intest "$(src_set "$_c_n")")" = "1" ] || continue
    _c_listed="${_c_listed:+$_c_listed,}$_c_n"
    case "$(dir_of "$_c_n")" in both | out) _c_blocked_by="${_c_blocked_by:+$_c_blocked_by,}$_c_n" ;; esac
    case "$(dir_of "$_c_n")" in both | in) _c_in_by="${_c_in_by:+$_c_in_by,}$_c_n" ;; esac
  done
  echo "listed_in=$_c_listed"
  echo "blocked_in_by=$_c_in_by"
  if [ "$_c_lan" = "1" ]; then _c_v=allowed_special_range
  elif [ "$_c_allow" = "1" ]; then _c_v=allowed_allowlist
  elif [ "$_c_dnsc" = "1" ]; then _c_v=allowed_dnscrypt
  elif [ "$_c_wgs" = "1" ]; then _c_v=allowed_wgshield
  elif [ -n "$_c_blocked_by" ] && [ -n "$_c_in_by" ]; then _c_v=blocked
  elif [ -n "$_c_blocked_by" ]; then _c_v=blocked_out
  elif [ -n "$_c_in_by" ]; then _c_v=blocked_in
  else _c_v=not_listed
  fi
  echo "blocked_by=$_c_blocked_by"
  echo "verdict=$_c_v"
  [ "$(overall_state)" = "protected" ] || [ "$(overall_state)" = "partial" ] || echo "note=enforcement is currently $(overall_state)"
  [ -n "$_c_adv" ] && echo "note_advanced=advanced rules are evaluated first and may decide differently"
  unset _c_ip _c_f _c_lan _c_allow _c_user _c_dnsc _c_wgs _c_adv _c_n _c_sf _c_blocked_by _c_in_by _c_listed _c_v
}

# ── probe ──────────────────────────────────────────────────────────────────
# A real connection attempt, like curl from a terminal. The verdict about
# the module comes from its own rule counters (before/after), not from the
# timing: refused + counter up = rejected here; timeout + counter up =
# dropped here; no counter change = decided somewhere else (the host, the
# network, another firewall).
_cs_now() { # centiseconds since boot
  read -r _cn_u _cn_r < /proc/uptime
  _cn_i=${_cn_u%.*}; _cn_f=${_cn_u#*.}
  echo "$_cn_i${_cn_f}"
  unset _cn_u _cn_r _cn_i _cn_f
}

_nc_bin() { # prints "<nc command>@<mode>": z = has -z, q = has -q, - = neither
  # ("@", not "|": mksh reads | inside ${x%pattern} as alternation)
  for _nb in "$BB nc" "nc" "toybox nc"; do
    [ "$_nb" = " nc" ] && continue
    # shellcheck disable=SC2086
    _nb_h=$($_nb --help 2>&1) || true
    case "$_nb_h" in *"Usage"* | *"usage"* | *"-w"*) : ;; *) continue ;; esac
    case "$_nb_h" in *"-z"*) echo "$_nb@z" ;; *"-q"*) echo "$_nb@q" ;; *) echo "$_nb@-" ;; esac
    unset _nb _nb_h; return 0
  done
  unset _nb _nb_h
  return 1
}

cmd_probe() {
  _pr_ip=${1:-}; _pr_port=${2:-443}
  [ -n "$_pr_ip" ] || usage "probe <ip> [port]"
  case "$_pr_ip" in */*) fail "give one address, not a network" ;; esac
  _pr_f=$(entry_family "$_pr_ip") || fail "not an IPv4/IPv6 address: $_pr_ip"
  case "$_pr_port" in '' | *[!0-9]*) fail "port must be a number" ;; esac
  { [ "$_pr_port" -ge 1 ] && [ "$_pr_port" -le 65535 ]; } || fail "port must be 1..65535"
  _pr_nc=$(_nc_bin) || fail "no nc (netcat) found - busybox or toybox is needed for this test"
  _pr_cmd=${_pr_nc%@*}; _pr_mode=${_pr_nc##*@}

  # shellcheck disable=SC2046
  set -- $(_hits "$_pr_f"); _pr_o0=${1:-0}; _pr_i0=${2:-0}
  _pr_t0=$(_cs_now)
  # shellcheck disable=SC2086
  case "$_pr_mode" in
    z) timeout 8 $_pr_cmd -z -w 4 "$_pr_ip" "$_pr_port" < /dev/null > /dev/null 2>&1 ;;
    q) timeout 8 $_pr_cmd -w 4 -q 0 "$_pr_ip" "$_pr_port" < /dev/null > /dev/null 2>&1 ;;
    *) timeout 6 $_pr_cmd -w 4 "$_pr_ip" "$_pr_port" < /dev/null > /dev/null 2>&1 ;;
  esac
  _pr_rc=$?
  _pr_ms=$(( ($(_cs_now) - _pr_t0) * 10 ))
  # shellcheck disable=SC2046
  set -- $(_hits "$_pr_f"); _pr_do=$(( ${1:-0} - _pr_o0 )); _pr_di=$(( ${2:-0} - _pr_i0 ))
  [ "$_pr_do" -lt 0 ] && _pr_do=0   # rules were rebuilt meanwhile
  [ "$_pr_di" -lt 0 ] && _pr_di=0

  if [ "$_pr_rc" -eq 0 ]; then _pr_res=connected
  elif [ "$_pr_rc" -eq 124 ] && [ "$_pr_mode" = "-" ] && [ "$_pr_do$_pr_di" = "00" ]; then
    _pr_res=connected   # connected; the server just kept the line open
  elif [ "$_pr_ms" -lt 1500 ]; then _pr_res=refused
  else _pr_res=timeout
  fi
  _pr_by=0
  [ "$_pr_res" != "connected" ] && [ $((_pr_do + _pr_di)) -gt 0 ] && _pr_by=1
  echo "ok=1"
  echo "ip=$_pr_ip"
  echo "port=$_pr_port"
  echo "family=$_pr_f"
  echo "result=$_pr_res"
  echo "ms=$_pr_ms"
  echo "blocked_by_module=$_pr_by"
  echo "module_hits_out=$_pr_do"
  echo "module_hits_in=$_pr_di"
  echo "state=$(overall_state)"
  unset _pr_ip _pr_port _pr_f _pr_nc _pr_cmd _pr_mode _pr_o0 _pr_i0 _pr_t0 _pr_rc _pr_ms _pr_do _pr_di _pr_res _pr_by
}

# ── lists ────────────────────────────────────────────────────────────────────
cmd_list() { # <allow|user> <add|del|list> [entries]
  _l_which=$1; _l_op=${2:-}
  shift 2 2>/dev/null
  case "$_l_op" in
    list)
      _l_f=$(list_file "$_l_which")
      echo "ok=1"
      echo "file=$_l_f"
      echo "entries=$(list_count "$_l_which")"
      [ "$_l_which" = "user" ] && echo "dir=$(dir_of user)"
      echo "@@LIST@@"
      [ -f "$_l_f" ] && { parse_entries 4 < "$_l_f"; parse_entries 6 < "$_l_f"; } 2>/dev/null
      ;;
    add | del)
      [ $# -ge 1 ] || usage "${_l_which} $_l_op <ip/cidr...>"
      need_lock
      if [ "$_l_op" = "add" ]; then _l_out=$(list_add "$_l_which" "$@"); else _l_out=$(list_del "$_l_which" "$@"); fi
      _l_rc=$?
      case "$_l_out" in error=*) echo "ok=0"; echo "$_l_out"; exit 1 ;; esac
      [ "$_l_rc" -eq 0 ] || fail "could not update the list"
      echo "ok=1"
      echo "$_l_out"
      echo "entries=$(list_count "$_l_which")"
      log_info "${_l_which} list: $_l_op $*"
      ;;
    *) usage "allow|block add|del|list" ;;
  esac
  unset _l_which _l_op _l_f _l_out _l_rc
}

# ── sources ──────────────────────────────────────────────────────────────────
cmd_sources_list() {
  echo "ok=1"
  echo "sources=$SOURCES"
  echo "auto_update=$AUTO_UPDATE"
  echo "update_running=$(yn update_running)"
  echo "@@SOURCES@@"
  echo "id|family|group|label|enabled|loaded|cached|updated|status|error|dir|description"
  for _sl_i in $(src_ids); do
    _sl_on=0; src_is_enabled "$_sl_i" && _sl_on=1
    _sl_ld=0; src_in_kernel "$_sl_i" && _sl_ld=$(set_count "$(src_set "$_sl_i")")
    echo "$_sl_i|$(src_family "$_sl_i")|$(src_field "$_sl_i" 3)|$(src_field "$_sl_i" 4)|$_sl_on|${_sl_ld:-0}|$(meta_get "$_sl_i" count)|$(meta_get "$_sl_i" updated)|$(meta_get "$_sl_i" status)|$(meta_get "$_sl_i" error | tr '|' '/')|$(dir_of "$_sl_i")|$(src_field "$_sl_i" 8)"
  done
  unset _sl_i _sl_on _sl_ld
}

# Apply a new SOURCES value: load what is cached, fetch what is not.
sources_apply() { # <new value>
  setting_valid SOURCES "$1" || fail "unknown source in '$1' (see: ctl.sh sources)"
  need_ipset; need_lock
  set_setting SOURCES "$1"
  log_info "sources: $1"
  load_settings
  # Lists join and leave ipsa_block*; the firewall rules stay as they are
  # (and so do their packet counters).
  sets_ensure 0 >/dev/null 2>&1
  sources_sync
  _settings_seen
  _sa_need=""
  for _sa_i in $(src_enabled); do [ -s "$(src_file "$_sa_i")" ] || _sa_need="$_sa_need $_sa_i"; done
  lock_release
  echo "ok=1"
  echo "sources=$SOURCES"
  if [ -n "$_sa_need" ]; then
    # shellcheck disable=SC2086
    if update_spawn manual $_sa_need; then echo "downloading=${_sa_need# }"
    else echo "downloading="; echo "note=an update is already running; run 'update' again afterwards"; fi
  fi
  unset _sa_need _sa_i
}

cmd_sources() {
  case "${1:-}" in
    "") cmd_sources_list ;;
    set) [ -n "${2:-}" ] || usage "sources set <id,id,...|none>"; sources_apply "$2" ;;
    enable | disable)
      [ -n "${2:-}" ] || usage "sources $1 <id>"
      src_known "$2" || fail "unknown source '$2'"
      _cs_new=""
      for _cs_i in $(src_ids); do
        if [ "$_cs_i" = "$2" ]; then
          [ "$1" = "enable" ] && _cs_new="$_cs_new,$_cs_i"
        elif src_is_enabled "$_cs_i"; then
          _cs_new="$_cs_new,$_cs_i"
        fi
      done
      _cs_new=${_cs_new#,}
      sources_apply "${_cs_new:-none}"
      ;;
    dir)
      # which traffic a list blocks: sources dir <id|user> <out|in|both>
      [ -n "${2:-}" ] && [ -n "${3:-}" ] || usage "sources dir <id|user> <out|in|both>"
      { [ "$2" = "user" ] || src_known "$2"; } || fail "unknown list '$2'"
      case "$3" in out | in | both) : ;; *) usage "sources dir <id|user> <out|in|both>" ;; esac
      need_lock
      _cd_new=""
      for _cd_i in $(echo "$DIRECTIONS" | tr ',' ' '); do
        [ "${_cd_i%%:*}" = "$2" ] || _cd_new="$_cd_new,$_cd_i"
      done
      [ "$3" = "both" ] || _cd_new="$_cd_new,$2:$3"
      set_setting DIRECTIONS "${_cd_new#,}" || fail "could not save the direction"
      load_settings
      sets_ensure 0 >/dev/null 2>&1
      sources_sync
      _settings_seen
      log_info "direction: $2 blocks $3"
      echo "ok=1"
      echo "list=$2"
      echo "dir=$(dir_of "$2")"
      ;;
    view)
      # sources view <id> [filter]: the networks in a list (cache), max 500
      src_known "${2:-}" || fail "unknown source '${2:-}'"
      _cv_q=${3:-}
      case "$_cv_q" in *[!0-9a-fA-F.:/]*) fail "search: digits, a-f, dots, colons and / only" ;; esac
      echo "ok=1"
      echo "total=$(grep -c . "$(src_file "$2")" 2>/dev/null || echo 0)"
      if [ -n "$_cv_q" ]; then echo "matches=$(grep -cF -- "$_cv_q" "$(src_file "$2")" 2>/dev/null || echo 0)"; fi
      echo "dir=$(dir_of "$2")"
      echo "@@LIST@@"
      src_entries "$2" "$_cv_q" 500
      ;;
    *) usage "sources [set <ids>|enable <id>|disable <id>|dir <id|user> <dir>|view <id> [filter]]" ;;
  esac
}

cmd_update() { # [ids]
  for _u_i in "$@"; do src_known "$_u_i" || fail "unknown source '$_u_i'"; done
  if [ $# -eq 0 ] && [ -z "$(src_enabled)" ]; then fail "no sources are enabled"; fi
  update_spawn manual "$@" || fail "an update is already running"
  echo "ok=1"
  echo "started=1"
  echo "sources=${*:-$(src_enabled | tr '\n' ' ' | sed 's/ $//')}"
  unset _u_i
}

cmd_update_status() {
  echo "ok=1"
  echo "running=$(yn update_running)"
  [ -f "$UPDATE_RESULT" ] && cat "$UPDATE_RESULT"
  echo "@@LOG@@"
  tail -n 40 "$UPDATE_LOG" 2>/dev/null
}

# The detached worker (started by update_spawn).
cmd__update() { # <manual|auto> [ids]
  _w_mode=${1:-manual}; shift 2>/dev/null
  update_lock || { echo "$(_ts) another update is running"; exit 1; }
  _w_ids="$*"
  [ -n "$_w_ids" ] || _w_ids=$(src_enabled | tr '\n' ' ')
  echo "$(_ts) update ($_w_mode): $_w_ids"
  _w_ok=0; _w_fail=0; _w_failed=""; _w_notify=""
  for _w_i in $_w_ids; do
    src_known "$_w_i" || continue
    if src_fetch "$_w_i"; then _w_r=ok; _w_ok=$((_w_ok + 1))
    else _w_r=fail; _w_fail=$((_w_fail + 1)); _w_failed="$_w_failed,$_w_i"; fi
    attempt_note "$_w_i" "$_w_r"
    # tell the user once per failure streak: at the 3rd automatic failure
    # in a row (attempts are at least an hour apart), not on every retry
    if [ "$_w_mode" = "auto" ] && [ "$_w_r" = "fail" ]; then
      read -r _w_t _w_n 2>/dev/null < "$(_attempt_file "$_w_i")"
      [ "${_w_n:-0}" = "3" ] && _w_notify="$_w_notify, $(src_field "$_w_i" 3) $(src_field "$_w_i" 4)"
    fi
    load_settings
    src_is_enabled "$_w_i" || continue
    [ -s "$(src_file "$_w_i")" ] || continue
    if [ "$_w_r" = "ok" ] || ! src_in_kernel "$_w_i"; then
      if lock_get 120; then
        if src_load "$_w_i"; then echo "$_w_i: loaded $(set_count "$(src_set "$_w_i")") entries"
        else echo "$_w_i: could not load into the kernel"; fi
        lock_release
      else
        echo "$_w_i: module busy, not loaded now (the watchdog loads it)"
      fi
    fi
  done
  echo "$(_ts) done: $_w_ok ok, $_w_fail failed"
  {
    echo "finished_at=$(mono_now)"
    echo "finished_wall=$(clock_sane && date +%s || echo 0)"
    echo "mode=$_w_mode"
    echo "ok_count=$_w_ok"
    echo "fail_count=$_w_fail"
  } > "$UPDATE_RESULT"
  mkdir -p "$CACHE"
  {
    echo "wall=$(clock_sane && date +%s || echo 0)"
    echo "mode=$_w_mode"
    echo "ok=$_w_ok"
    echo "fail=$_w_fail"
    echo "failed=${_w_failed#,}"
  } > "$LAST_UPDATE.tmp" && mv -f "$LAST_UPDATE.tmp" "$LAST_UPDATE"
  if [ "$_w_fail" -gt 0 ]; then log_warn "update ($_w_mode): $_w_ok ok, $_w_fail failed - see ctl.sh update-status"
  else log_info "update ($_w_mode): $_w_ok source(s) updated"; fi
  if [ -n "$_w_notify" ]; then
    notify ipset-arm64-update "ipset: list update failing" \
      "The automatic update of ${_w_notify#, } failed 3 times in a row. The last good copy stays active. Open the ipset WebUI (Lists) for the error."
    log_info "update: notification shown for${_w_notify#,}"
  fi
  unset _w_mode _w_ids _w_ok _w_fail _w_failed _w_notify _w_i _w_r _w_t _w_n
  update_unlock
}

# ── dispatch ─────────────────────────────────────────────────────────────────
_cmd=${1:-}
shift 2>/dev/null

case "$_cmd" in
  poll) need_ipset; cmd_poll ;;
  status) need_ipset; cmd_status ;;
  apply)
    need_ipset; need_lock
    log_info "apply requested"
    apply_and_report
    ;;
  enable | disable)
    need_ipset; need_lock
    if [ "$_cmd" = "enable" ]; then set_setting ENABLED 1; else set_setting ENABLED 0; fi
    log_info "master switch: $_cmd"
    apply_and_report
    ;;
  pause)
    _m=${1:-}
    case "$_m" in '' | *[!0-9]*) usage "pause <minutes 1..1440>" ;; esac
    { [ "$_m" -ge 1 ] && [ "$_m" -le 1440 ]; } || usage "pause <minutes 1..1440>"
    need_ipset; need_lock
    echo $(( $(mono_now) + _m * 60 )) > "$PAUSE_FILE"
    log_info "paused for $_m minute(s)"
    apply_and_report
    echo "paused_left=$(pause_left)"
    ;;
  resume)
    need_ipset; need_lock
    rm -f "$PAUSE_FILE"
    log_info "resumed"
    apply_and_report
    ;;
  set)
    [ $# -eq 2 ] || usage "set <KEY> <VALUE>"
    setting_valid "$1" "$2" || fail "invalid value '$2' for '$1'"
    [ "$1" = "SOURCES" ] && { cmd_sources set "$2"; exit 0; }
    need_ipset; need_lock
    set_setting "$1" "$2" || fail "unknown setting '$1'"
    log_info "setting $1=$2"
    case "$1" in
      AUTO_UPDATE | LOG_KEEP_LINES)
        # nothing in the firewall depends on these
        _settings_seen
        echo "ok=1"; echo "state=$(overall_state)" ;;
      *) apply_and_report ;;
    esac
    ;;
  settings)
    echo "ok=1"
    for _k in $SETTINGS_KEYS; do eval "echo \"$_k=\$$_k\""; done
    ;;
  allow) need_ipset; cmd_list allow "$@" ;;
  block) need_ipset; cmd_list user "$@" ;;
  check) need_ipset; cmd_check "${1:-}" ;;
  probe) need_ipset; cmd_probe "${1:-}" "${2:-}" ;;
  sources) need_ipset; cmd_sources "$@" ;;
  update) need_ipset; cmd_update "$@" ;;
  update-status) cmd_update_status ;;
  _update) need_ipset; cmd__update "$@" ;;
  log)
    _n=${1:-200}
    case "$_n" in '' | *[!0-9]*) _n=200 ;; esac
    echo "ok=1"
    echo "@@LOG@@"
    tail -n "$_n" "$LOG" 2>/dev/null
    ;;
  log-clear)
    : > "$LOG"
    echo "ok=1"
    ;;
  *)
    usage "ctl.sh poll|status|apply|enable|disable|pause <min>|resume|set <K> <V>|settings|allow ...|block ...|sources ...|update [id...]|update-status|check <ip>|log [n]|log-clear"
    ;;
esac
exit 0
