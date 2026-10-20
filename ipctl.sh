#!/system/bin/sh
# ipctl.sh - advanced toolkit for ipset-arm64: sets and firewall rules you
# build by hand. (The module's own protection - allowlist, blocklist, lists -
# is controlled with ctl.sh.)
#
# Usage (as root):
#   su -c '/system/bin/sh /data/adb/modules/ipset_arm64/ipctl.sh <command> [args]'
#
# Commands:
#   status                                   - capability check and overview
#   list [setname]                           - your sets (summary) or one set's members
#   types                                    - every supported set type
#   owned                                    - the sets you created here
#   create <n> [type] [inet|inet6]           - create a set (default type: hash:ip)
#   destroy <n>                              - destroy a set (only ones created here)
#   add <n> <entry> [entry ...]              - add members
#   del <n> <entry> [entry ...]              - remove members
#   test <n> <entry>                         - is an entry a member?
#   rule-add <n> [chain] [dir] [target] [uid]  - add a firewall rule for the set
#                                              (defaults: OUTPUT dst DROP; uid = per-app,
#                                              OUTPUT only; dir may be e.g. dst,dst for
#                                              two-dimensional sets)
#   rule-del <n> [chain] [dir] [target] [uid]  - remove that rule
#   rules                                    - the rules you created
#   apps                                     - installed packages with their UID
#   feed-update / feed-status                - = the firehol-level1 source (compatibility)
#   save / restore                           - persist / reload your sets
#   bootlog / bootlog-clear                  - what the last boot did
#   flush-all                                - remove every set and rule created here
#
# Rules run inside the module's chains (IPSA_ADV_OUT / _IN / _FWD), before
# the module's own allowlist and blocklists, for IPv4 and IPv6 alike (the
# set's family decides). ACCEPT and DROP/REJECT are final; RETURN means "no
# decision here" - the packet continues to the module's own lists.

set -u

MODDIR="$(cd "$(dirname "$0")" && pwd)"
if [ ! -f "$MODDIR/sh/common.sh" ]; then
  echo "ERROR: sh/common.sh missing - reflash the module"
  exit 1
fi
# shellcheck source=/dev/null
. "$MODDIR/sh/common.sh"
load_settings
mkdir -p "$DATA" "$RUN"
touch "$OWNED" "$RULES"
trap 'lock_release' EXIT
trap 'lock_release; exit 1' INT TERM HUP PIPE

# One-time migration from the in-module data location used before r5.
if [ -d "$MODDIR/data" ] && [ ! -s "$OWNED" ] && [ ! -s "$STATE" ]; then
  cp -a "$MODDIR/data/." "$DATA/" 2>/dev/null
fi
# Installs from before the ownership manifest: adopt the sets in the save file.
if [ ! -s "$OWNED" ] && [ -s "$STATE" ]; then
  awk '$1=="create" {print $2}' "$STATE" 2>/dev/null | sort -u > "$OWNED"
fi

die() {
  echo "ERROR: $*"
  log_error "ipctl: $*"
  exit 1
}

if [ -z "$IPSET" ] || ! "$IPSET" --version >/dev/null 2>&1; then
  die "ipset binary not found or not runnable (checked module dir and PATH)"
fi

need_lock() { lock_get 30 || die "busy - another operation is still running, try again"; }

# ---- input validation (the input may come from a UI) ----

valid_setname() {
  echo "$1" | grep -Eq '^[a-zA-Z0-9_]{1,31}$'
}

is_managed() { case "$1" in ipsa_*) return 0 ;; esac; return 1; }

valid_settype() {
  case "$1" in
    bitmap:ip|bitmap:ip,mac|bitmap:port) return 0 ;;
    hash:ip|hash:mac|hash:ip,mac|hash:net|hash:net,net) return 0 ;;
    hash:ip,port|hash:ip,port,ip|hash:ip,port,net) return 0 ;;
    hash:ip,mark|hash:net,port|hash:net,port,net|hash:net,iface) return 0 ;;
    list:set) return 0 ;;
    *) return 1 ;;
  esac
}

valid_family() {
  case "$1" in inet|inet6) return 0 ;; *) return 1 ;; esac
}

# Not a syntax check - ipset is the authority on what a member of each set
# type looks like. This only guarantees that nothing can break out of the
# argument: letters (protocol names, interface names), digits and the
# punctuation members use. No whitespace, quotes, $ ` ; | & < > ( ) * ?
# and no leading dash (it would be read as an option).
valid_entry() {
  case "$1" in
    "") return 1 ;;
    -*) return 1 ;;
    *[!0-9A-Za-z.:/,_-]*) return 1 ;;
  esac
  [ "${#1}" -le 128 ]
}

valid_chain() {
  case "$1" in INPUT|OUTPUT|FORWARD) return 0 ;; *) return 1 ;; esac
}

# src / dst, or up to three comma-separated for multi-dimensional sets
valid_dir() {
  echo "$1" | grep -Eq '^(src|dst)(,(src|dst)){0,2}$'
}

valid_target() {
  case "$1" in DROP|ACCEPT|REJECT|RETURN) return 0 ;; *) return 1 ;; esac
}

set_loaded() { "$IPSET" list -n 2>/dev/null | grep -qx "$1"; }

# ---- commands ----

cmd_status() {
  echo "== ipset-arm64 status =="
  echo "ipset binary   : $IPSET"
  if "$IPSET" --version >/dev/null 2>&1; then echo "  runs           : OK"; else echo "  runs           : FAIL"; fi
  echo "iptables       : ${IPT4:-MISSING}"
  echo "ip6tables      : ${IPT6:-MISSING}"

  if [ -r /proc/config.gz ]; then
    _kcfg=$(zcat /proc/config.gz 2>/dev/null)
    for cfg in CONFIG_IP_SET CONFIG_IP_SET_HASH_IP CONFIG_IP_SET_HASH_NET CONFIG_IP_SET_HASH_MAC CONFIG_NETFILTER_XT_SET CONFIG_IP6_NF_TARGET_REJECT; do
      val=$(echo "$_kcfg" | grep "^${cfg}=" | cut -d= -f2)
      echo "  $cfg = ${val:-not set / not found}"
    done
  else
    echo "  /proc/config.gz not readable - skipping kernel config check"
  fi

  echo ""
  echo "Firewall (module chains):"
  echo "  IPv4: $(fam_state 4)"
  echo "  IPv6: $(fam_state 6)"
  [ "$ENABLED" != "1" ] && echo "  master switch: OFF"
  is_paused && echo "  paused: $(pause_left)s left"

  echo ""
  echo "Sets created here:"
  if [ -s "$OWNED" ]; then
    own_list | while read -r n; do
      if set_loaded "$n"; then echo "  - $n"; else echo "  - $n  (in manifest but not currently loaded)"; fi
    done
  else
    echo "  (none)"
  fi

  echo ""
  echo "Other sets on this device (NOT managed here, never touched):"
  _others=$("$IPSET" list -n 2>/dev/null | grep -v '^ipsa_' | grep -vxF -f "$OWNED" 2>/dev/null)
  if [ -n "$_others" ]; then echo "$_others" | sed 's/^/  - /'; else echo "  (none)"; fi

  echo ""
  echo "Your rules (from $RULES):"
  if [ -s "$RULES" ]; then sed 's/^/  /' "$RULES"; else echo "  (none)"; fi
  _rej=$(cat "$RUN"/adv_rejected.* 2>/dev/null)
  if [ -n "$_rej" ]; then echo ""; echo "Rules the kernel refused (not active):"; echo "$_rej" | sed 's/^/  /'; fi
  _skp=$(cut -d'|' -f2- "$RUN"/adv_skipped.* 2>/dev/null | sort -u)
  if [ -n "$_skp" ]; then echo ""; echo "Rules whose set is missing (not active):"; echo "$_skp" | sed 's/^/  /'; fi
  return 0
}

cmd_list() {
  if [ -n "${1:-}" ]; then
    valid_setname "$1" || die "invalid set name"
    "$IPSET" list "$1" || die "set '$1' does not exist"
  else
    # The module's own ipsa_* sets are managed with ctl.sh, not listed here.
    names=$("$IPSET" list -n 2>/dev/null | grep -v '^ipsa_')
    if [ -z "$names" ]; then
      echo "(no sets defined)"
      return 0
    fi
    for n in $names; do
      _hdr=$("$IPSET" list -t "$n" 2>/dev/null)
      count=$(echo "$_hdr" | sed -n 's/^Number of entries: *//p')
      type=$(echo "$_hdr" | sed -n 's/^Type: *//p')
      echo "$n  type=$type  entries=$count"
    done
  fi
}

cmd_create() {
  name="${1:-}"; type="${2:-}"; family="${3:-}"
  [ -n "$type" ] || type=hash:ip
  valid_setname "$name" || die "invalid set name (use letters/digits/underscore, max 31 chars)"
  is_managed "$name" && die "names starting with ipsa_ are reserved for the module"
  valid_settype "$type" || die "unsupported type '$type' (see: ipctl.sh types)"
  extra=""
  if [ -n "$family" ]; then
    valid_family "$family" || die "invalid family '$family' (use inet or inet6)"
    case "$type" in
      bitmap:*|hash:mac|list:set) die "type '$type' does not take a family" ;;
    esac
    extra="family $family"
  fi
  need_lock
  # shellcheck disable=SC2086
  "$IPSET" create "$name" "$type" $extra 2>&1 || die "failed to create set"
  own_add "$name"
  log_info "ipctl: created set $name ($type${extra:+ $extra})"
  user_sets_save
  echo "OK: created '$name' ($type)"
}

cmd_destroy() {
  name="${1:-}"
  valid_setname "$name" || die "invalid set name"
  is_managed "$name" && die "'$name' is managed by the module"
  if grep -q "^[A-Z]*|$name|" "$RULES" 2>/dev/null; then
    die "set '$name' still has active firewall rule(s); run rule-del first (see: rules)"
  fi
  own_has "$name" || die "'$name' was not created by this module - refusing to destroy it. Use ipset directly if you really mean to."
  need_lock
  "$IPSET" destroy "$name" 2>&1 || die "failed to destroy set (does it exist? is it used by another rule or list:set?)"
  own_remove "$name"
  log_info "ipctl: destroyed set $name"
  user_sets_save
  echo "OK: destroyed '$name'"
}

_members() { # add|del <set> <entries...>
  _m_op=$1; name="${2:-}"
  valid_setname "$name" || die "invalid set name"
  is_managed "$name" && die "'$name' is managed by the module - use ctl.sh allow/block instead"
  shift 2 2>/dev/null
  [ $# -ge 1 ] || die "nothing to $_m_op - usage: $_m_op <set> <entry> [entry ...]"
  for e in "$@"; do
    valid_entry "$e" || die "invalid entry '$e' (unsupported characters, or too long)"
  done
  need_lock
  _n=0
  for e in "$@"; do
    if [ "$_m_op" = "add" ]; then
      "$IPSET" add "$name" "$e" 2>&1 || { [ "$_n" -gt 0 ] && user_sets_save; die "failed to add '$e' (set may not exist, wrong format for this set type, or duplicate entry)"; }
    else
      "$IPSET" del "$name" "$e" 2>&1 || { [ "$_n" -gt 0 ] && user_sets_save; die "failed to remove '$e' (was it a member?)"; }
    fi
    _n=$((_n + 1))
  done
  user_sets_save
  if [ "$_m_op" = "add" ]; then
    log_info "ipctl: added $_n entr(y/ies) to $name"
    echo "OK: added $_n entr(y/ies) to '$name'"
  else
    log_info "ipctl: removed $_n entr(y/ies) from $name"
    echo "OK: removed $_n entr(y/ies) from '$name'"
  fi
}

cmd_test() {
  name="${1:-}"; ip="${2:-}"
  valid_setname "$name" || die "invalid set name"
  valid_entry "$ip" || die "invalid entry '$ip' (unsupported characters, or too long)"
  "$IPSET" test "$name" "$ip"
}

_rule_args() { # sets: name chain dir target uid key
  name="${1:-}"; chain="${2:-}"; dir="${3:-}"; target="${4:-}"; uid="${5:-}"
  [ -n "$chain" ] || chain=OUTPUT
  [ -n "$dir" ] || dir=dst
  [ -n "$target" ] || target=DROP
  valid_setname "$name" || die "invalid set name"
  valid_chain "$chain" || die "invalid chain (INPUT/OUTPUT/FORWARD)"
  valid_dir "$dir" || die "invalid direction (src/dst, or e.g. dst,dst)"
  valid_target "$target" || die "invalid target (DROP/ACCEPT/REJECT/RETURN)"
  if [ -n "$uid" ]; then
    echo "$uid" | grep -Eq '^[0-9]+$' || die "invalid uid '$uid'"
  fi
  key="${chain}|${name}|${dir}|${target}"
  [ -n "$uid" ] && key="${key}|${uid}"
  return 0
}

# Is this rule in the live chain of every family it belongs to?
_rule_live() {
  _rl_sf=$(set_family "$name") || return 1
  case "$chain" in OUTPUT) _rl_ch=IPSA_ADV_OUT ;; INPUT) _rl_ch=IPSA_ADV_IN ;; *) _rl_ch=IPSA_ADV_FWD ;; esac
  _rl_o=""
  [ -n "$uid" ] && _rl_o="-m owner --uid-owner $uid"
  _rl_seen=0
  for _rl_f in 4 6; do
    [ "$_rl_sf" = "any" ] || [ "$_rl_sf" = "$_rl_f" ] || continue
    case "$(fam_state "$_rl_f")" in ok | ok-drop | off) : ;; *) continue ;; esac
    [ "$_rl_f" = "6" ] && [ "$IPV6" != "1" ] && continue
    # shellcheck disable=SC2086
    ipt "$_rl_f" -C "$_rl_ch" $_rl_o -m set --match-set "$name" "$dir" -j "$target" 2>/dev/null || return 1
    _rl_seen=1
  done
  [ "$_rl_seen" = "1" ]
}

cmd_rule_add() {
  _rule_args "$@"
  is_managed "$name" && die "'$name' is managed by the module"
  if [ -n "$uid" ] && [ "$chain" != "OUTPUT" ]; then
    die "per-app filtering (uid) only works on the OUTPUT chain - the owner match has no meaning for INPUT/FORWARD"
  fi
  set_loaded "$name" || die "set '$name' does not exist"
  sf=$(set_family "$name")
  if [ "$sf" = "6" ]; then
    v6_supported || die "'$name' is an IPv6 set, but ip6tables is not available on this device"
    [ "$IPV6" = "1" ] || die "'$name' is an IPv6 set, but IPv6 enforcement is off (setting IPV6=0)"
    case "$(fam_state 6)" in
      error:*) die "'$name' is an IPv6 set, but the IPv6 firewall is not working on this device ($(fam_state 6 | sed 's/^error://'))" ;;
    esac
  fi
  if grep -qx "$key" "$RULES" 2>/dev/null; then
    echo "OK: rule already active ($key)"
    return 0
  fi
  need_lock
  cp -f "$RULES" "$RULES.bak" 2>/dev/null
  echo "$key" >> "$RULES"
  rules_apply >/dev/null 2>&1
  # Confirmed, not assumed: the rule must be in the chain now.
  if ! _rule_live; then
    mv -f "$RULES.bak" "$RULES"
    rules_apply >/dev/null 2>&1
    die "the kernel refused this rule (set type and direction may not match) - not saved"
  fi
  rm -f "$RULES.bak"
  log_info "ipctl: rule added: $key"
  echo "OK: rule active -> $chain, match-set $name $dir, -j $target${uid:+ (app uid $uid)}"
  [ "$ENABLED" = "1" ] || echo "    (the module is switched off - the rule takes effect when it is on)"
}

cmd_rule_del() {
  _rule_args "$@"
  need_lock
  grep -vx "$key" "$RULES" > "$RULES.tmp" 2>/dev/null
  mv -f "$RULES.tmp" "$RULES"
  rules_apply >/dev/null 2>&1
  log_info "ipctl: rule removed: $key"
  echo "OK: rule removed -> $key"
}

cmd_apps() {
  pm list packages -U 2>/dev/null | awk -F'[: ]+' 'NF>=4 {print $2"|"$4}' | sort
}

cmd_rules() {
  if [ -s "$RULES" ]; then cat "$RULES"; else echo "(no dynamic rules active)"; fi
}

# ---- threat feed (compatibility with the r9 WebUI) ----
# The feed is now the firehol-level1 source of the catalog (ctl.sh sources).
# These two commands keep the old WebUI's "Threat Feeds" card working.
cmd_feed_update() {
  if ! src_is_enabled firehol-level1; then
    sh "$MODDIR/ctl.sh" sources enable firehol-level1 >/dev/null 2>&1
    load_settings
  fi
  update_running && die "a list update is already running - try again in a moment"
  sh "$MODDIR/ctl.sh" _update manual firehol-level1
  [ "$(meta_get firehol-level1 status)" = "ok" ] || die "$(meta_get firehol-level1 error)"
  echo "OK: firehol-level1 updated with $(meta_get firehol-level1 count) entries"
}

cmd_feed_status() {
  _fs_u=$(meta_get firehol-level1 updated)
  if [ -z "$(meta_get firehol-level1 count)" ]; then echo "(never updated)"; return 0; fi
  _fs_d=$(date -d "@${_fs_u:-0}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
  [ "${_fs_u:-0}" = "0" ] && _fs_d="unknown"
  echo "{\"updated\":\"$_fs_d\",\"count\":$(meta_get firehol-level1 count),\"source\":\"$(src_field firehol-level1 6)\",\"status\":\"$(meta_get firehol-level1 status)\"}"
}

cmd_save() {
  need_lock
  user_sets_save
  echo "OK: saved $(own_list | grep -c .) set(s)"
}

cmd_restore() {
  need_lock
  echo "== restore run: $(date '+%Y-%m-%d %H:%M:%S') =="
  if [ -s "$STATE" ]; then
    echo "Restoring $(grep -c '^create ' "$STATE") set(s), $(grep -c '^add ' "$STATE") entr(y/ies)"
    if user_sets_restore; then echo "Sets restored."; else echo "Some sets could not be restored (see log)."; fi
  else
    echo "No saved sets - nothing to restore."
  fi
  if rules_apply; then echo "Rules applied (IPv4: $(fam_state 4), IPv6: $(fam_state 6))."
  else echo "Rules: IPv4 could not be applied (see log)."; fi
  echo "== restore complete =="
}

cmd_types() {
  echo "Set types supported by this script:"
  echo "  bitmap:ip        bitmap:ip,mac    bitmap:port"
  echo "  hash:ip          hash:mac         hash:ip,mac"
  echo "  hash:net         hash:net,net     hash:net,port"
  echo "  hash:net,port,net                 hash:net,iface"
  echo "  hash:ip,port     hash:ip,port,ip  hash:ip,port,net"
  echo "  hash:ip,mark     list:set"
  echo ""
  echo "Usage: create <n> [type] [inet|inet6]     (default type: hash:ip)"
  echo "Examples:"
  echo "  create blocklist hash:net"
  echo "  create v6block   hash:net inet6"
  echo "  create services  hash:ip,port        then: add services 1.2.3.4,tcp:443"
  echo "                                       and:  rule-add services OUTPUT dst,dst"
  echo ""
  echo "Which types actually work depends on the kernel - run 'status'."
}

cmd_bootlog() {
  if [ -s "$BOOTLOG" ]; then cat "$BOOTLOG"; else echo "(no boot log yet - reboot the device once to generate it)"; fi
}

cmd_bootlog_clear() {
  : > "$BOOTLOG"
  log_info "ipctl: boot log cleared manually"
  echo "OK: boot log cleared"
}

cmd_flush_all() {
  need_lock
  # Rules first: the kernel refuses to destroy a set a rule still uses.
  : > "$RULES"
  rules_apply >/dev/null 2>&1
  _destroyed=0
  for n in $(own_list); do
    "$IPSET" destroy "$n" 2>/dev/null && _destroyed=$((_destroyed + 1))
  done
  : > "$OWNED"
  : > "$STATE"
  log_info "ipctl: flush-all ($_destroyed set(s))"
  echo "OK: removed $_destroyed set(s) created by this module, and all its rules"
  echo "    (sets created by other apps were left alone)"
}

case "${1:-}" in
  status)    cmd_status ;;
  list)      cmd_list "${2:-}" ;;
  create)    cmd_create "${2:-}" "${3:-}" "${4:-}" ;;
  types)     cmd_types ;;
  owned)     own_list ;;
  destroy)   cmd_destroy "${2:-}" ;;
  add)       shift; _members add "$@" ;;
  del)       shift; _members del "$@" ;;
  test)      cmd_test "${2:-}" "${3:-}" ;;
  rule-add)  cmd_rule_add "${2:-}" "${3:-}" "${4:-}" "${5:-}" "${6:-}" ;;
  rule-del)  cmd_rule_del "${2:-}" "${3:-}" "${4:-}" "${5:-}" "${6:-}" ;;
  apps)      cmd_apps ;;
  rules)     cmd_rules ;;
  bootlog)   cmd_bootlog ;;
  bootlog-clear) cmd_bootlog_clear ;;
  feed-update) cmd_feed_update ;;
  feed-status) cmd_feed_status ;;
  save)      cmd_save ;;
  restore)   cmd_restore ;;
  flush-all) cmd_flush_all ;;
  *)
    echo "Usage: ipctl.sh {status|types|list|owned|create|destroy|add|del|test|"
    echo "                 rule-add|rule-del|rules|apps|bootlog|bootlog-clear|"
    echo "                 feed-update|feed-status|save|restore|flush-all}"
    exit 1
    ;;
esac
