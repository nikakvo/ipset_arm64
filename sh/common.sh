#!/system/bin/sh
# shellcheck shell=sh disable=SC2034
#
# sh/common.sh - shared by post-fs-data.sh, service.sh, ctl.sh, ipctl.sh
# and uninstall.sh. Sourcing it only defines variables and functions.
#
# POSIX sh (mksh / toybox / busybox ash). No bashisms.

MODULE_ID="ipset_arm64"
MODDIR="${MODDIR:-/data/adb/modules/$MODULE_ID}"

# ── Paths ────────────────────────────────────────────────────────────────────
# Persistent data lives outside $MODDIR: a module update replaces $MODDIR
# wholesale, and only uninstall.sh removes this directory.
DATA="/data/adb/ipset_arm64_data"
RUN="$DATA/run"                    # per-boot state, emptied by post-fs-data
CONF="$DATA/settings.conf"
LOG="$DATA/ipset.log"
BOOTLOG="$DATA/service.log"        # what the last boot did (ipctl bootlog)

ALLOW_FILE="$DATA/ip-allowlist.txt"
BLOCK_FILE="$DATA/ip-blocklist.txt"
CACHE="$DATA/cache"                # downloaded lists, one file per source

# The allow/block lists are mirrored here for editing with any app; the
# watchdog applies edits within one tick.
SD_DIR="/storage/emulated/0/ipset-arm64"
SD_FILES="ip-allowlist.txt ip-blocklist.txt"

# Advanced toolkit (ipctl.sh): sets and rules created by hand.
OWNED="$DATA/owned.list"
STATE="$DATA/sets.save"
RULES="$DATA/rules.conf"

MODPROP="$MODDIR/module.prop"
LOCK_DIR="$RUN/lock"
PAUSE_FILE="$RUN/paused_until"
HEALTH_FILE="$RUN/health"
WATCHDOG_PIDFILE="$RUN/watchdog.pid"
APPLIED_CONF_MTIME="$RUN/conf_mtime"

# ── Tools ────────────────────────────────────────────────────────────────────
BB=""
for _b in /data/adb/ksu/bin/busybox /data/adb/ap/bin/busybox /data/adb/magisk/busybox; do
  if [ -x "$_b" ]; then BB="$_b"; break; fi
done
unset _b

if [ -x "$MODDIR/system/bin/ipset" ]; then
  IPSET="$MODDIR/system/bin/ipset"
else
  IPSET="$(command -v ipset 2>/dev/null)"
fi

_tool() { # <name> -> path or empty
  command -v "$1" 2>/dev/null && return 0
  [ -x "/system/bin/$1" ] && echo "/system/bin/$1"
}
IPT4="$(_tool iptables)"
IPT6="$(_tool ip6tables)"
RST4="$(_tool iptables-restore)"
RST6="$(_tool ip6tables-restore)"
# iptables-save reads the tables without the xtables lock (r11, see rules.sh)
SAV4="$(_tool iptables-save)"
SAV6="$(_tool ip6tables-save)"

# ── Settings ─────────────────────────────────────────────────────────────────
# Parsed, never sourced: only known keys, only plain values. A stray command
# in the file cannot run as root inside the watchdog; it is simply ignored.
SETTINGS_KEYS="ENABLED OUT_TARGET FORWARD_BLOCK IPV6 SOURCES DIRECTIONS AUTO_UPDATE DNSCRYPT_ALLOW WGSHIELD_ALLOW LOG_KEEP_LINES"

settings_defaults() {
  ENABLED=1          # master switch: 0 = the module enforces nothing
  OUT_TARGET=REJECT  # outgoing to a blocked address: REJECT (fails fast) or DROP
  FORWARD_BLOCK=0    # also filter hotspot / tethering clients
  IPV6=1             # enforce on IPv6 too (when ip6tables supports it)
  SOURCES="firehol-level1,spamhaus-dropv6"   # enabled lists (sh/sources.sh)
  AUTO_UPDATE=off    # off | daily | weekly - the user opts in
  DIRECTIONS=""      # per list: <id>:out|in|both, comma separated (default both)
  DNSCRYPT_ALLOW=1   # never block the resolvers the dnscrypt-proxy module uses
  WGSHIELD_ALLOW=1   # never block the tunnel servers of the WG Shield module
  LOG_KEEP_LINES=1500
}

# 0 when <value> is acceptable for <key>
setting_valid() { # <KEY> <VALUE>
  case "$1" in
    ENABLED | FORWARD_BLOCK | IPV6 | DNSCRYPT_ALLOW | WGSHIELD_ALLOW)
      case "$2" in 0 | 1) return 0 ;; esac ;;
    OUT_TARGET)
      case "$2" in REJECT | DROP) return 0 ;; esac ;;
    AUTO_UPDATE)
      case "$2" in off | daily | weekly) return 0 ;; esac ;;
    DIRECTIONS)
      [ -z "$2" ] && return 0
      case "$2" in *[!a-z0-9,:-]*) return 1 ;; esac
      # split on "," with the shell itself (no forks: the watchdog reads
      # the settings every tick); the characters were checked above
      _sv_o=$IFS; IFS=,; _sv_r=0
      for _sv_i in $2; do
        [ -n "$_sv_i" ] || continue   # "a,,b" was accepted before r15 too
        case "${_sv_i#*:}" in out | in | both) : ;; *) _sv_r=1; break ;; esac
        [ "${_sv_i%%:*}" = "user" ] || src_known "${_sv_i%%:*}" || { _sv_r=1; break; }
      done
      IFS=$_sv_o
      unset _sv_i _sv_o
      return "$_sv_r" ;;
    SOURCES)
      [ "$2" = "none" ] && return 0
      case "$2" in '' | *[!a-z0-9,-]*) return 1 ;; esac
      _sv_o=$IFS; IFS=,; _sv_r=0
      for _sv_i in $2; do
        [ -n "$_sv_i" ] || continue
        src_known "$_sv_i" || { _sv_r=1; break; }
      done
      IFS=$_sv_o
      unset _sv_i _sv_o
      return "$_sv_r" ;;
    LOG_KEEP_LINES)
      case "$2" in '' | *[!0-9]*) return 1 ;; esac
      [ "$2" -ge 100 ] && [ "$2" -le 20000 ] && return 0 ;;
  esac
  return 1
}

load_settings() {
  settings_defaults
  [ -f "$CONF" ] || return 0
  while IFS='=' read -r _ls_k _ls_v || [ -n "$_ls_k" ]; do
    case "$_ls_k" in '' | \#*) continue ;; esac
    _ls_v=${_ls_v%%#*}
    _ls_v=${_ls_v%%[ 	]*}
    _ls_v=${_ls_v#\"}
    _ls_v=${_ls_v%\"}
    case " $SETTINGS_KEYS " in *" $_ls_k "*) : ;; *) continue ;; esac
    setting_valid "$_ls_k" "$_ls_v" || continue
    eval "$_ls_k=\$_ls_v"
  done < "$CONF"
  unset _ls_k _ls_v
  return 0
}

# Write one setting, keeping the rest of the file and its comments.
set_setting() { # <KEY> <VALUE>
  case " $SETTINGS_KEYS " in *" $1 "*) : ;; *) return 1 ;; esac
  setting_valid "$1" "$2" || return 1
  [ -f "$CONF" ] || : > "$CONF"
  if grep -q "^$1=" "$CONF" 2>/dev/null; then
    sed -i "s|^$1=.*|$1=$2|" "$CONF"
  else
    printf '%s=%s\n' "$1" "$2" >> "$CONF"
  fi
}

write_default_settings() {
  [ -f "$CONF" ] && return 0
  mkdir -p "$DATA"
  cat > "$CONF" << 'EOF'
# ipset-arm64 settings. Edited by the WebUI and ctl.sh; hand edits are
# picked up by the watchdog within 10 seconds. Unknown keys and invalid
# values are ignored (the default is used instead).

# Master switch. 0 = the module enforces nothing (sets stay loaded).
ENABLED=1

# What happens to outgoing traffic to a blocked address.
# REJECT = the app gets an immediate error (recommended).
# DROP   = packets vanish; the app waits until its own timeout.
OUT_TARGET=REJECT

# Also filter hotspot / USB tethering clients (1/0).
FORWARD_BLOCK=0

# Enforce on IPv6 as well (1/0). Needs ip6tables with the set match.
IPV6=1

# Blocklist sources, comma separated, or "none". See: ctl.sh sources
SOURCES=firehol-level1,spamhaus-dropv6

# Which traffic each list blocks: <id>:out, <id>:in or <id>:both, comma
# separated ("user" = your own blocklist). A list not named here blocks both.
DIRECTIONS=

# If the dnscrypt-proxy module is installed, never block the resolvers it
# uses (read from its dnscrypt-proxy.toml) (1/0).
DNSCRYPT_ALLOW=1

# If the WG Shield module is installed, never block its tunnel servers
# (the Endpoint addresses of its tunnels) (1/0).
WGSHIELD_ALLOW=1

# Automatic list updates: off, daily or weekly. Off by default: nothing
# is downloaded until you press Update (or switch this on).
AUTO_UPDATE=off

# Log file size: keep this many lines.
LOG_KEEP_LINES=1500
EOF
}

# ── Time ─────────────────────────────────────────────────────────────────────
# Seconds since boot for every interval. The wall clock is wrong at boot and
# jumps when it syncs; /proc/uptime only moves forward.
mono_now() {
  read -r _mn_u _mn_r 2>/dev/null < /proc/uptime
  echo "${_mn_u%%.*}"
  unset _mn_u _mn_r
}

# The same, without a fork: sets NOW (the watchdog calls it every tick).
mono_set() {
  read -r NOW _mn_r 2>/dev/null < /proc/uptime
  NOW=${NOW%%.*}
  unset _mn_r
}

mtime_of() { stat -c %Y "$1" 2>/dev/null || echo 0; }

# "<mtime>:<size>" of settings.conf: a second write in the same second
# almost always changes the size, so it is not missed.
conf_stamp() { stat -c '%Y:%s' "$CONF" 2>/dev/null || echo 0; }

# First line of a file into FL (empty when missing), without a fork.
first_line() {
  FL=""
  read -r FL 2>/dev/null < "$1"
  return 0
}

# ── Logging ──────────────────────────────────────────────────────────────────
# The wall clock is still at 1970 early in boot (before the network time
# sync); such lines show the time since boot instead of a false date.
clock_sane() { [ "$(date +%Y 2>/dev/null)" -ge 2024 ] 2>/dev/null; }
_ts() {
  if clock_sane; then date '+%Y-%m-%d %H:%M:%S' 2>/dev/null
  else echo "boot+$(mono_now)s"; fi
}
# The phone is shutting down or rebooting. Android sets
# sys.shutdown.requested when a normal shutdown starts and sys.powerctl at
# its very end (a plain "reboot" command sets only sys.powerctl).
shutting_down() {
  [ -n "$(getprop sys.shutdown.requested 2>/dev/null)" ] ||
    [ -n "$(getprop sys.powerctl 2>/dev/null)" ]
}
# The watchdog sets QUIET_ON_SHUTDOWN=1: whatever it was doing when the
# shutdown started fails (the system is being taken apart under it), and
# those failures are not worth a red line in the log.
_log_quiet() { [ "${QUIET_ON_SHUTDOWN:-0}" = "1" ] && shutting_down; }
log_info()  { _log_quiet && return 0; echo "$(_ts) [INFO] $*"  >> "$LOG" 2>/dev/null; }
log_warn()  { _log_quiet && return 0; echo "$(_ts) [WARN] $*"  >> "$LOG" 2>/dev/null; }
log_error() { _log_quiet && return 0; echo "$(_ts) [ERROR] $*" >> "$LOG" 2>/dev/null; }
bootlog()   { echo "$(_ts) $*" >> "$BOOTLOG" 2>/dev/null; }

rotate_log() {
  [ -f "$LOG" ] || return 0
  _rl_keep=${LOG_KEEP_LINES:-1500}
  _rl_n=$(wc -l < "$LOG" 2>/dev/null)
  _rl_n=$((_rl_n + 0))
  if [ "$_rl_n" -gt $((_rl_keep * 2)) ]; then
    tail -n "$_rl_keep" "$LOG" > "$LOG.tmp" 2>/dev/null && cat "$LOG.tmp" > "$LOG" 2>/dev/null
    rm -f "$LOG.tmp"
  fi
  unset _rl_keep _rl_n
}

# ── Lock ─────────────────────────────────────────────────────────────────────
# One writer at a time for sets, rules and data files: the WebUI, a hand-run
# command and the watchdog must never change them together. A lock left by a
# process that died (killed, rebooted mid-command) is taken over.
LOCK_HELD=0

lock_try() {
  [ -d "$RUN" ] || mkdir -p "$RUN" 2>/dev/null
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    echo $$ > "$LOCK_DIR/pid"
    LOCK_HELD=1
    return 0
  fi
  first_line "$LOCK_DIR/pid"; _lt_p=$FL
  # No pid yet: the holder has just created the lock. Busy - unless the
  # lock has been without a pid for over a minute (holder killed between
  # mkdir and writing it).
  if [ -z "$_lt_p" ]; then
    _lt_age=$(( $(date +%s) - $(mtime_of "$LOCK_DIR") ))
    if [ "$_lt_age" -lt 60 ] && [ "$_lt_age" -gt -60 ]; then unset _lt_p _lt_age; return 1; fi
    unset _lt_age
  elif [ -d "/proc/$_lt_p" ]; then
    unset _lt_p; return 1
  fi
  # Stale. Take it over atomically: only one process can rename the
  # directory away. If what was renamed is not the stale lock that was
  # looked at (another process got there first and made a fresh one),
  # put it back and report busy.
  _lt_s="$LOCK_DIR.stale.$$"
  if mv "$LOCK_DIR" "$_lt_s" 2>/dev/null; then
    if [ "$(cat "$_lt_s/pid" 2>/dev/null)" != "$_lt_p" ]; then
      mv "$_lt_s" "$LOCK_DIR" 2>/dev/null || rm -rf "$_lt_s"
      unset _lt_p _lt_s
      return 1
    fi
    rm -rf "$_lt_s"
  fi
  unset _lt_p _lt_s
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    echo $$ > "$LOCK_DIR/pid"
    LOCK_HELD=1
    return 0
  fi
  return 1
}

# Wait up to <seconds> (default 20) for the lock.
lock_get() {
  _lg_left=$(( ${1:-20} * 5 ))
  while [ "$_lg_left" -gt 0 ]; do
    if lock_try; then unset _lg_left; return 0; fi
    sleep 0.2 2>/dev/null || sleep 1
    _lg_left=$((_lg_left - 1))
  done
  unset _lg_left
  return 1
}

lock_release() {
  [ "$LOCK_HELD" = "1" ] || return 0
  first_line "$LOCK_DIR/pid"
  [ "$FL" = "$$" ] && rm -rf "$LOCK_DIR"
  LOCK_HELD=0
}

# ── Pause ────────────────────────────────────────────────────────────────────
# A deadline in seconds-since-boot, so a reboot always ends a pause
# (post-fs-data also empties $RUN).
pause_left() {
  _pl_u=0
  [ -f "$PAUSE_FILE" ] && read -r _pl_u < "$PAUSE_FILE" 2>/dev/null
  case "$_pl_u" in '' | *[!0-9]*) _pl_u=0 ;; esac
  _pl_l=$((_pl_u - $(mono_now)))
  [ "$_pl_l" -lt 0 ] && _pl_l=0
  echo "$_pl_l"
  unset _pl_u _pl_l
}
is_paused() { [ -f "$PAUSE_FILE" ] && [ "$(pause_left)" -gt 0 ]; }

# ── Downloads ────────────────────────────────────────────────────────────────
# curl, then busybox wget, then toybox wget. Writes <out> only on success.
dl() { # <url> <out>
  rm -f "$2.part"
  if command -v curl >/dev/null 2>&1; then
    curl -sfL --max-time 300 --connect-timeout 15 --retry 1 "$1" -o "$2.part" 2>/dev/null &&
      [ -s "$2.part" ] && mv -f "$2.part" "$2" && return 0
  fi
  if [ -n "$BB" ]; then
    rm -f "$2.part"
    "$BB" wget -q -T 60 -O "$2.part" "$1" 2>/dev/null &&
      [ -s "$2.part" ] && mv -f "$2.part" "$2" && return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    rm -f "$2.part"
    wget -q -O "$2.part" "$1" 2>/dev/null &&
      [ -s "$2.part" ] && mv -f "$2.part" "$2" && return 0
  fi
  rm -f "$2.part"
  return 1
}

# ── sdcard mirror ────────────────────────────────────────────────────────────
# After the module changes a list, copy it to the sdcard and give both
# copies the same mtime, so the next sync does not take the module's own
# write for a user edit.
mirror_to_sd() { # <file name in DATA>
  [ -f "$DATA/$1" ] || return 1
  [ -d "${SD_DIR%/*}/Android" ] || return 1   # shared storage mounted (sd_ready)
  mkdir -p "$SD_DIR" 2>/dev/null || return 1
  cp -f "$DATA/$1" "$SD_DIR/$1" 2>/dev/null || return 1
  touch -r "$SD_DIR/$1" "$DATA/$1" 2>/dev/null
}

# ── Notification ─────────────────────────────────────────────────────────────
# Best effort, through Android's notification service ("cmd notification",
# shown as coming from the Shell app). Posted as the shell user: on his
# phone (HyperOS) a post as root returns 0 but never appears; as uid 2000
# it does (tested on the phone). <tag> <title> <text>
_nq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
notify() {
  command -v cmd >/dev/null 2>&1 || return 0
  _nf_c="cmd notification post -S bigtext -t $(_nq "$2") $(_nq "$1") $(_nq "$3")"
  if [ "$(id -u)" = "0" ] && command -v su >/dev/null 2>&1 &&
    su 2000 -c "$_nf_c" >/dev/null 2>&1; then
    unset _nf_c; return 0
  fi
  eval "$_nf_c" >/dev/null 2>&1
  unset _nf_c
  return 0
}

# ── Module status line ───────────────────────────────────────────────────────
set_module_status() {
  [ -f "$MODPROP" ] || return 0
  _ms_d="IP-level blocklists (ipset + iptables/ip6tables) | $1"
  # The text holds "|" (the sed delimiter) and may hold "&" or "\":
  # escape them, or sed fails and the card keeps the old status.
  _ms_e=$(printf '%s' "$_ms_d" | sed 's/[\\&|]/\\&/g')
  sed -i "s|^description=.*|description=$_ms_e|" "$MODPROP" 2>/dev/null
  unset _ms_d _ms_e
}

# ── Libraries ────────────────────────────────────────────────────────────────
for _lib in sets sources dnscrypt wgshield rules; do
  if [ -f "$MODDIR/sh/$_lib.sh" ]; then
    # shellcheck source=/dev/null
    . "$MODDIR/sh/$_lib.sh"
  fi
done
unset _lib

# LAN Cloak Arm64 (same set): read only, for the System tab. It hides the
# phone on the Wi-Fi network (DHCP, mDNS / SSDP / LLMNR) with its own chains
# and never touches this module's sets or chains; nothing here depends on it.
LANC_MODDIR="/data/adb/modules/lan-cloak"
LANC_STATUS="/data/adb/lan-cloak/state/status"
lanc_keys() {
  if [ ! -f "$LANC_MODDIR/module.prop" ]; then _lc_m=absent
  elif [ -f "$LANC_MODDIR/disable" ] || [ -f "$LANC_MODDIR/remove" ]; then _lc_m=disabled
  else _lc_m=enabled; fi
  _lc_s=""; _lc_r=""; _lc_d=""; _lc_a=""; _lc_w=""; _lc_u=""
  if [ "$_lc_m" != absent ] && [ -f "$LANC_STATUS" ]; then
    while IFS='=' read -r _lc_k _lc_v; do
      case "$_lc_k" in
        state) _lc_s=$_lc_v ;; reason) _lc_r=$_lc_v ;; dhcp) _lc_d=$_lc_v ;;
        announce) _lc_a=$_lc_v ;; wifi) _lc_w=$_lc_v ;; updated) _lc_u=$_lc_v ;;
      esac
    done 2>/dev/null < "$LANC_STATUS"
  fi
  echo "lancloak=$_lc_m"
  echo "lancloak_state=$_lc_s"
  echo "lancloak_reason=$_lc_r"
  echo "lancloak_dhcp=$_lc_d"
  echo "lancloak_announce=$_lc_a"
  echo "lancloak_wifi=$_lc_w"
  case "$_lc_u" in
    ''|*[!0-9]*) echo "lancloak_age=" ;;
    *) echo "lancloak_age=$(( $(date +%s) - _lc_u ))" ;;
  esac
  unset _lc_m _lc_s _lc_r _lc_d _lc_a _lc_w _lc_u _lc_k _lc_v
}
