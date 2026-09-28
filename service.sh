#!/system/bin/sh
# service.sh - ipset-arm64 watchdog.
#
# Waits until netd has set up the firewall (netd flushes the built-in
# chains when it starts, which would remove anything added before it),
# applies the module's rules, then checks every 10 seconds that they are
# still what they should be:
#
#   - settings.conf changed (WebUI, ctl.sh, a hand edit)  -> apply
#   - a pause ran out                                     -> apply
#   - a managed set disappeared                           -> rebuild it
#   - the module's chains or jumps changed (netd restart,
#     another firewall app, a manual iptables command)    -> repair
#
# Every check that touches iptables or sets runs under the module lock, so
# the watchdog never acts in the middle of a change made by ctl.sh, and
# never on a state that is seconds old. The result is published to
# $RUN/health for ctl.sh poll/status and the WebUI.

MODDIR=${0%/*}
if [ ! -f "$MODDIR/sh/common.sh" ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] sh/common.sh missing - reflash the module" >> /data/adb/ipset_arm64_data/ipset.log
  exit 1
fi
# shellcheck source=/dev/null
. "$MODDIR/sh/common.sh"

mkdir -p "$DATA" "$RUN"
load_settings

TICK=10
NETD_WAIT=90
AUTO_EVERY=6        # ticks between checks for due list updates
AUTO_BOOT_DELAY=120 # seconds after start before the first automatic update

renice -n 10 -p $$ >/dev/null 2>&1

# ── Single instance ──────────────────────────────────────────────────────────
MYPID=$$
for _p in /proc/[0-9]*; do
  _pid=${_p#/proc/}
  [ "$_pid" = "$MYPID" ] && continue
  case "$(tr '\0' ' ' 2>/dev/null < "$_p/cmdline")" in
    *"$MODULE_ID/service.sh"*) kill "$_pid" 2>/dev/null ;;
  esac
done
unset _p _pid
echo "$MYPID" > "$WATCHDOG_PIDFILE"

STARTED=$(mono_now)
NOW=$STARTED
REPAIRS=0
LAST_REPAIR="none"
LAST_REPAIR_AT=0
RETRY_DELAY4=30; RETRY_AT4=0
RETRY_DELAY6=30; RETRY_AT6=0
H_STATE="starting"
LAST_STATUS=""

if [ -z "$IPSET" ] || ! "$IPSET" --version >/dev/null 2>&1; then
  bootlog "service: ipset binary not runnable - watchdog not started"
  log_error "watchdog: ipset binary not runnable, nothing is enforced"
  set_module_status "⚠️ ipset binary not runnable"
  exit 1
fi
if [ -z "$IPT4" ] || [ -z "$RST4" ]; then
  bootlog "service: iptables / iptables-restore not found - watchdog not started"
  log_error "watchdog: iptables or iptables-restore not found, nothing is enforced"
  set_module_status "⚠️ iptables-restore not found"
  exit 1
fi

# ── State published to $HEALTH_FILE ──────────────────────────────────────────
compute_state() {
  if [ "$ENABLED" != "1" ]; then H_STATE=disabled; return; fi
  if is_paused; then H_STATE=paused; return; fi
  case "$(fam_state 4)" in ok | ok-drop) : ;; *) H_STATE=error; return ;; esac
  case "$(fam_state 6)" in
    ok | ok-drop) H_STATE=protected ;;
    off) if [ "$IPV6" = "1" ]; then H_STATE=partial; else H_STATE=protected; fi ;;
    *) H_STATE=partial ;;
  esac
}

write_health() {
  {
    echo "state=$H_STATE"
    echo "ipv4=$(fam_state 4)"
    echo "ipv6=$(fam_state 6)"
    echo "repairs=$REPAIRS"
    echo "last_repair=$LAST_REPAIR"
    echo "last_repair_at=$LAST_REPAIR_AT"
    echo "watchdog_started=$STARTED"
    echo "clock=monotonic"
    echo "tick_at=$NOW"
  } > "$HEALTH_FILE.tmp" 2>/dev/null && mv -f "$HEALTH_FILE.tmp" "$HEALTH_FILE"
}

fam_label() {
  _fl=""
  case "$(fam_state 4)" in ok | ok-drop) _fl="IPv4" ;; esac
  case "$(fam_state 6)" in ok | ok-drop) _fl="${_fl:+$_fl + }IPv6" ;; esac
  echo "${_fl:-none}"
  unset _fl
}

update_module_status() {
  case "$H_STATE" in
    protected) _us="✅ Protected ($(fam_label))" ;;
    partial)   _us="⚠️ Partly protected ($(fam_label))" ;;
    paused)    _us="⏸️ Paused" ;;
    disabled)  _us="⭕ Switched off" ;;
    *)         _us="❌ Not enforcing - open the WebUI" ;;
  esac
  if [ "$_us" != "$LAST_STATUS" ]; then
    set_module_status "$_us"
    LAST_STATUS=$_us
  fi
  unset _us
}

# After an apply that left a family in error, re-check that family with a
# growing delay (30 s ... 1 h) instead of every tick; the other family is
# still checked every tick. A settings change always retries at once.
after_apply() {
  compute_state
  for _aa_f in 4 6; do
    if [ "$_aa_f" = "4" ]; then _aa_d=$RETRY_DELAY4; else _aa_d=$RETRY_DELAY6; fi
    case "$(fam_state "$_aa_f")" in
      error*)
        _aa_at=$(( $(mono_now) + _aa_d ))
        _aa_d=$((_aa_d * 2)); [ "$_aa_d" -gt 3600 ] && _aa_d=3600
        ;;
      *) _aa_at=0; _aa_d=30 ;;
    esac
    if [ "$_aa_f" = "4" ]; then RETRY_AT4=$_aa_at; RETRY_DELAY4=$_aa_d
    else RETRY_AT6=$_aa_at; RETRY_DELAY6=$_aa_d; fi
  done
  unset _aa_f _aa_d _aa_at
}

# What (if anything) needs an apply. Called with the lock held.
# Prints "<kind> <family|all> <reason>"; kind = config (expected), retry (a family that
# failed, on its backoff schedule; logged only if the error changes) or
# repair (changed from outside).
# (Space, not "|": mksh treats | in ${x%%pattern} as alternation.)
what_changed() {
  if [ "$(mtime_of "$CONF")" != "$(cat "$APPLIED_CONF_MTIME" 2>/dev/null)" ]; then
    echo "config all settings changed"; return
  fi
  if [ -f "$PAUSE_FILE" ] && [ "$(pause_left)" -eq 0 ]; then
    rm -f "$PAUSE_FILE"
    echo "config all pause ended"; return
  fi
  if [ $((_ticks % AUTO_EVERY)) -eq 0 ] && dnsc_changed; then
    echo "config all dnscrypt-proxy configuration changed"; return
  fi
  _wc_m=""
  for _wc_i in $(src_enabled); do
    [ -s "$(src_file "$_wc_i")" ] && ! src_in_kernel "$_wc_i" && _wc_m="$_wc_m $_wc_i"
  done
  if [ -n "$_wc_m" ]; then
    echo "config all source(s) to load:$_wc_m"; unset _wc_m _wc_i; return
  fi
  unset _wc_i
  _wc_m=$(managed_missing | tr '\n' ' ')
  if [ -n "$_wc_m" ]; then
    echo "repair all managed set(s) missing: ${_wc_m% }"; unset _wc_m; return
  fi
  unset _wc_m
  _wc_now=$(mono_now)
  for _wc_f in 4 6; do
    [ "$_wc_f" = "6" ] && ! v6_supported && continue
    if [ "$_wc_f" = "4" ]; then _wc_r=$RETRY_AT4; else _wc_r=$RETRY_AT6; fi
    [ "$_wc_r" -gt 0 ] && [ "$_wc_now" -lt "$_wc_r" ] && continue
    # A family that failed earlier has no stored signature: this is the
    # scheduled retry, not something changed from outside.
    case "$(fam_state "$_wc_f")" in
      error*)
        # (RETRY_AT 0: the failure came from ctl.sh, not from this loop -
        # retry now, which also starts the backoff.)
        echo "retry $_wc_f IPv$_wc_f: retrying after the earlier failure"; unset _wc_f _wc_r _wc_now; return ;;
    esac
    if [ "$(rules_sig "$_wc_f")" != "$(cat "$RUN/sig$_wc_f" 2>/dev/null)" ]; then
      echo "repair $_wc_f IPv$_wc_f firewall rules changed from outside"; unset _wc_f _wc_r _wc_now; return
    fi
  done
  unset _wc_f _wc_r _wc_now
}

# ── Wait for netd ────────────────────────────────────────────────────────────
# netd's own chains appear in OUTPUT once it has finished its setup. On a
# ROM without them, go ahead after NETD_WAIT seconds; the watchdog repairs
# the jumps if netd flushes later anyway.
_w=0
while [ "$_w" -lt "$NETD_WAIT" ]; do
  if ipt_dump 4 | grep -qE -- '^-A OUTPUT -j (fw_OUTPUT|bw_OUTPUT|oem_out|st_OUTPUT)$'; then
    break
  fi
  sleep 2
  _w=$((_w + 2))
done
if [ "$_w" -ge "$NETD_WAIT" ]; then
  bootlog "service: netd chains not seen after ${NETD_WAIT}s - applying anyway"
else
  bootlog "service: netd ready after ${_w}s"
fi
unset _w

NOW=$(mono_now)
if lock_get 60; then
  rules_apply
  lock_release
else
  log_error "watchdog: could not get the lock for the first apply"
fi
load_settings
after_apply
bootlog "service: firewall applied - state $H_STATE (IPv4: $(fam_state 4), IPv6: $(fam_state 6))"
log_info "watchdog started (pid $MYPID) - state $H_STATE, IPv4 $(fam_state 4), IPv6 $(fam_state 6), SELinux $(getenforce 2>/dev/null || echo unknown)"
write_health
update_module_status

# ── Loop ─────────────────────────────────────────────────────────────────────
# The phone is shutting down: stop quietly. (Sets, rules and files of the
# module vanish under a running watchdog then, and every check would fail.)
# Checked at the start of each tick and again around an apply, because a
# tick that began just before the shutdown would otherwise carry on.
# shellcheck disable=SC2034  # read by the log functions in sh/common.sh
QUIET_ON_SHUTDOWN=1
stop_for_shutdown() {
  [ "$1" = "locked" ] && lock_release
  # shellcheck disable=SC2034
  QUIET_ON_SHUTDOWN=0
  log_info "watchdog: system shutting down, stopping"
  exit 0
}

_ticks=0
while true; do
  sleep "$TICK"
  NOW=$(mono_now)
  shutting_down && stop_for_shutdown
  if lock_try; then
    _chg=$(what_changed)
    [ -n "$_chg" ] && shutting_down && stop_for_shutdown locked
    if [ -n "$_chg" ]; then
      _kind=${_chg%% *}; _rest=${_chg#* }
      _fam=${_rest%% *}; _why=${_rest#* }
      [ "$_fam" = "all" ] && _fam=""
      if [ "$_kind" = "repair" ]; then
        REPAIRS=$((REPAIRS + 1))
        LAST_REPAIR=$_why
        LAST_REPAIR_AT=$NOW
        log_warn "watchdog: $_why - repairing"
      elif [ "$_kind" = "config" ]; then
        log_info "watchdog: $_why - applying"
      fi
      rules_apply $_fam
      # Do not publish a failed state (module description, health) that
      # only came from the shutdown.
      shutting_down && stop_for_shutdown locked
      load_settings
      after_apply
    fi
    _sd=$(sd_sync)
    [ -n "$_sd" ] && echo "$_sd" | while read -r _l; do log_info "sdcard: $_l"; done
    lock_release
  fi
  # Automatic list updates: checked once a minute, run detached so the
  # watchdog never waits on a download.
  # (Not in the first 2 minutes after boot: the network is usually not up.)
  if [ $((_ticks % AUTO_EVERY)) -eq 0 ] && [ $((NOW - STARTED)) -ge "$AUTO_BOOT_DELAY" ] && ! update_running; then
    _due=$(auto_due)
    if [ -n "$_due" ]; then
      log_info "watchdog: starting automatic list update ($AUTO_UPDATE): $_due"
      # shellcheck disable=SC2086
      update_spawn auto $_due
    fi
  fi
  load_settings
  compute_state
  write_health
  update_module_status
  _ticks=$((_ticks + 1))
  if [ "$_ticks" -ge 360 ]; then rotate_log; _ticks=0; fi
done
