#!/system/bin/sh
# shellcheck shell=sh disable=SC2034
#
# sh/rules.sh - the module's firewall, for IPv4 (iptables) and IPv6
# (ip6tables) alike.
#
# Everything lives in the module's own chains of the filter table:
#
#   OUTPUT  -> IPSA_OUT     INPUT -> IPSA_IN     FORWARD -> IPSA_FWD
#
#   IPSA_OUT   loopback                          RETURN
#              IPSA_ADV_OUT (advanced rules, exactly as written)
#              ipsa_allow  dst                   RETURN   (allowlist wins)
#              ipsa_lan    dst                   RETURN   (never block LAN etc.)
#              ipsa_out    dst                   REJECT or DROP
#   IPSA_IN    loopback RETURN, IPSA_ADV_IN, then replies to connections
#              this phone opened (conntrack ESTABLISHED,RELATED) RETURN -
#              "incoming" means unsolicited traffic; without this a list
#              that blocks incoming only would also kill the answers to the
#              phone's own connections - then allowlist, LAN, ipsa_in src DROP
#   IPSA_FWD   the same with dst                 (when FORWARD_BLOCK=1)
#
# A chain's content is written with one iptables-restore --noflush: the
# kernel swaps the whole table in one step, so the chain is never half
# built. Before that the exact text is checked with iptables-restore
# --test, so a rule the kernel refuses can never replace a working chain.
#
# Only the jumps from the built-in chains are added and removed one by one.
# netd flushes OUTPUT/INPUT/FORWARD when it starts (and when it restarts),
# which removes the jumps but not the chains; the watchdog puts them back.
# Enabling, disabling and pausing only move the jumps.

IPSA_CHAINS="IPSA_OUT IPSA_IN IPSA_FWD IPSA_ADV_OUT IPSA_ADV_IN IPSA_ADV_FWD"
IPSA_JUMPS="OUTPUT:IPSA_OUT INPUT:IPSA_IN FORWARD:IPSA_FWD"

# ── Wrappers ─────────────────────────────────────────────────────────────────
# -w: wait for the xtables lock instead of failing while netd holds it.
# Which form this iptables understands is worked out once per boot.
IPT_W_FILE="$RUN/ipt_wait"
IPT_W="-"
RST_W="-"

_ipt_wait_init() {
  [ "$IPT_W" != "-" ] && return 0
  if [ -f "$IPT_W_FILE" ]; then
    IPT_W=$(sed -n 1p "$IPT_W_FILE"); RST_W=$(sed -n 2p "$IPT_W_FILE")
    return 0
  fi
  IPT_W=""; RST_W=""
  for _iw in "-w 5" "-w"; do
    # shellcheck disable=SC2086
    if "$IPT4" $_iw -S OUTPUT >/dev/null 2>&1; then IPT_W=$_iw; break; fi
  done
  for _iw in "-w 5" "-w"; do
    # shellcheck disable=SC2086
    if printf '*filter\nCOMMIT\n' | "$RST4" $_iw --noflush --test >/dev/null 2>&1; then RST_W=$_iw; break; fi
  done
  unset _iw
  mkdir -p "$RUN"
  printf '%s\n%s\n' "$IPT_W" "$RST_W" > "$IPT_W_FILE" 2>/dev/null
}

ipt() { # <4|6> <args...>
  _ipt_wait_init
  if [ "$1" = "6" ]; then _ipt_b=$IPT6; else _ipt_b=$IPT4; fi
  shift
  [ -n "$_ipt_b" ] || return 127
  # shellcheck disable=SC2086
  "$_ipt_b" $IPT_W "$@"
}

ipt_restore() { # <4|6> [--test]   (rules on stdin)
  _ipt_wait_init
  if [ "$1" = "6" ]; then _ir_b=$RST6; else _ir_b=$RST4; fi
  shift
  [ -n "$_ir_b" ] || return 127
  # shellcheck disable=SC2086
  "$_ir_b" $RST_W --noflush "$@"
}

# ── Rendering ────────────────────────────────────────────────────────────────
# Advanced rules from rules.conf, for one family, as iptables-restore lines.
# A rule whose set does not exist, or whose set belongs to the other
# family, is left out (and noted), so it can never break the rest.
_adv_render() { # <family>
  [ -s "$RULES" ] || return 0
  while IFS='|' read -r _ar_c _ar_n _ar_d _ar_t _ar_u; do
    [ -n "$_ar_c" ] || continue
    _ar_sf=$(set_family "$_ar_n") || { echo "missing|$_ar_c|$_ar_n|$_ar_d|$_ar_t|$_ar_u" >> "$RUN/adv_skipped.$1"; continue; }
    [ "$_ar_sf" = "any" ] || [ "$_ar_sf" = "$1" ] || continue
    case "$_ar_c" in
      OUTPUT) _ar_ch=IPSA_ADV_OUT ;;
      INPUT) _ar_ch=IPSA_ADV_IN ;;
      FORWARD) _ar_ch=IPSA_ADV_FWD ;;
      *) continue ;;
    esac
    _ar_o=""
    [ -n "$_ar_u" ] && _ar_o="-m owner --uid-owner $_ar_u "
    echo "-A $_ar_ch ${_ar_o}-m set --match-set $_ar_n $_ar_d -j $_ar_t"
  done < "$RULES"
  unset _ar_c _ar_n _ar_d _ar_t _ar_u _ar_sf _ar_ch _ar_o
}

# The blocking rule. With REJECT, TCP gets a TCP reset: it is not subject
# to the kernel's ICMP rate limit (IPv6 allows one error per second by
# default, so a second connection attempt could wait a full second before
# failing), and the app sees "connection refused" at once.
_br_block() { # <chain> <family> <dir> <target> <aggregate: ipsa_out|ipsa_in>
  if [ "$4" = "REJECT" ]; then
    echo "-A $1 -p tcp -m set --match-set $5$2 $3 -j REJECT --reject-with tcp-reset"
  fi
  echo "-A $1 -m set --match-set $5$2 $3 -j $4"
}

# The module's own rules for one family (no header, no COMMIT).
_base_render() { # <family> <outgoing target>
  echo "-A IPSA_OUT -o lo -j RETURN"
  echo "-A IPSA_OUT -j IPSA_ADV_OUT"
  echo "-A IPSA_OUT -m set --match-set ipsa_allow$1 dst -j RETURN"
  echo "-A IPSA_OUT -m set --match-set ipsa_dnsc$1 dst -j RETURN"
  echo "-A IPSA_OUT -m set --match-set ipsa_wgs$1 dst -j RETURN"
  echo "-A IPSA_OUT -m set --match-set ipsa_lan$1 dst -j RETURN"
  _br_block IPSA_OUT "$1" dst "$2" ipsa_out
  echo "-A IPSA_IN -i lo -j RETURN"
  echo "-A IPSA_IN -j IPSA_ADV_IN"
  [ "$(ct_ok "$1")" = "1" ] && echo "-A IPSA_IN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
  echo "-A IPSA_IN -m set --match-set ipsa_allow$1 src -j RETURN"
  echo "-A IPSA_IN -m set --match-set ipsa_dnsc$1 src -j RETURN"
  echo "-A IPSA_IN -m set --match-set ipsa_wgs$1 src -j RETURN"
  echo "-A IPSA_IN -m set --match-set ipsa_lan$1 src -j RETURN"
  echo "-A IPSA_IN -m set --match-set ipsa_in$1 src -j DROP"
  echo "-A IPSA_FWD -j IPSA_ADV_FWD"
  if [ "$FORWARD_BLOCK" = "1" ]; then
    echo "-A IPSA_FWD -m set --match-set ipsa_allow$1 dst -j RETURN"
    echo "-A IPSA_FWD -m set --match-set ipsa_lan$1 dst -j RETURN"
    _br_block IPSA_FWD "$1" dst "$2" ipsa_out
  fi
}

# Does this kernel have the conntrack match? Asked once per boot and family,
# with a throw-away chain in test mode (nothing is installed).
ct_ok() { # <family> -> 1 / 0
  if [ ! -f "$RUN/ct$1" ]; then
    if printf '*filter\n:IPSA_CTTEST - [0:0]\n-A IPSA_CTTEST -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN\nCOMMIT\n' |
      ipt_restore "$1" --test >/dev/null 2>&1; then
      echo 1 > "$RUN/ct$1"
    else
      echo 0 > "$RUN/ct$1"
      log_warn "IPv$1: no conntrack match in this kernel - a list set to incoming only also drops the replies to this phone's own connections"
    fi
  fi
  cat "$RUN/ct$1"
}

_wrap() { # (rule lines on stdin) -> complete restore text
  echo "*filter"
  for _w_c in $IPSA_CHAINS; do echo ":$_w_c - [0:0]"; done
  cat
  echo "COMMIT"
  unset _w_c
}

_restore_test() { # <family> <file>
  ipt_restore "$1" --test < "$2" >/dev/null 2>"$RUN/restore_err.$1"
}

# ── Apply ────────────────────────────────────────────────────────────────────
# Record a family error. Logged when it is new, not on every retry of the
# same failure (a kernel without IPv6 filtering would otherwise log every
# retry for as long as the phone is on).
_fam_error() { # <family> <short reason> <log text>
  if [ "$(cat "$RUN/fam$1" 2>/dev/null)" != "error:$2" ]; then
    log_error "IPv$1: $3 ($2)"
  fi
  echo "error:$2" > "$RUN/fam$1"
}

# Build and install the chains of one family, then set the jumps.
# Result in $RUN/fam<f>: ok | ok-drop | off | unavailable | error:<reason>
_fam_apply() { # <family> <active 0|1>
  _fa_f=$1
  _fa_dir="$RUN/rules$_fa_f"
  mkdir -p "$_fa_dir"
  rm -f "$RUN/adv_skipped.$_fa_f" "$RUN/adv_rejected.$_fa_f"

  _fa_t=$OUT_TARGET
  _base_render "$_fa_f" "$_fa_t" > "$_fa_dir/base"
  _adv_render "$_fa_f" > "$_fa_dir/adv"

  # 1. The module's own rules must pass on their own. The only thing that
  #    differs between kernels here is REJECT (IPv6 REJECT is a separate
  #    kernel option), so fall back to DROP before giving up.
  _wrap < "$_fa_dir/base" > "$_fa_dir/test"
  if ! _restore_test "$_fa_f" "$_fa_dir/test"; then
    if [ "$_fa_t" = "REJECT" ]; then
      _fa_t=DROP
      _base_render "$_fa_f" DROP > "$_fa_dir/base"
      _wrap < "$_fa_dir/base" > "$_fa_dir/test"
    fi
    if ! _restore_test "$_fa_f" "$_fa_dir/test"; then
      _fa_why=$(head -n 1 "$RUN/restore_err.$_fa_f" 2>/dev/null | sed 's/^.*tables-restore[^:]*: //' | tr '|=' '  ')
      _fam_error "$_fa_f" "${_fa_why:-rules refused by the kernel}" "firewall rules refused, protection for IPv$_fa_f is not active"
      _jumps_off "$_fa_f"
      unset _fa_f _fa_dir _fa_t _fa_why
      return 1
    fi
    log_warn "IPv$_fa_f: REJECT is not supported by this kernel, using DROP"
  fi

  # 2. Advanced rules: all together if they pass, otherwise one by one,
  #    keeping those the kernel accepts.
  cat "$_fa_dir/base" "$_fa_dir/adv" | _wrap > "$_fa_dir/full"
  if [ -s "$_fa_dir/adv" ] && ! _restore_test "$_fa_f" "$_fa_dir/full"; then
    : > "$_fa_dir/adv_ok"
    while read -r _fa_r; do
      if { cat "$_fa_dir/base"; echo "$_fa_r"; } | _wrap | ipt_restore "$_fa_f" --test >/dev/null 2>&1; then
        echo "$_fa_r" >> "$_fa_dir/adv_ok"
      else
        echo "$_fa_r" >> "$RUN/adv_rejected.$_fa_f"
        log_warn "IPv$_fa_f: advanced rule refused by the kernel, skipped: $_fa_r"
      fi
    done < "$_fa_dir/adv"
    cat "$_fa_dir/base" "$_fa_dir/adv_ok" | _wrap > "$_fa_dir/full"
  fi

  # 3. Install.
  if ! ipt_restore "$_fa_f" < "$_fa_dir/full" >/dev/null 2>"$RUN/restore_err.$_fa_f"; then
    _fa_why=$(head -n 1 "$RUN/restore_err.$_fa_f" 2>/dev/null | sed 's/^.*tables-restore[^:]*: //' | tr '|=' '  ')
    _fam_error "$_fa_f" "${_fa_why:-iptables-restore failed}" "iptables-restore failed after a successful test"
    unset _fa_f _fa_dir _fa_t _fa_why _fa_r
    return 1
  fi

  # 4. Confirm: the chain holds what was written (not assumed).
  _fa_want=$(grep -c '^-A IPSA_OUT ' "$_fa_dir/full")
  _fa_have=$(ipt_dump "$_fa_f" | grep -c '^-A IPSA_OUT ')
  if [ "$_fa_want" != "$_fa_have" ]; then
    _fam_error "$_fa_f" "chain content not confirmed" "IPSA_OUT has $_fa_have rule(s) after apply, expected $_fa_want"
    unset _fa_f _fa_dir _fa_t _fa_want _fa_have _fa_r
    return 1
  fi

  if [ "$2" = "1" ]; then _jumps_on "$_fa_f"; else _jumps_off "$_fa_f"; fi

  if [ "$2" != "1" ]; then echo off > "$RUN/fam$_fa_f"
  elif [ "$_fa_t" = "$OUT_TARGET" ]; then echo ok > "$RUN/fam$_fa_f"
  else echo ok-drop > "$RUN/fam$_fa_f"
  fi
  rules_sig "$_fa_f" > "$RUN/sig$_fa_f"
  unset _fa_f _fa_dir _fa_t _fa_want _fa_have _fa_r
  return 0
}

_jumps_on() { # <family>
  for _jo_p in $IPSA_JUMPS; do
    _jo_b=${_jo_p%%:*}; _jo_c=${_jo_p#*:}
    ipt "$1" -C "$_jo_b" -j "$_jo_c" 2>/dev/null || ipt "$1" -I "$_jo_b" 1 -j "$_jo_c" 2>/dev/null ||
      log_error "IPv$1: could not add the jump $_jo_b -> $_jo_c"
  done
  unset _jo_p _jo_b _jo_c
}

_jumps_off() { # <family>
  for _jf_p in $IPSA_JUMPS; do
    _jf_b=${_jf_p%%:*}; _jf_c=${_jf_p#*:}
    _jf_i=0
    while [ "$_jf_i" -lt 5 ] && ipt "$1" -C "$_jf_b" -j "$_jf_c" 2>/dev/null; do
      ipt "$1" -D "$_jf_b" -j "$_jf_c" 2>/dev/null
      _jf_i=$((_jf_i + 1))
    done
  done
  unset _jf_p _jf_b _jf_c _jf_i
}

# ── Reading without the xtables lock (r11) ───────────────────────────────────
# "iptables -S / -L / -C" can take the global xtables lock. VPN apps such as
# WireGuard's wg-quick run iptables WITHOUT -w and fail outright if anyone
# holds it at that instant ("wg-quick returned 4" / "124", measured on the
# phone). The watchdog tick and the dashboard poll read the tables often,
# so they read with iptables-save, which never takes the lock. Writing
# (iptables-restore, -I/-D) is unchanged.
ipt_dump() { # <family> [-c]  -> filter table, iptables-save format
  if [ "$1" = "6" ]; then _dp_b=$SAV6; else _dp_b=$SAV4; fi
  if [ -n "$_dp_b" ]; then
    # shellcheck disable=SC2086
    "$_dp_b" $2 -t filter 2>/dev/null
  else
    # no iptables-save: fall back to -S (same "-A ..." lines)
    ipt "$1" -S 2>/dev/null
  fi
  unset _dp_b
}

# Everything of the module in one family's filter table, as one checksum.
# Only the "-A" lines: chain declarations differ between iptables-save and
# -S, and a jump or rule is what matters.
rules_sig_v() { # <family> -> SIG, and SIG_OK=1 when the table could be read
  _rs_d=$(ipt_dump "$1")
  # A readable filter table always names OUTPUT (":OUTPUT ACCEPT" or
  # "-P OUTPUT"). Empty output = the tool failed (e.g. while the phone
  # shuts down), which is not "rules changed from outside".
  case "$_rs_d" in *OUTPUT*) SIG_OK=1 ;; *) SIG_OK=0 ;; esac
  SIG=$(printf '%s\n' "$_rs_d" | grep '^-A .*IPSA_' | cksum)
  SIG="${SIG%%[ 	]*}${SIG##*[ 	]}"   # "crc size" -> "crcsize"
  unset _rs_d
}
rules_sig() { # <family>
  rules_sig_v "$1"; echo "$SIG"
}

# jump_present <family> <parent> <chain>, on a dump in $2... kept simple:
jump_count() { # <family> <parent> <chain>
  ipt_dump "$1" | awk -v j="-A $2 -j $3" '$0 == j { c++ } END { print c + 0 }'
}

v6_supported() { [ -n "$IPT6" ] && [ -n "$RST6" ]; }

# Up to r9 advanced rules were inserted straight into OUTPUT/INPUT/FORWARD.
# Remove any that are still there (from before the update, this boot).
_legacy_cleanup() {
  [ -s "$RULES" ] || return 0
  while IFS='|' read -r _lc_c _lc_n _lc_d _lc_t _lc_u; do
    [ -n "$_lc_c" ] || continue
    _lc_o=""
    [ -n "$_lc_u" ] && _lc_o="-m owner --uid-owner $_lc_u"
    _lc_i=0
    # shellcheck disable=SC2086
    while [ "$_lc_i" -lt 5 ] && ipt 4 -C "$_lc_c" $_lc_o -m set --match-set "$_lc_n" "$_lc_d" -j "$_lc_t" 2>/dev/null; do
      # shellcheck disable=SC2086
      ipt 4 -D "$_lc_c" $_lc_o -m set --match-set "$_lc_n" "$_lc_d" -j "$_lc_t" 2>/dev/null
      _lc_i=$((_lc_i + 1))
    done
  done < "$RULES"
  unset _lc_c _lc_n _lc_d _lc_t _lc_u _lc_o _lc_i
}

# Bring the firewall to what the settings say. The caller holds the lock.
# With <family> (4 or 6) only that family is rebuilt - a repair or retry of
# one family leaves the other family's chains (and packet counters) alone.
# Returns 0 when IPv4 is fine (IPv6 trouble is reported, not fatal).
rules_apply() { # [family]
  _ra_only=${1:-}
  load_settings
  mkdir -p "$RUN"
  _ra_active=1
  { [ "$ENABLED" = "1" ] && ! is_paused; } || _ra_active=0

  if ! sets_ensure 0; then
    log_warn "some managed sets could not be prepared - see the lines above"
  fi
  [ -f "$RUN/legacy_cleaned" ] || { _legacy_cleanup; : > "$RUN/legacy_cleaned"; }
  legacy_feed_migrate_files
  sources_sync
  if dnsc_changed; then _ra_d=$(dnsc_sync); log_info "dnscrypt: $_ra_d"; fi
  if wgs_changed; then _ra_d=$(wgs_sync); log_info "wg-shield: $_ra_d"; fi

  _ra_rc=0
  if [ "$_ra_only" != "6" ]; then
    _fam_apply 4 "$_ra_active"
    _ra_rc=$?
  else
    case "$(fam_state 4)" in ok | ok-drop | off) : ;; *) _ra_rc=1 ;; esac
  fi

  if [ "$_ra_only" != "4" ]; then
    if [ "$IPV6" = "1" ] && v6_supported; then
      _fam_apply 6 "$_ra_active"
    elif v6_supported; then
      _jumps_off 6
      echo off > "$RUN/fam6"
      rules_sig 6 > "$RUN/sig6"
    else
      echo unavailable > "$RUN/fam6"
    fi
  fi

  legacy_feed_migrate_set
  mono_now > "$RUN/applied_at"
  [ -z "$_ra_only" ] && conf_stamp > "$APPLIED_CONF_MTIME"
  _ra_r=$_ra_rc
  unset _ra_active _ra_rc _ra_only _ra_d
  return "$_ra_r"
}

# Remove every chain and jump of the module (uninstall, flush).
rules_remove_all() {
  for _rr_f in 4 6; do
    [ "$_rr_f" = "6" ] && ! v6_supported && continue
    _jumps_off "$_rr_f"
    for _rr_c in $IPSA_CHAINS; do ipt "$_rr_f" -F "$_rr_c" 2>/dev/null; done
    for _rr_c in $IPSA_CHAINS; do ipt "$_rr_f" -X "$_rr_c" 2>/dev/null; done
  done
  _legacy_cleanup
  unset _rr_f _rr_c
}

fam_state() { cat "$RUN/fam$1" 2>/dev/null || echo unknown; }
