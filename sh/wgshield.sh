#!/system/bin/sh
# shellcheck shell=sh disable=SC2034
#
# sh/wgshield.sh - never block the servers of the WG Shield module.
#
# Kernel WireGuard sends its UDP packets through filter OUTPUT, so a tunnel
# server that is in an enabled list would be refused and the tunnel could
# not connect. The server addresses go into ipsa_wgs4 / ipsa_wgs6, which the
# firewall lets through before any list, like the allowlist.
#
# Read from WG Shield (read only, same set - see the set handoff):
#   - the "Endpoint =" lines of /data/adb/wg-shield/tunnels/*.conf - only
#     those lines; the keys in the files are never read into a variable,
#     written or logged. IP endpoints only: a host name is resolved by
#     WG Shield itself when it connects, so it is not known here...
#   - ...except for the active tunnel: "endpoint=" in WG Shield's
#     state/status holds the address it really connected to (host names
#     resolved).
# The watchdog checks once a minute whether either changed.

WGS_TUNNELS="/data/adb/wg-shield/tunnels"
WGS_STATUS="/data/adb/wg-shield/state/status"

wgs_present() { [ -d "$WGS_TUNNELS" ]; }

# Endpoint addresses, one per line (IPv4 / IPv6, no port). Host names are
# counted on stderr as "hostnames=N".
wgs_addrs() {
  {
    for _wa_f in "$WGS_TUNNELS"/*.conf; do
      [ -f "$_wa_f" ] || continue
      # only the Endpoint lines leave this grep
      grep -i '^[[:space:]]*endpoint[[:space:]]*=' "$_wa_f" 2>/dev/null
    done
    first_line_key "$WGS_STATUS" endpoint && [ -n "$KV" ] && echo "endpoint=$KV"
  } | awk '
    {
      v = substr($0, index($0, "=") + 1)
      gsub(/[ \t\r]/, "", v)
      if (v == "") next
      if (substr(v, 1, 1) == "[") {           # [v6]:port
        e = index(v, "]"); if (e < 3) next
        a = substr(v, 2, e - 2)
      } else {
        n = split(v, p, ":")
        if (n < 2) next
        a = substr(v, 1, length(v) - length(p[n]) - 1)   # strip :port
      }
      if (a ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ || (a ~ /:/ && a ~ /^[0-9A-Fa-f:.]+$/)) print a
      else h++
    }
    END { if (h) printf "hostnames=%d\n", h > "/dev/stderr" }'
  unset _wa_f
}

# Value of <key>= in a key=value file into KV, without forks.
first_line_key() { # <file> <key>
  KV=""
  [ -f "$1" ] || return 1
  while IFS='=' read -r _fk_k _fk_v; do
    [ "$_fk_k" = "$2" ] && { KV=$_fk_v; break; }
  done 2>/dev/null < "$1"
  unset _fk_k _fk_v
  return 0
}

# What the sync depends on: the tunnel files (names + mtimes), the active
# endpoint and the switch. One stat and one cksum.
wgs_stamp() { # -> WS
  if [ "$WGSHIELD_ALLOW" = "1" ] && wgs_present; then
    WS=$(stat -c '%Y %n' "$WGS_TUNNELS" "$WGS_TUNNELS"/*.conf 2>/dev/null | cksum)
    WS=${WS%%[ 	]*}
    first_line_key "$WGS_STATUS" endpoint
    WS="$WS:$KV:1"
  else
    WS="off:$WGSHIELD_ALLOW"
  fi
}

wgs_changed() {
  wgs_stamp
  first_line "$RUN/wgs.stamp"
  [ "$WS" != "$FL" ]
}

# Load the addresses into ipsa_wgs4/6 (empty when switched off or when
# WG Shield is not installed). Caller holds the lock. Prints a summary.
wgs_sync() {
  _wy_l="$RUN/wgs.list"
  wgs_stamp
  _wy_h=0
  if [ "$WGSHIELD_ALLOW" = "1" ] && wgs_present; then
    wgs_addrs 2> "$RUN/wgs.err" | sort -u > "$_wy_l"
    _wy_h=$(sed -n 's/^hostnames=//p' "$RUN/wgs.err" 2>/dev/null)
    rm -f "$RUN/wgs.err"
  else
    : > "$_wy_l"
  fi
  echo "${_wy_h:-0}" > "$RUN/wgs.hostnames"
  parse_entries 4 < "$_wy_l" 2>/dev/null | set_load ipsa_wgs4 4 4096 >/dev/null
  parse_entries 6 < "$_wy_l" 2>/dev/null | set_load ipsa_wgs6 6 4096 >/dev/null
  echo "$WS" > "$RUN/wgs.stamp"
  _wy_n=$(( $(set_count ipsa_wgs4) + $(set_count ipsa_wgs6) ))
  if [ "$WGSHIELD_ALLOW" != "1" ]; then echo "off"
  elif wgs_present; then
    if [ "${_wy_h:-0}" -gt 0 ]; then
      echo "$_wy_n server address(es) of WG Shield kept reachable ($_wy_h host-name endpoint(s): only the active one is known here)"
    else
      echo "$_wy_n server address(es) of WG Shield kept reachable"
    fi
  else echo "WG Shield not installed"
  fi
  unset _wy_l _wy_n _wy_h
}
