#!/system/bin/sh
# shellcheck shell=sh disable=SC2034
#
# sh/dnscrypt.sh - get along with the dnscrypt-proxy module.
#
# If dnscrypt-proxy-android-arm64-only is installed, the addresses it needs
# must never be blocked by a list here, or this phone would lose DNS:
#   - bootstrap_resolvers and netprobe_address from its dnscrypt-proxy.toml
#   - the servers pinned in its [static] section (the address inside each
#     sdns:// stamp; stamps without an address - DoH by hostname - have none)
# They go into ipsa_dnsc4 / ipsa_dnsc6, which the firewall lets through
# before any list, like the allowlist. The watchdog re-reads the file when
# it changes (a resolver switched in the DNSCrypt WebUI, say).

DNSC_TOML="/data/adb/dnscrypt-proxy/dnscrypt-proxy.toml"

# sdns:// stamp -> the server address in it (IP, no port), or nothing.
# Layout: protocol byte, 8 property bytes, then a length-prefixed address.
stamp_addr() {
  _st_s=${1#sdns://}
  _st_s=$(echo "$_st_s" | tr '_-' '/+')
  case $(( ${#_st_s} % 4 )) in 2) _st_s="$_st_s==" ;; 3) _st_s="$_st_s=" ;; esac
  echo "$_st_s" | base64 -d 2>/dev/null | od -An -tu1 -v | awk '
    { for (i = 1; i <= NF; i++) b[n++] = $i }
    END {
      p = b[0]
      if (n < 10 || (p != 0 && p != 1 && p != 2 && p != 3 && p != 4)) exit
      l = b[9]; a = ""
      for (i = 10; i < 10 + l && i < n; i++) a = a sprintf("%c", b[i])
      if (a == "") exit
      if (substr(a, 1, 1) == "[") { sub(/^\[/, "", a); sub(/\].*$/, "", a) }
      else if (gsub(/:/, ":", a) == 1) sub(/:[0-9]+$/, "", a)
      print a
    }'
  unset _st_s
}

# Every address dnscrypt-proxy needs, one per line (not yet validated).
dnsc_addrs() {
  [ -f "$DNSC_TOML" ] || return 0
  # bootstrap_resolvers = ['9.9.9.9:53', ...]   netprobe_address = '9.9.9.9:53'
  awk '
    /^[ \t]*(bootstrap_resolvers|netprobe_address)[ \t]*=/ {
      v = $0; sub(/^[^=]*=/, "", v); sub(/#.*$/, "", v)
      gsub(/[][\047"\t ]/, "", v)
      n = split(v, a, ",")
      for (i = 1; i <= n; i++) {
        x = a[i]; if (x == "") continue
        if (substr(x, 1, 1) == "[") { sub(/^\[/, "", x); sub(/\].*$/, "", x) }
        else if (gsub(/:/, ":", x) == 1) sub(/:[0-9]+$/, "", x)
        print x
      }
    }' "$DNSC_TOML"
  # the stamps of the [static] servers (and any other uncommented stamp line)
  sed -n "s/^[ \t]*stamp[ \t]*=[ \t]*['\"]\(sdns:\/\/[A-Za-z0-9_-]*\)['\"].*/\1/p" "$DNSC_TOML" |
    while read -r _da_s; do stamp_addr "$_da_s"; done
  unset _da_s
}

dnsc_present() { [ -f "$DNSC_TOML" ]; }

# Load the addresses into ipsa_dnsc4/6 (empty when switched off or when
# dnscrypt is not installed). Caller holds the lock. Prints a summary.
dnsc_sync() {
  _dy_l="$RUN/dnsc.list"
  if [ "$DNSCRYPT_ALLOW" = "1" ] && dnsc_present; then
    dnsc_addrs | sort -u > "$_dy_l"
  else
    : > "$_dy_l"
  fi
  parse_entries 4 < "$_dy_l" 2>/dev/null | set_load ipsa_dnsc4 4 1024 >/dev/null
  parse_entries 6 < "$_dy_l" 2>/dev/null | set_load ipsa_dnsc6 6 1024 >/dev/null
  mtime_of "$DNSC_TOML" > "$RUN/dnsc.mtime"
  echo "$DNSCRYPT_ALLOW" >> "$RUN/dnsc.mtime"
  _dy_n=$(( $(set_count ipsa_dnsc4) + $(set_count ipsa_dnsc6) ))
  if [ "$DNSCRYPT_ALLOW" != "1" ]; then echo "off"
  elif dnsc_present; then echo "$_dy_n address(es) of dnscrypt-proxy kept reachable"
  else echo "dnscrypt-proxy not installed"
  fi
  unset _dy_l _dy_n
}

# Has the dnscrypt config (or the switch) changed since the last sync?
dnsc_changed() {
  _dc_m=$(mtime_of "$DNSC_TOML"); _dc_a=""; _dc_b=""
  { read -r _dc_a; read -r _dc_b; } 2>/dev/null < "$RUN/dnsc.mtime"
  [ "$_dc_m" != "$_dc_a" ] || [ "$DNSCRYPT_ALLOW" != "$_dc_b" ]
  _dc_rc=$?
  unset _dc_m _dc_a _dc_b
  return "$_dc_rc"
}
