#!/system/bin/sh
# customize.sh - install / update.
#
# Your data lives in /data/adb/ipset_arm64_data, outside the module, and is
# kept across updates: settings, allow/block lists, advanced sets and rules.

# shellcheck disable=SC2034
SKIPUNZIP=0

if [ "$ARCH" != "arm64" ]; then
  abort "! This module is for arm64 devices only (this device: $ARCH)"
fi

ui_print "- Setting permissions"
set_perm_recursive "$MODPATH/system/bin" 0 0 0755 0755
for _f in ctl.sh ipctl.sh service.sh post-fs-data.sh uninstall.sh; do
  [ -f "$MODPATH/$_f" ] && set_perm "$MODPATH/$_f" 0 0 0755
done
set_perm_recursive "$MODPATH/sh" 0 0 0755 0644

if ! "$MODPATH/system/bin/ipset" --version >/dev/null 2>&1; then
  ui_print "! Warning: the ipset binary does not run on this device"
fi

# shellcheck disable=SC2034
MODDIR="$MODPATH"
# shellcheck source=/dev/null
. "$MODPATH/sh/common.sh"

mkdir -p "$DATA"
if [ -f "$CONF" ]; then
  ui_print "- Keeping your settings"
  # Settings added in this version: write them with their defaults, so
  # the file shows every option (existing values are never changed).
  if ! grep -q '^SOURCES=' "$CONF"; then
    printf '\n# Blocklist sources, comma separated, or "none". See: ctl.sh sources\nSOURCES=firehol-level1,spamhaus-dropv6\n' >> "$CONF"
    ui_print "  + SOURCES=firehol-level1,spamhaus-dropv6"
  fi
  # r10 stage 3: IN_BLOCK (one switch for all incoming) became a direction
  # per list. IN_BLOCK=0 meant "outgoing only" for everything.
  if grep -q '^IN_BLOCK=' "$CONF"; then
    if grep -q '^IN_BLOCK=0' "$CONF"; then
      _d="user:out"
      for _i in firehol-level1 firehol-level2 firehol-level3 firehol-level4 firehol-webclient spamhaus-dropv6; do _d="$_d,$_i:out"; done
      grep -q '^DIRECTIONS=' "$CONF" || printf '\nDIRECTIONS=%s\n' "$_d" >> "$CONF"
      ui_print "  * incoming blocking was off: every list now blocks outgoing only"
    fi
    sed -i '/^# Also drop incoming packets from blocked addresses/d; /^IN_BLOCK=/d' "$CONF"
  fi
  if ! grep -q '^DIRECTIONS=' "$CONF"; then
    printf '\n# Which traffic each list blocks: <id>:out, <id>:in or <id>:both, comma\n# separated ("user" = your own blocklist). A list not named here blocks both.\nDIRECTIONS=\n' >> "$CONF"
  fi
  if ! grep -q '^DNSCRYPT_ALLOW=' "$CONF"; then
    printf '\n# If the dnscrypt-proxy module is installed, never block the resolvers it\n# uses (read from its dnscrypt-proxy.toml) (1/0).\nDNSCRYPT_ALLOW=1\n' >> "$CONF"
  fi
  if ! grep -q '^AUTO_UPDATE=' "$CONF"; then
    printf '\n# Automatic list updates: off, daily or weekly.\nAUTO_UPDATE=off\n' >> "$CONF"
    ui_print "  + AUTO_UPDATE=off"
  fi
else
  write_default_settings
  ui_print "- Default settings written"
fi

# Up to r9 the log was ipctl.log, in another format. Start the new one.
if [ -f "$DATA/ipctl.log" ]; then
  rm -f "$DATA/ipctl.log"
  ui_print "- Old log (ipctl.log) replaced by ipset.log"
fi

_sets=$(grep -c . "$OWNED" 2>/dev/null)
_rules=$(grep -c . "$RULES" 2>/dev/null)
if [ "${_sets:-0}" -gt 0 ] || [ "${_rules:-0}" -gt 0 ]; then
  ui_print "- Keeping your advanced sets (${_sets:-0}) and rules (${_rules:-0})"
  ui_print "  Rules now run in the module's own chains, for IPv4 and IPv6"
fi
[ -f "$ALLOW_FILE" ] || printf '# Allowlist - one IPv4/IPv6 address or network per line. Always wins.\n' > "$ALLOW_FILE"
[ -f "$BLOCK_FILE" ] || printf '# Your own blocklist - one IPv4/IPv6 address or network per line.\n' > "$BLOCK_FILE"

: > "$BOOTLOG"
log_info "installed $(sed -n 's/^version=//p' "$MODPATH/module.prop")"

ui_print "- Reboot, then open the WebUI: choose your lists and press Update"
ui_print "  Command line: su -c '/system/bin/sh /data/adb/modules/$MODULE_ID/ctl.sh status'"
