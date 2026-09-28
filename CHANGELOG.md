# Changelog

All notable changes to this module are documented here.

## v7.24-r12

Quiet reboots.

* **No more red lines in the log after a reboot.** If the watchdog's 10-second check happened to start while the phone was already shutting down, it tried to reload the lists and rules while Android was taking the system apart, and logged a burst of errors (*"could not build ipsa_lan4"*, *"firewall rules refused"*). They were harmless — the next boot always came up protected — but looked like a failure. The watchdog now also notices a shutdown at its very start (`sys.shutdown.requested`, not only `sys.powerctl` at its end), checks again before and after applying, and stops without logging errors that only came from the shutdown
* The module description in the root manager no longer shows *"Not enforcing"* after such a reboot until the new boot applies the rules

## v7.24-r11

Friendlier to VPN apps.

* **No more firewall lock while checking.** Android's firewall has one global lock. VPN apps such as WireGuard (`wg-quick`) run their firewall commands without waiting for it and fail outright if anyone holds it at that moment — *"wg-quick returned 4"* or *"124"*, a tunnel that will not start or stop. The watchdog's check every 10 seconds, the dashboard's hit counters (refreshed every few seconds) and the status page read the tables with commands that can take the lock. They now use `iptables-save` (counters with `iptables-save -c`), which never takes it. Writing is unchanged: one `iptables-restore` per family, as before
* The boot wait for Android's firewall setup reads without the lock too

## v7.24-r10

The biggest release so far: the module becomes an IP blocklist with a new core, IPv6, a choice of lists, a new WebUI and a Help page. Settings, your sets and your rules carry over from r9 automatically.

### Blocking

* **IPv6 is filtered too.** Every rule now exists for iptables and ip6tables alike. Until r9 only IPv4 was ever blocked — an IPv6 set could be created, but no rule could use it
* The module keeps its rules in **its own chains** (`IPSA_OUT`, `IPSA_IN`, `IPSA_FWD`), linked at the top of `OUTPUT`, `INPUT` and `FORWARD`, instead of inserting rules straight into Android's chains
* Rules are written with one `iptables-restore` per family, checked by the kernel in test mode first. A rule the kernel refuses is left out and reported; it can no longer replace a working chain or take the phone offline
* **Special-purpose ranges are never blocked**: loopback, private LAN, carrier NAT (`100.64/10`), link-local, multicast. Every list entry overlapping them is removed — before, only exact line matches were, so a differently aggregated list could have cut the phone off from its own router
* Outgoing connections to a blocked address are **refused at once** (TCP reset, ICMP for the rest), or dropped silently if you prefer. The reset is not subject to the kernel's ICMP rate limit, which could delay a refusal on IPv6 by a second
* A **watchdog** checks every 10 seconds and repairs the links that netd removes when it starts or restarts; repairs are counted on the Dashboard. Before, rules were restored once at boot and never again
* Settings changes, list edits and pauses are applied by the watchdog within 10 seconds, and it retries failures with a growing delay instead of every tick
* Every change is serialised by a lock with safe takeover of a lock left by a killed process — two taps in the WebUI can no longer corrupt the saved state

### Blocklists

* A catalog of lists: **FireHOL Level 1, 2, 3, 4, Web client** (IPv4) and **Spamhaus DROPv6** (IPv6). Level 1 and DROPv6 are preselected
* **A direction for each list** — Outgoing, Incoming or Both — and for your own blocklist. Incoming lets the replies to the phone's own connections through, so it blocks only unsolicited traffic
* Every list has its own set, joined into per-direction aggregates: adding, removing, updating or redirecting a list never touches the firewall rules or resets their counters
* Each list is cached. A failed download, or one with far fewer entries than expected, keeps the last good copy — a list never shrinks by accident
* **Nothing is downloaded until you ask.** Automatic update off / daily / weekly, only when you switch it on; the Dashboard shows when the next update is due and how the last one went, kept across reboots
* Automatic updates run inside the watchdog, detached, from two minutes after boot, with at most one attempt an hour per list (as Spamhaus asks)
* **View** any downloaded list, search it, and let a network through
* The r9 threat feed (`feed_firehol_level1`) becomes the FireHOL Level 1 list. Its entries seed the cache, so protection continues immediately after the update, even offline; the old set and its rules are removed

### Your lists and tools

* **Your blocklist and allowlist**, IPv4 and IPv6, as `ip-blocklist.txt` / `ip-allowlist.txt`, mirrored to `/sdcard/ipset-arm64/` — edit them with any app, applied within 10 seconds. The allowlist always wins
* **Check an address**: which lists hold it, in which direction, and the verdict
* **Test connection**: a real TCP connection from the phone to any address and port; whether this module stopped it is read from its own rule counters
* **Pause** for 15 minutes, 1 hour or 4 hours; a reboot also ends a pause
* A master switch that turns everything off without uninstalling

### DNSCrypt

* If dnscrypt-proxy-android-arm64-only is installed, its bootstrap resolvers, connectivity probe and pinned `[static]` servers are read from its `dnscrypt-proxy.toml` and never blocked. A resolver switch in the DNSCrypt WebUI is followed within a minute. Can be switched off in System

### WebUI

* Rebuilt: **Dashboard**, **Lists**, **Tools**, **System**, **Log**, in the original ipset-arm64 colours and logo
* A banner that says whether the phone is protected, and why not
* Packets blocked in and out since the rules were applied
* Every button shows it was pressed and ignores repeated taps while its command runs
* The page no longer waits for the web font: it opens at once without a network
* **Help**: a full guide to every screen, setting and command
* Advanced sets and rules are still there (Tools → Advanced), with an app search for per-app rules

### Advanced sets and rules (ipctl.sh)

* Rules run in the module's chains for IPv4 or IPv6, depending on the set's family
* A rule is saved only after it is confirmed in the kernel; one the kernel refuses is rolled back with the reason
* Entries with ports and interfaces (`1.2.3.4,tcp:443`, `10.0.0.0/8,wlan0`) were rejected by the input check since r9 — including the README's own examples. Fixed
* Two-dimensional matches (`dst,dst`) for sets such as `hash:ip,port`
* Saving never deletes a set from disk that failed to load at boot; restore retries set by set, so one broken set costs only itself
* `rule-del` from the WebUI; deleting a set offers to delete its rules too
* `RETURN` now means "no decision here — continue to the lists"
* Names starting with `ipsa_` are reserved for the module

### Other

* New `ctl.sh` with `key=value` output for everything the WebUI does; `ipctl.sh` stays compatible
* Sets are loaded in `post-fs-data`; rules are added once netd has finished starting
* Log lines written before the clock is set show `boot+Ns` instead of a 1970 date; the log is trimmed automatically
* The watchdog stops quietly when the phone shuts down
* `module.prop` no longer calls the binary statically linked (it is linked against libmnl statically, bionic dynamically)
* Magisk-compatible installer (`META-INF`)

### Upgrading from r9

* Reboot after flashing. Your advanced sets and rules are kept and move into the new chains
* Open **Lists** once and tap **Update lists** to download the current lists (the old feed's copy is used until then)
* Rules that r9 inserted directly into `OUTPUT`/`INPUT` are removed on the first start

---

## v7.24-r9

**Fixed**
- `save`, `restore` and `flush-all` operated on every ipset set on the
  device, not just this module's. That meant adopting other apps' sets
  into our state file — and destroying them on uninstall. Ownership is
  now tracked explicitly; existing sets are migrated on upgrade.
- `destroy` refuses sets this module did not create.
- `restore` now passes `-exist`. Without it, one pre-existing set
  aborted the restore and everything after that line was silently
  skipped.
- Entry validation rejected valid IPv6 and MAC addresses (IPv4-only
  regex). Replaced with an injection-safe character check; `ipset`
  itself validates syntax.

**Changed**
- All 15 set types supported, including the MAC-keyed ones. New
  `types` command lists them.
- `create <name> <type> inet6` for IPv6 sets.
- `add` / `del` accept multiple entries and save once (bulk loading
  was quadratic).
- `status` separates our sets from other apps'. New `owned` command.
- WebUI type dropdown and help table updated to match.

---

## v7.24-r8

**⚠ Threat feed auto-update (24h) temporarily removed**

The 24h background auto-update for the threat feed (`feed_firehol_level1`) was causing the same device/ROM compatibility issues as the DNSCrypt module (the background loop wasn't reliably surviving Doze/battery optimization on some devices, leading to a stuck "due now" countdown). To avoid misleading users, this feature has been pulled from this release.

- Removed the "Enable auto (24h)" toggle and countdown from the Threat Feeds card
- Feed updates are manual-only again via the **Update Now** button — same as before, stable and predictable
- No more background loop, flags, or schedule files tied to feed auto-update
- `service.sh` no longer runs a periodic watchdog for this — boot restore of sets/rules is unaffected

Everything else (set/rule management, boot restore, connectivity test, bootlog) is unchanged.

Auto-update will return in a future release once the scheduling logic is reworked and verified to be reliable across devices and ROMs.

---

## ipset-arm64 — v7.24-r7

### Fixed
- **Feed auto-update loop dying silently and never recovering** — the background loop spends nearly all its life in a single long `sleep` (up to 24h), making it an easy target for Android's Doze/battery-optimization/low-memory killer. When killed mid-session, the flag stayed "on" but nothing updated again, and the dashboard's countdown got stuck on "due now" indefinitely. `service.sh` is now a persistent watchdog that checks the loop's health every 5 minutes and respawns it if it's dead while the flag is on — self-heals within minutes regardless of whether the WebUI is ever opened. `feed-status` also self-heals instantly whenever it's called.
- **Dashboard never reflecting a completed background update** — the countdown row re-rendered every second, but only from a value fetched once on page load; a background auto-update (or the watchdog respawning a dead loop) stayed invisible until the WebUI was fully closed and reopened. `index.html` now polls the real feed status every 30s while the tab is visible, so the dashboard updates live.
- **Boot-restore log mixing history across boots/flashes** — `service.log` now starts clean on every boot (`service.sh`) and on every install/upgrade (`customize.sh`), instead of accumulating a rolling tail across many boots.

---

## ipset-arm64-v7.24-r6

### Fixed
- Feed auto-update could silently die (killed by Android's battery optimizer) and get stuck on "due now" forever until reboot. `service.sh` now watches it every 5 min and restarts it if it's down — self-heals whether or not the dashboard is open.

---

## ipset-arm64-v7.24-r5

### Added
- **Live countdown for Threat Feeds auto-update** — when auto-update is enabled, a new "Next update in: Xh Ym Zs" row appears below the toggle, ticking in real time. Persists correctly across page reloads, not just while the WebUI happens to be open.
- **Clear button for Boot Restore Log** — the log is already capped at 500 lines per boot cycle by `service.sh`, but you can now explicitly wipe it on demand (with a confirmation dialog, since this truncates a real on-disk file, unlike the purely session-based Command Log clear).
- `ipctl.sh` gained `bootlog-clear`; `feed-status` now also reports `next_update_epoch`, tracked by the auto-update loop before each sleep cycle.

### Fixed
- **Config set selector losing sync after visiting Help** — navigating to `help.html` and back could leave the set dropdown visually showing a previously-selected set while the firewall rule slots displayed as inactive (browsers/WebViews auto-restore a `<select>`'s visual value across navigation, independent of the page's own JS state, which always starts fresh). The selector is now explicitly reset in sync with the app's actual state on every load, so this mismatch can no longer happen.

---

## ipset-arm64-v7.24-r4

### Added
- **Per-app (per-UID) firewall filtering** — rules can now be scoped to a single Android app instead of applying to the whole device. Uses `iptables`'s `owner` match (`--uid-owner`), restricted to the `OUTPUT` chain, since Android has no way to attribute incoming traffic to a specific app before it's routed.
- **App search in Config** — type or paste part of a package name to find an installed app from a locally cached list (loaded once, on first tap of the search box), shown as a removable chip once selected.
- `ipctl.sh` gained the `apps` command (`pm list packages -U`, parsed into `package|uid` pairs) and `rule-add`/`rule-del` accept an optional trailing `uid` argument.
- **Custom modal system** replacing every native `alert()`/`confirm()` — dark-themed, matches the rest of the UI (cyan info dialogs, red delete confirmations). No more jarring system popups breaking the visual language.
- **Empty-set protection** — enabling a rule on a set with zero members is now blocked with an explanation instead of silently creating a rule that blocks nothing.
- **Custom-styled dropdowns** across the whole WebUI — removed native browser appearance, added a matching chevron icon (gray by default, green on focus) and refined hover states, for visual consistency with the rest of the design.
- Version badge (`v7.24-r4`) added to the WebUI header and Help page.
- Matching favicon added to both `index.html` and `help.html`.
- Thousands separators on entry counts (Sets tiles, Threat Feeds status) for readability at scale.
- `webroot/help.html` updated: full per-app filtering documentation, empty-set behavior, expanded command reference (`apps`, uid-aware `rule-add`/`rule-del` examples).

### Changed
- `rules.conf` format is backward-compatible: entries stay 4 fields (`chain|set|dir|target`) as before; a 5th `uid` field only appears when per-app filtering is actually used, so existing active rules from prior versions are unaffected by this update.
- `restore`, `flush-all`, and `uninstall.sh`'s fallback cleanup path all updated to correctly reapply/remove owner-matched (per-app) rules across reboots and on uninstall.

### Fixed
- Threat Feeds entry count now reflects the real, de-duplicated `ipset` member count (read from the live set after the atomic swap) instead of the raw source JSON line count, which could be a few entries higher when the feed contains overlapping/duplicate CIDRs.

---

## ipset-arm64-v7.24-r3

### Added
- **Config section (03) redesigned into 3 independent rule slots per set** — supports up to 3 simultaneous firewall rules on the same set (e.g. block both `INPUT` and `OUTPUT` at once, or apply different targets per direction). Each slot tracks its own identity across refreshes; enabling slot 2 stays in slot 2, never gets reshuffled to slot 1.
- **Config is now fully decoupled from Set Detail** — has its own independent set selector, separate from tapping a tile in Sets. Managing rules never requires scrolling past a set's member list, no matter how large (tested against a 1600+ entry feed set).
- **Set Detail (member editor) repositioned** directly under Sets, accordion-style — tap a tile to open, tap again to close, no page navigation needed.
- **Duplicate rule prevention** — attempting to enable a chain/direction/target combination already active in another slot is blocked with an on-screen warning instead of silently creating a redundant tracking entry.
- **Threat Feeds panel (06)** — new managed set `feed_spamhaus_drop`, sourced from [Spamhaus DROP v4](https://www.spamhaus.org/drop/drop_v4.json). "Update Now" for manual refresh (atomic swap, zero traffic gap), "Enable auto (24h)" toggle for background refresh every 24 hours (resumes automatically after reboot if left on, off by default). Feed-managed sets are tagged with an orange **FEED** badge in the Sets list.
- `ipctl.sh` gained three commands: `feed-update`, `feed-status`, `feed-auto {on|off|status}`.
- `service.sh` resumes the threat feed auto-update loop after reboot if it was previously enabled.
- `uninstall.sh` now also stops the threat feed auto-update loop and removes its state on module removal.
- **HELP badge** added to the WebUI header, linking directly to in-app documentation.
- `webroot/help.html` fully rewritten to match the new architecture: Config's 3-slot system, Threat Feeds, corrected section numbering throughout, expanded command reference.

### Changed
- **Clear** (Command Log) button restyled red to match other destructive actions; **Refresh** buttons restyled cyan for visual consistency with other read/info actions.
- Command reference docs now cover multi-rule usage (calling `rule-add` again with a different chain/direction to stack up to 3 rules on one set).

### Fixed
- **Config slot reassignment bug** — activating a specific rule slot (e.g. slot 2) could cause a *different* slot (e.g. slot 1) to display as active instead, because slot contents were recalculated positionally from the rules list on every refresh rather than tracking which slot the user actually interacted with. Slot identity is now tracked persistently and independently across refreshes.

---

## v7.24-r2

### Added
- **`ipctl.sh`** — dynamic control engine for the module. Nothing is static or default-enabled: sets, addresses, and firewall rules only exist once explicitly created. Commands: `status`, `list`, `create`, `destroy`, `add`, `del`, `test`, `rule-add`, `rule-del`, `rules`, `bootlog`, `save`, `restore`, `flush-all`.
- **WebUI control panel** (`webroot/index.html`) — create/destroy sets, manage members, toggle firewall rules, run a built-in connectivity (ping) test, and review logs, entirely from your root manager's WebUI. No Termux or adb required for day-to-day use.
- **In-app help** (`webroot/help.html`) — full documentation covering every panel, `hash:ip` vs `hash:net`, persistence/update behavior, uninstall behavior, and how to use this module alongside `dnscrypt-proxy-android-arm64-only`.
- **`service.sh`** — automatically restores all sets and firewall rules on every boot. Purely reactive: if nothing was ever created, it does nothing.
- **External persistent storage** (`/data/adb/ipset_arm64_data/`) — sets and rules now survive both reboots **and** module updates/reflashes, since this location lives outside the folder Magisk/KernelSU replace on update. Includes automatic one-time migration from the old in-module storage path for anyone upgrading from an earlier internal build.
- **`uninstall.sh`** — full cleanup on module removal: flushes every ipset set and iptables rule the module created (kernel-level, not just files) and deletes the external data directory. No orphaned rules left active after uninstall.
- **Boot Restore Log** — visibility into exactly what `service.sh` restored on the last boot, viewable directly in the WebUI.
- **Command Log** — rolling session history (last 30 actions) of everything run through the WebUI, with a live size indicator.
- **Connectivity Test panel** — built-in ping runner to verify a block took effect, without leaving the WebUI.
- **Status panel** — live kernel capability check (`CONFIG_IP_SET`, `CONFIG_IP_SET_HASH_IP`, `CONFIG_IP_SET_HASH_NET`, `CONFIG_NETFILTER_XT_SET`, `xt_set` match), plus a snapshot of every active set and rule, with color-coded terminal-style output (green = OK, red = missing/failed).
- **Cascading set deletion** — "Delete entire set" in the WebUI now automatically disables any active rule referencing it first, then destroys it, instead of blocking with an error.

### Changed
- `customize.sh` now sets executable permissions on `ipctl.sh`, `service.sh`, and `uninstall.sh` explicitly, independent of how permission bits survive zip packaging.

### Fixed
- Rule removal (`rule-del`) no longer silently fails to update `rules.conf` when it was the only active rule for a set — a POSIX `grep -v` exit-code trap (empty output = non-zero exit) could previously leave a stale "active" entry in the tracking file even after the underlying iptables rule was correctly removed.

---

## v7.24-r1 (Initial Release)

- First public build of `ipset` v7.24 for Android arm64
- Cross-compiled with Android NDK r26d, targeting aarch64-linux-android API 29
- Statically linked against libmnl
- Tested against GKI 5.15.194 (android13-5.15) kernel with `CONFIG_IP_SET=y`
- Confirmed working: set creation, add/list/destroy operations, protocol v7 handshake with kernel
