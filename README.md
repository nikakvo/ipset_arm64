<p align="center">
  <img src="https://img.shields.io/badge/ARM64-only-00d4ff?style=flat-square" />
  <img src="https://img.shields.io/badge/v7.24--r12-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/SukiSU%20%2F%20KernelSU%20%2F%20APatch%20%2F%20Magisk-compatible-4affb4?style=flat-square" />
  <img src="https://img.shields.io/badge/IPv4%20%2B%20IPv6-filtered-00d4ff?style=flat-square" />
</p>

# ipset-arm64

IP-level blocklists for Android. The module loads lists of known-bad networks — botnets, malware control servers, hijacked address space — into the kernel with **ipset**, and blocks traffic to and from them with **iptables** and **ip6tables**. Everything is controlled from a WebUI in your root manager.

DNS blocking stops a name from being looked up; it cannot stop an app that connects to a **hard-coded IP address**. This module can. It is part of a set with [DNSCrypt Proxy Arm64](https://github.com/nikakvo/dnscrypt-proxy-android-arm64-only) and [VPN Hotspot Arm64](https://github.com/nikakvo/vpn-hotspot-arm64) — see [The networking set](#the-networking-set).

<img width="300" alt="ipset-arm64 WebUI" src="https://raw.githubusercontent.com/nikakvo/ipset-arm64/main/ipset-arm64.jpg" />

## Features

* **Blocklists to choose from**: FireHOL Level 1–4, FireHOL Web client and Spamhaus DROPv6 — IPv4 and IPv6
* **A direction for each list**: block outgoing connections, incoming ones, or both
* **Nothing is downloaded until you ask**: pick your lists, tap Update; automatic updates (daily or weekly) only if you switch them on, with the next run and the last result on the Dashboard
* **Safe updates**: a new list replaces the old one in a single step, a failed download keeps the last good copy, special-purpose ranges (your LAN, carrier NAT, loopback…) are never blocked
* **Your own blocklist and allowlist**, also as plain text files on the sdcard
* **Check an address**: which list holds it and what the module does with it
* **Test connection**: a real connection from the phone, and whether this module stopped it
* **View and search** the contents of any list, and let a network through
* **Advanced**: your own ipset sets and firewall rules, per app if you like, as in earlier versions
* **Watchdog**: puts the rules back within seconds when Android's network daemon or another app removes them
* **DNSCrypt aware**: the resolvers the DNSCrypt module uses are never blocked
* **Help** built into the WebUI, explaining every screen and setting

## How it works

The module keeps its rules in its own chains, linked at the top of Android's `OUTPUT`, `INPUT` and `FORWARD` chains:

```
outgoing   loopback → your advanced rules → allowlist → DNSCrypt resolvers
           → LAN & special ranges → lists (Outgoing/Both) → refuse or drop

incoming   loopback → your advanced rules → replies to the phone's own
           connections → allowlist, DNSCrypt, LAN → lists (Incoming/Both) → drop
```

* Each list is its own ipset set. Lists join a per-direction aggregate (`list:set`), and the firewall rules only reference those aggregates — so adding, removing, updating a list or changing its direction never touches iptables.
* Rules are written with one `iptables-restore` per family: the kernel swaps them in at once, after checking them in test mode first. A rule the kernel refuses never replaces a working chain.
* Android's netd flushes the built-in chains when it starts and when it restarts. The watchdog checks every 10 seconds and repairs the links; the Dashboard counts the repairs.
* If anything fails, the network keeps working (fail-open) and the WebUI says what is wrong.

## Requirements

| | |
|---|---|
| CPU | arm64 only |
| Root | SukiSU Ultra, KernelSU or APatch — WebUI built in. Magisk works too; open the WebUI with MMRL or KSU WebUI Standalone |
| Kernel | `CONFIG_IP_SET` and `CONFIG_NETFILTER_XT_SET` (most GKI kernels have both) |
| IPv6 | `ip6tables` with the set match; without it, IPv4 is still protected and the WebUI says so |

System → Device in the WebUI shows whether your kernel has what is needed.

## Installation

1. Download the zip from [Releases](../../releases)
2. Flash it in your root manager and reboot
3. Open the module's WebUI → **Lists** → choose your lists (FireHOL Level 1 and Spamhaus DROPv6 are preselected) → **Update lists**
4. The Dashboard shows **Protected**

Updating from an earlier version keeps your settings, advanced sets and rules. The old threat feed (`feed_firehol_level1`) becomes the FireHOL Level 1 list, and its old rules are removed — protection continues right away, even without a network at boot.

## WebUI

| Tab | |
|---|---|
| **Dashboard** | Protected or not, and why; networks blocked, packets stopped in and out; protection switch, pause (15 min / 1 h / 4 h); next and last automatic update |
| **Lists** | The blocklists with their size, age and direction; View and search; Update with a live log; automatic update off / daily / weekly |
| **Tools** | Check an address, Test connection, your blocklist and allowlist, advanced sets and rules |
| **System** | Health of the IPv4 and IPv6 rules, watchdog, settings, kernel features |
| **Log** | Module log, last boot, last update |

## Blocklists

| List | Size | |
|---|---|---|
| FireHOL Level 1 | ~4,700 | Recommended. Botnets, malware control servers, hijacked networks — minimum false positives |
| FireHOL Level 2 | ~18,500 | Attacks seen in the last 48 hours |
| FireHOL Level 3 | ~12,000 | Attackers, spyware and malware of the last 30 days |
| FireHOL Level 4 | ~160,000 | Aggressive; expect false positives |
| FireHOL Web client | ~470 | Addresses browsers and apps should never talk to |
| Spamhaus DROPv6 | ~90 | Recommended. IPv6 networks hijacked or run by cyber-crime |

**Directions.** *Outgoing* stops connections from the phone to a listed address. *Incoming* drops connections a listed address starts towards the phone, while the phone's own connections to it still work. *Both* is the default. Example: Level 1 on Both and Level 4 on Incoming — attackers cannot reach the phone, and Level 4's false positives never break a site you open.

**Updates.** A failed download, or one with far fewer entries than expected, is discarded and the last good copy stays in use. Automatic updates refresh each list a day or a week after its last download, checked once a minute from two minutes after boot; failed attempts are retried an hour later. Spamhaus asks for at most one download an hour, and the module keeps to it.

## Your lists

`/sdcard/ipset-arm64/ip-blocklist.txt` and `ip-allowlist.txt` — one IPv4/IPv6 address or network per line, `#` for comments. Edit them in the WebUI or with any app; changes apply within 10 seconds. Your blocklist has its own direction. The allowlist always wins over every list.

## Files

| Path | |
|---|---|
| `/data/adb/ipset_arm64_data/settings.conf` | Settings — see Help → Files & settings for every key |
| `/data/adb/ipset_arm64_data/ip-blocklist.txt`, `ip-allowlist.txt` | Your lists (mirrored to `/sdcard/ipset-arm64/`) |
| `/data/adb/ipset_arm64_data/cache/` | Last good copy of each list |
| `/data/adb/ipset_arm64_data/owned.list`, `sets.save`, `rules.conf` | Your advanced sets and rules |
| `/data/adb/ipset_arm64_data/ipset.log`, `service.log` | Module log, last boot |

## Command line

Everything the WebUI does, from a root shell (`su -c` in Termux). Output is `key=value`.

```sh
sh /data/adb/modules/ipset_arm64/ctl.sh status
sh /data/adb/modules/ipset_arm64/ctl.sh sources                       # the lists
sh /data/adb/modules/ipset_arm64/ctl.sh sources enable firehol-level2
sh /data/adb/modules/ipset_arm64/ctl.sh sources dir firehol-level4 in # out | in | both
sh /data/adb/modules/ipset_arm64/ctl.sh update                        # download now
sh /data/adb/modules/ipset_arm64/ctl.sh check 103.117.84.5
sh /data/adb/modules/ipset_arm64/ctl.sh probe 103.117.84.5 443        # real connection test
sh /data/adb/modules/ipset_arm64/ctl.sh block add 203.0.113.0/24
sh /data/adb/modules/ipset_arm64/ctl.sh allow add 198.51.100.7
sh /data/adb/modules/ipset_arm64/ctl.sh pause 15
sh /data/adb/modules/ipset_arm64/ctl.sh set AUTO_UPDATE daily
```

Advanced sets and rules keep their own tool, compatible with earlier versions:

```sh
sh /data/adb/modules/ipset_arm64/ipctl.sh create myset hash:net
sh /data/adb/modules/ipset_arm64/ipctl.sh add myset 203.0.113.0/24
sh /data/adb/modules/ipset_arm64/ipctl.sh rule-add myset OUTPUT dst REJECT
sh /data/adb/modules/ipset_arm64/ipctl.sh rule-add myset OUTPUT dst DROP 10123   # one app (uid)
sh /data/adb/modules/ipset_arm64/ipctl.sh types                                 # all set types
```

All 16 set types are supported (`hash:net`, `hash:ip,port`, `hash:net,iface`, `bitmap:port`, `list:set`…); which ones work depends on the kernel. Sets named `ipsa_*` belong to the module. Sets created by other apps are never touched.

## With DNSCrypt, a VPN, or another firewall

* **[DNSCrypt](https://github.com/nikakvo/dnscrypt-proxy-android-arm64-only) module**: its bootstrap resolvers, connectivity probe and pinned servers are read from its `dnscrypt-proxy.toml` and never blocked, so a list can never take DNS away from the phone. Switching resolvers in the DNSCrypt WebUI is followed within a minute.
* **VPN**: apps' traffic passes the rules with its real destination before it enters the tunnel, so blocking keeps working with a VPN on. Hotspot devices sent through the VPN by [VPN Hotspot Arm64](https://github.com/nikakvo/vpn-hotspot-arm64) are filtered before they enter the tunnel too. The same holds for [WG Shield Arm64](https://github.com/nikakvo/wg-shield-arm64) (kernel WireGuard without an app) — just make sure a tunnel server is never in your lists (**Check** its address), or the tunnel cannot connect.
* **AFWall+ and others**: the module only adds its own chains and three links; other firewalls' rules are not changed.

## The networking set

Four modules built to work together — each one works on its own, and each adds a layer for the phone **and everyone on its hotspot**:

| | Module | What it adds |
|---|---|---|
| 🟢 | [DNSCrypt Proxy Arm64](https://github.com/nikakvo/dnscrypt-proxy-android-arm64-only) | Encrypted DNS with ad / tracker blocklists — for the phone and for hotspot devices, even those with their own DNS server set |
| 🔵 | **ipset-arm64** *(this module)* | IP blocklists (FireHOL, Spamhaus) in the kernel — stops apps and devices that connect to hard-coded IP addresses, which DNS blocking cannot see |
| 🟡 | [VPN Hotspot Arm64](https://github.com/nikakvo/vpn-hotspot-arm64) | Sends hotspot, USB and Bluetooth devices through the phone's VPN, with kill switch — Android's VPN only covers the phone's own apps |
| 🩵 | [WG Shield Arm64](https://github.com/nikakvo/wg-shield-arm64) | Always-on kernel WireGuard for the phone, with kill switch — no app |

```
device on your hotspot  /  app on the phone
   │  DNS      → DNSCrypt Proxy   encrypted, filtered
   │  traffic  → ipset            listed networks dropped
   │  hotspot  → VPN Hotspot      into the tunnel (kill switch)
   ▼  tunnel   → WG Shield        kernel WireGuard, always on — or any VPN app
internet
```

- **Order is fixed and checked** by each module: DNSCrypt's hotspot filter → ipset → VPN Hotspot → Android. Nothing reaches the VPN around the two filters
- **With the whole set**, hotspot devices get your filtered DNS (DNSCrypt's own queries travel inside the tunnel), your IP blocklists and your VPN exit — on Wi-Fi and on mobile data
- **VPN apps stay happy** — none of the modules holds Android's firewall lock while checking, so WireGuard (`wg-quick`) and other VPN apps connect and disconnect without errors
- **On its own** it blocks the listed networks for the phone and hotspot devices; DNS and routing stay as they are.

**Tested together** on a Poco F6 Pro (vermeer), Xiaomi.eu ROM (HyperOS 3, Android 16), kernel [GKI_Kernel_SukiSU](https://github.com/nikakvo/GKI_Kernel_SukiSU) (SukiSU Ultra), with WG Shield, WireGuard (kernel backend) and v2rayNG; hotspot devices: a Windows laptop and a stock Android phone. Other devices should work but are not tested — reports welcome.

## Uninstall

Remove the module in your root manager. Its chains, links and sets, your advanced sets and rules, and `/data/adb/ipset_arm64_data/` are removed; sets and rules of other apps are left alone. The copies of your lists in `/sdcard/ipset-arm64/` stay.

## Build details

* `ipset` 7.24, cross-compiled with Android NDK r26d (aarch64-linux-android, API 29)
* Statically linked against `libmnl`; dynamically against Android's bionic libc/libdl (standard for NDK binaries)
* Built from upstream sources: [ipset](https://git.netfilter.org/ipset) and [libmnl](https://git.netfilter.org/libmnl)
* Speaks ipset protocol version 7, which all current GKI kernels use
* Scripts are POSIX sh: run-tested with mksh and busybox sh (syntax-checked with dash too), and with busybox awk and one-true-awk

## Credits

* [FireHOL IP lists](https://github.com/firehol/blocklist-ipsets) — each list combines public sources with their own terms, see [iplists.firehol.org](https://iplists.firehol.org)
* [Spamhaus DROP](https://www.spamhaus.org) — data © The Spamhaus Project, free to use with attribution
* [ipset](https://ipset.netfilter.org) — the netfilter project, GPL-2.0

## Disclaimer

Provided as-is, for personal use. Not affiliated with the netfilter project, FireHOL or Spamhaus. Blocklists can contain false positives; if something stops working, **Tools → Check an address** tells you whether a list is the cause.

## License

The module's scripts and WebUI are [MIT](LICENSE). The bundled binary and the blocklists keep their own licenses — see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
