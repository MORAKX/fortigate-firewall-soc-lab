# FortiGate Firewall Lab: Network Segmentation, Web Filtering & UTM Log Analysis

**Author:** Yehia Zakaria · Cybersecurity Student / Aspiring SOC Analyst
**Lab Type:** Hands-on Home Lab (SOC Training Series)
**Tools:** VMware Hypervisor, FortiGate VM (FortiOS), Ubuntu, Kali Linux, Windows 10

---

## 1. Introduction & Project Goals

As part of my SOC analyst training, I built a segmented network lab around a **FortiGate Firewall VM** to get hands-on experience with the technology that sits at the center of most enterprise security stacks: next-generation firewalls (NGFW).

Rather than just reading about firewall theory, I wanted to actually build a small "company network" — with a Sales department, a Marketing department, and a Server zone — and enforce real security policy between them, the way a junior network/security admin or SOC analyst might encounter in production.

**My goals for this lab were to:**

- Practice standing up a FortiGate VM in VMware and wiring up multiple internal network segments (VLAN-style zone separation).
- Configure interface IPs, static routing, and NAT so that internal zones could reach the internet through a single WAN uplink.
- Write and apply **firewall security policies** that reflect real business logic (e.g., "Sales should not access social media/gambling sites," "Marketing/dev machines should not reach AI services").
- Build and apply **custom Web Filter profiles** using FortiGuard categories and manual URL filter lists.
- Generate real blocked-traffic events and practice **reading and interpreting FortiGate UTM logs** — the same skill a SOC analyst uses daily when triaging alerts.
- Get comfortable with core **FortiOS CLI** syntax, since many real-world environments are managed via CLI/SSH, not just the GUI.

This project ties together networking fundamentals, firewall policy design, and log analysis — three skills that show up constantly in SOC analyst job descriptions.

---

## 2. Architecture & Network Topology

The lab simulates a small business with three internal segments, each behind its own FortiGate interface, plus a WAN uplink for internet access.

```
                                   ┌────────────────────────┐
                                   │        Internet        |
                                   └────────────┬───────────┘
                                                │
                                        (DHCP)  │
                                        ┌───────┴────────┐
                                        │   Port 1 (WAN) |
                                        └───────┬────────┘
                                                │
                              ┌─────────────────┼──────────────────┐
                              │                 │                  │
                     ┌────────┴───────┐ ┌───────┴─────────┐ ┌──────┴────────┐
                     │    Port 2      │ │    Port 3       | │    Port 4     │
                     │  Sales Zone    | │ Marketing Zone  | │   Server Zone │
                     │ 10.0.1.1/24    │ │ 10.0.2.1/24     │ │ 10.0.3.1/24   │
                     └────────┬───────┘ └───────┬─────────┘ └─────┬─────────┘
                              │                 │                 │
                     ┌────────┴───────┐ ┌───────┴────────┐ ┌──────┴──────────┐
                     │ Ubuntu VM      │ │ Kali Linux VM  | │  Windows 10 VM  │
                     │ 10.0.1.10/24   │ │ 10.0.2.10/24   | │  10.0.3.10/24   │
                     │ GW: 10.0.1.1   │ │ GW: 10.0.2.1   | │  GW: 10.0.3.1   │
                     └────────────────┘ └────────────────┘ └─────────────────┘

     FortiGate Policies:
     • Sales2Internet         → Port2 → Port1 (NAT) + Sales_WebFilter
     • AIblocker4Marketing    → Port3 → Port1 (NAT) + Block_AI_Services
```

### IP Addressing Table

| Zone / Device        | FortiGate Interface | Interface IP  | Host VM         | Host IP        | Gateway    |
|-----------------------|---------------------|----------------|------------------|-----------------|-------------|
| WAN / Internet        | Port 1              | DHCP (ISP)     | —                | —               | —           |
| Sales Department      | Port 2              | 10.0.1.1/24    | Ubuntu VM        | 10.0.1.10/24    | 10.0.1.1    |
| Marketing Department  | Port 3              | 10.0.2.1/24    | Kali Linux VM    | 10.0.2.10/24    | 10.0.2.1    |
| Server Zone           | Port 4              | 10.0.3.1/24    | Windows 10 VM    | 10.0.3.10/24    | 10.0.3.1    |

Each internal interface was configured to allow **PING, HTTPS, and SSH** for management/testing purposes, which made troubleshooting connectivity and policy hits much easier during testing.

---

## 3. Network Setup & FortiGate CLI Configurations

All configuration below was done through the FortiOS CLI (accessible via the GUI's CLI console or SSH into the FortiGate management IP).

### 3.1 Interface Configuration

```bash
config system interface
    edit "port2"
        set alias "Sales"
        set ip 10.0.1.1 255.255.255.0
        set allowaccess ping https ssh
        set role lan
    next
    edit "port3"
        set alias "Marketing"
        set ip 10.0.2.1 255.255.255.0
        set allowaccess ping https ssh
        set role lan
    next
    edit "port4"
        set alias "ServerZone"
        set ip 10.0.3.1 255.255.255.0
        set allowaccess ping https ssh
        set role lan
    next
end
```

> `port1` (WAN) was left on DHCP mode via `set mode dhcp` under its interface config, since it pulls its address from the upstream network/hypervisor NAT.

### 3.2 Static Routing

A single default route sends all outbound traffic from the internal zones toward the WAN interface:

```bash
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set device "port1"
        set gateway <WAN_GATEWAY_IP>
    next
end
```

### 3.3 Web Filter Configuration

**Sales_WebFilter** — blocks restricted categories (social media, gambling) using FortiGuard category filtering:

```bash
config webfilter profile
    edit "Sales_WebFilter"
        set comment "Restrict Sales dept from social media & gambling"
        config ftgd-wf
            config filters
                edit 1
                    set category 61   ! Social Networking
                    set action block
                next
                edit 2
                    set category 26   ! Gambling
                    set action block
                next
            end
        end
    next
end
```

**Block_AI_Services** — uses a manual URL filter list to block AI platforms outright, since many AI tools don't fall neatly into a single FortiGuard category:

```bash
config webfilter urlfilter
    edit 1
        set name "AI_Services_List"
        config entries
            edit 1
                set url "openai.com"
                set action block
                set type wildcard
            next
            edit 2
                set url "chatgpt.com"
                set action block
                set type wildcard
            next
            edit 3
                set url "claude.ai"
                set action block
                set type wildcard
            next
            edit 4
                set url "midjourney.com"
                set action block
                set type wildcard
            next
        end
    next
end

config webfilter profile
    edit "Block_AI_Services"
        set comment "Block access to AI service domains for Marketing dept"
        set urlfilter-table 1
    next
end
```

### 3.4 Firewall Security Policies

**Policy 1 — Sales2Internet:**

```bash
config firewall policy
    edit 1
        set name "Sales2Internet"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set utm-status enable
        set webfilter-profile "Sales_WebFilter"
        set nat enable
    next
end
```

**Policy 2 — AIblocker4Marketing:**

```bash
config firewall policy
    edit 2
        set name "AIblocker4Marketing"
        set srcintf "port3"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set utm-status enable
        set webfilter-profile "Block_AI_Services"
        set nat enable
    next
end
```

Both policies allow general internet access (NAT-enabled ACCEPT), but layer a UTM Web Filter profile on top — this is the core NGFW concept: **allow the connection, then inspect and selectively block based on content/category**, rather than blocking at the network layer entirely.

---

## 4. Testing & Traffic Log Analysis

### 4.1 Verification Procedure

1. From the **Ubuntu VM (Sales)**, browsed to a known social media site and a gambling site to confirm the `Sales_WebFilter` profile triggered a block page.
2. From the **Kali Linux VM (Marketing)**, attempted to reach `claude.ai`, `chatgpt.com`, and `openai.com` to confirm the `Block_AI_Services` URL filter triggered.
3. Confirmed **legitimate traffic still passed** (e.g., general browsing, DNS resolution, ping to 8.8.8.8) to validate the policies weren't overly restrictive.
4. Cross-referenced each test against **FortiView > Web Filter** and the raw log viewer on the FortiGate to confirm log generation matched real-time behavior.

### 4.2 Sample UTM Web Filter Log Output

Below is a representative FortiGate syslog entry generated when the Marketing VM attempted to reach an AI domain:

```
date=2026-09-18 time=14:32:07 devname="FortiGate-VM" devid="FGVM-LAB01" logid="0316013056"
type="utm" subtype="webfilter" eventtype="ftgd_blk" level="warning" vd="root"
policyid=2 sessionid=184223 srcip=10.0.2.10 srcport=51422 srcintf="port3"
dstip=104.18.32.7 dstport=443 dstintf="port1" proto=6
service="HTTPS" hostname="claude.ai" url="/"
action="blocked" reqtype="direct" msg="URL belongs to a blocked category or list"
method="domain" cat=0 catdesc="Blocked-URL-List" crscore=30 crlevel="high"
```

And a Sales VM attempt to reach a blocked social media category:

```
date=2026-09-18 time=14:41:52 devname="FortiGate-VM" devid="FGVM-LAB01" logid="0316013056"
type="utm" subtype="webfilter" eventtype="ftgd_blk" level="warning" vd="root"
policyid=1 sessionid=184391 srcip=10.0.1.10 srcport=52810 srcintf="port2"
dstip=157.240.22.35 dstport=443 dstintf="port1" proto=6
service="HTTPS" hostname="facebook.com" url="/"
action="blocked" reqtype="direct" msg="URL belongs to a blocked FortiGuard category"
method="rating" cat=61 catdesc="Social Networking" crscore=30 crlevel="high"
```

**Fields I paid close attention to (SOC-relevant):**

| Field         | Why It Matters for Triage                                   |
|----------------|--------------------------------------------------------------|
| `srcip` / `dstip` | Identifies which internal host initiated the request and the destination it tried to reach — first thing I'd pivot on. |
| `policyid`     | Tells me exactly which firewall policy handled the traffic, useful for auditing rule effectiveness. |
| `hostname`/`url` | Shows the actual domain requested — critical for distinguishing benign vs. suspicious destinations. |
| `eventtype="ftgd_blk"` | Confirms this was a FortiGuard category/URL block, not an IPS or AV event — helps route the alert to the right playbook. |
| `catdesc`      | Human-readable category context (e.g., "Social Networking" vs. "Blocked-URL-List") — speeds up analyst triage. |
| `crscore`/`crlevel` | Risk scoring FortiGate assigns to the destination — useful for prioritizing follow-up. |

### 4.3 CLI Debug & Packet Tracing

To go beyond the GUI and validate policy behavior at the packet level, I used FortiOS's built-in flow debug tools:

```bash
diagnose debug flow filter saddr 10.0.2.10
diagnose debug flow filter daddr 104.18.32.7
diagnose debug flow show function-name enable
diagnose debug flow trace start 20
diagnose debug enable
```

This let me watch, in real time, how a packet from the Kali VM was matched against `AIblocker4Marketing`, hit the webfilter profile, and got dropped — instead of just trusting the block page.

To inspect active sessions and confirm NAT translation was working correctly:

```bash
diagnose sys session list
diagnose sys session filter src 10.0.1.10
diagnose sys session filter dport 443
```

This showed live session entries with source/NAT'd IP, destination, port, and policy ID — extremely useful for confirming that traffic was actually being NAT'd out through Port 1 as expected.

---

## 5. Key Takeaways & Reflection

This lab reinforced several concepts that I now understand at a much more practical level than I did from reading alone:

**Network segmentation is a real control, not just a diagram.** Putting Sales, Marketing, and the Server zone on separate interfaces/subnets meant I could apply *different* security postures to each group based on their actual risk profile and business need — not a one-size-fits-all rule.

**UTM profiles turn "allow" into "allow, but inspect."** The biggest mental shift for me was realizing that a `set action accept` policy isn't the end of the story — the web filter profile sitting on top of it is doing continuous content inspection on every session. That's the essence of NGFW behavior versus a traditional stateless firewall.

**Category-based filtering vs. explicit URL lists solve different problems.** FortiGuard category blocking (like Social Networking or Gambling) is fast to deploy and covers broad classes of sites, but for a fast-moving space like AI tools — where new domains pop up constantly and may not be categorized yet — a maintained manual URL filter list gave me more precise, guaranteed control.

**Reading raw logs is a skill you have to practice.** Seeing the block page in a browser is one thing; parsing the actual `eventtype`, `policyid`, `catdesc`, and `crscore` fields in the syslog output is what a SOC analyst is really doing all day. This lab gave me low-stakes reps at reading FortiGate log syntax before I'll need to do it under pressure during an actual incident.

**CLI fluency matters.** The GUI is great for quick changes, but being able to write `config firewall policy` and `diagnose debug flow` commands directly means I'm not dependent on a specific interface — a skill that transfers to any FortiGate deployment I might touch in a SOC or NOC role.

**Next steps I want to explore:** adding IPS profiles and antivirus scanning to these same policies, setting up FortiAnalyzer (or a SIEM like Splunk/Wazuh) to centralize and alert on these logs automatically, and simulating a lateral movement scenario from the Kali VM to practice detecting it across zones.

---

*This lab was completed independently as part of ongoing SOC analyst training. All IP ranges are private/lab-only (RFC 1918) and no production systems were involved.*
