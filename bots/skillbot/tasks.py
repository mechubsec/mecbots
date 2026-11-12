"""skillbot task table: one self-contained task per SRX skill whose output can `commit check` on the
standalone lab vSRX. Skills that need two nodes or hardware (mnha, chassis cluster,
cluster-to-mnha, license maintenance, mnha builders) have no task and are listed as not covered."""

FACTS = """Target: a standalone vSRX, Junos 24.4R1. Existing configuration you can rely on but must not redefine:
- ge-0/0/0 unit 0 has 192.0.2.10/24 and is in security zone untrust; default route via 192.0.2.1
- ge-0/0/1 unit 0 has 198.51.100.1/25 and is in security zone trust (the LAN is 198.51.100.0/25)
- ge-0/0/2 and ge-0/0/4 are free interfaces with no configuration
- st0 units 1 and 2 are taken; use st0.10 or higher for new tunnels
- a global policy named lab-policy-1 (permit any) exists
Use the global policy form, never zone-pair policies. Use only names, addresses and values given in the task."""

TASKS = {
    "srx-nat": "Configure source NAT for trust to untrust: rule-set sbot-snat, pool sbot-pool "
               "192.0.2.200/32 to 192.0.2.203/32 with proxy ARP on ge-0/0/0.0 for it, rule matching source 198.51.100.0/25 into the pool. "
               "Also destination NAT: rule-set sbot-dnat from zone untrust, pool sbot-web 198.51.100.50/32 port 443, "
               "rule matching destination 192.0.2.10/32 port 8443 into that pool. "
               "Add global address sbot-web 198.51.100.50/32 and a global policy sbot-web-in permitting junos-https from untrust to trust to it.",
    "srx-policy": "Create global address-book entries sbot-app1 198.51.100.21/32 and sbot-app2 198.51.100.22/32, an address-set sbot-apps with both, "
                  "and a custom application sbot-tcp-8080 for tcp 8080-8090. Add global policies, in order: sbot-apps-out permit "
                  "from trust to untrust, source sbot-apps, application sbot-tcp-8080 and junos-https, log session-init and session-close; "
                  "sbot-deny-log from any to any, everything, deny with log session-init.",
    "srx-ipsec-hub-spoke": "Configure the hub of a static route-based hub-and-spoke IPsec VPN for two spokes: spoke1 at 203.0.113.11 "
                           "(LAN 203.0.113.64/26, tunnel st0.11) and spoke2 at 203.0.113.12 (LAN 203.0.113.128/26, tunnel st0.12). "
                           "The hub's external interface is ge-0/0/0.0 (192.0.2.10). IKEv2, aes-256-cbc, sha-256, group14, pre-shared key "
                           "ascii-text Example-Psk-1 for both, one IKE gateway, IPsec VPN and st0 unit per spoke, new zone sbot-vpn holding both st0 units, "
                           "static routes to the spoke LANs via their st0 unit, and global policies permitting trust and sbot-vpn traffic in both directions.",
    "srx-syslog-logging": "Send security logs and system syslog to a new collector 192.0.2.151 UDP port 5140. Use stream name sbot "
                          "for the security log (severity info, format sd-syslog, category all, source interface ge-0/0/0.0). "
                          "Also add system syslog host 192.0.2.151 port 5140 any info. Do not change the existing 192.0.2.150 configuration.",
    "srx-dynamic-ip-feed": "Configure a dynamic address feed: feed server sbot-feed at https://feeds.example.net with an update interval of 60 minutes, "
                           "feed name sbot-blocklist at path /lists/blocklist.txt, a dynamic address entry named sbot-block using it, "
                           "and a global policy sbot-block-out denying trust to untrust traffic to sbot-block with log session-init.",
    "srx-advpn": "Configure the ADVPN hub: tunnel st0.20 (multipoint, 203.0.113.193/28), IKEv2 gateway sbot-adv-gw for dynamic spokes identified by "
                 "user-at-hostname group IKE ID (suffix sbot.example.net, max 10 connections) on ge-0/0/0.0, aes-256-cbc, sha-256, group14, "
                 "pre-shared key ascii-text Example-Psk-2, ADVPN partner suggestions enabled, IPsec VPN sbot-adv-vpn bound to st0.20 with "
                 "traffic selectors not required, zone sbot-adv holding st0.20, and global policies permitting sbot-adv to and from trust.",
    "srx-autovpn-full-tunnel": "Configure the AutoVPN hub for full-tunnel spokes: tunnel st0.30 (multipoint, 203.0.113.209/28), IKEv2 gateway sbot-auto-gw with "
                               "dynamic hostname group IKE ID (suffix sbot.example.net, max 20 connections) on ge-0/0/0.0, aes-256-cbc, sha-256, group14, "
                               "pre-shared key ascii-text Example-Psk-3, IPsec VPN sbot-auto-vpn bound to st0.30, zone sbot-auto holding st0.30, "
                               "source NAT from sbot-auto to untrust using the egress interface for 203.0.113.208/28, and a global policy sbot-auto-out permitting sbot-auto to untrust.",
    "srx-mpls-in-flow": "Configure this vSRX as a secure PE: MPLS in flow mode, core link ge-0/0/2.0 198.51.100.193/30 with family mpls, LDP on it, "
                        "loopback lo0.0 203.0.113.1/32 as router-id, OSPF area 0 on the core link and loopback (passive on loopback), iBGP to 203.0.113.2 "
                        "(AS 65000, local-address 203.0.113.1) with family inet-vpn unicast, and VRF CUST-A (instance-type vrf) on ge-0/0/4.0 198.51.100.201/29 with "
                        "route-distinguisher 65000:100 and vrf-target target:65000:100. Put ge-0/0/2.0 in zone sbot-core (allow ospf, ldp, bgp inbound) "
                        "and map ge-0/0/4.0 into zone sbot-cust-a.",
    "srx-ips": "Create an IDP policy sbot-idp with two rules in rulebase ips: rule 1 matches from-zone untrust to-zone trust, any source and destination, "
               "application default, attacks predefined-attack-groups \"Critical - TCP\", action drop-connection, severity critical, notification log-attacks; "
               "rule 2 matches the same zones, attacks predefined-attack-groups \"Major - TCP\", action no-action, notification log-attacks. "
               "Make it the active policy and add global policy sbot-idp-in permitting untrust to trust to any destination with application-services idp-policy sbot-idp.",
    "srx-initial-setup": "Day-1 bring-up of a new DMZ segment: ge-0/0/2 unit 0 198.51.100.129/26 in new zone sbot-dmz allowing ping and ssh inbound on that interface, "
                         "a screen sbot-screen with icmp ping-death, ip source-route-option, tcp syn-flood (alarm-threshold 1024, attack-threshold 200, "
                         "source-threshold 4000, timeout 20) and tcp land applied to sbot-dmz, NTP server 203.0.113.50, name servers 203.0.113.53 and 203.0.113.54, "
                         "and global policies sbot-dmz-out permitting sbot-dmz to untrust and sbot-dmz-deny denying sbot-dmz to trust with log session-init.",
}
