from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import EventMixin
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
import os
import csv
import argparse

from pox.lib.packet import ethernet, ETHER_BROADCAST
from pox.lib.packet import arp
from pox.lib.packet import ipv4
from pox.lib.packet import icmp
from pox.lib.packet import tcp

log = core.getLogger()
priority = 50000

class Firewall(EventMixin):
    def __init__(self, l2config="l2firewall.config", l3config="l3firewall.config"):
        core.listenTo(core.openflow)
        core.openflow.addListenerByName("PacketIn", self._handle_PacketIn)
        core.openflow.addListenerByName("ConnectionUp", self._handle_ConnectionUp)

        self.mac_ip_map = {}
        self.blocked_macs = set()

        self.disbaled_MAC_pair = []
        self.fwconfig = []

        self.l2config_file = l2config
        self.l3config_file = l3config

        if not self.l2config_file:
            self.l2config_file = "l2firewall.config"
        try:
            with open(self.l2config_file, 'r') as rules:
                csvreader = csv.DictReader(rules)
                for line in csvreader:
                    mac_0 = EthAddr(line['mac_0']) if line['mac_0'] != 'any' else None
                    mac_1 = EthAddr(line['mac_1']) if line['mac_1'] != 'any' else None
                    self.disbaled_MAC_pair.append((mac_0, mac_1))
            log.info(f"Loaded L2 firewall rules from {self.l2config_file}")
        except Exception as e:
            log.error(f"Error loading L2 firewall config {self.l2config_file}: {e}")
            self.disbaled_MAC_pair = []

        self.rules = []
        if not self.l3config_file:
            self.l3config_file = "l3firewall.config"
        try:
            with open(self.l3config_file, 'r') as csvfile:
                log.debug("Reading log file !")
                csvreader = csv.DictReader(csvfile)
                for row in csvreader:
                    log.debug("Saving individual rule parameters in rule dict !")
                    prio = int(row['priority'])
                    srcmac = EthAddr(row['src_mac']) if row['src_mac'] != 'any' else None
                    dstmac = EthAddr(row['dst_mac']) if row['dst_mac'] != 'any' else None
                    s_ip = IPAddr(row['src_ip']) if row['src_ip'] != 'any' else None
                    d_ip = IPAddr(row['dst_ip']) if row['dst_ip'] != 'any' else None
                    s_port = int(row['src_port']) if row['src_port'] != 'any' else None
                    d_port = int(row['dst_port']) if row['dst_port'] != 'any' else None
                    nw_proto_str = row['nw_proto']

                    nw_proto = 0
                    if nw_proto_str.lower() == "tcp":
                        nw_proto = ipv4.TCP_PROTOCOL
                    elif nw_proto_str.lower() == "icmp":
                        nw_proto = ipv4.ICMP_PROTOCOL
                    elif nw_proto_str.lower() == "udp":
                        nw_proto = ipv4.UDP_PROTOCOL
                    else:
                        log.warning(f"Unknown network protocol '{nw_proto_str}' in {self.l3config_file}. Rule ignored.")
                        continue

                    self.rules.append({
                        'priority': prio,
                        'src_mac': srcmac, 'dst_mac': dstmac,
                        'src_ip': s_ip, 'dst_ip': d_ip,
                        'src_port': s_port, 'dst_port': d_port,
                        'nw_proto': nw_proto
                    })
            log.info(f"Loaded L3 firewall rules from {self.l3config_file}")
        except Exception as e:
            log.error(f"Error loading L3 firewall config {self.l3config_file}: {e}")
            self.rules = []

        log.debug("Enabling Firewall Module")
        log.info("Firewall (with Port Security) module initialized.")
        log.debug(f"Initial mac_ip_map: {self.mac_ip_map}")

    def _handle_ConnectionUp(self, event):
        log.info(f"Switch {dpidToStr(event.dpid)} connected. Installing L2 firewall rules.")
        self.connection = event.connection
        for source, destination in self.disbaled_MAC_pair:
            print(source, destination)
            message = of.ofp_flow_mod()
            match = of.ofp_match()
            match.dl_src = source
            match.dl_dst = destination
            message.priority = 65535
            message.match = match
            event.connection.send(message)

        log.debug(f"Firewall rules: %s", dpidToStr(event.dpid))


    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring unparsed packet (no higher-layer protocol).")
            return

        match = of.ofp_match.from_packet(packet)
        connection = event.connection
        dl_src = packet.src

        log.info(f"\nPacketIn: DPID={dpidToStr(event.dpid)}, Port={event.port}, Src MAC={dl_src}, Dst MAC={packet.dst}")

        if dl_src in self.blocked_macs:
            log.info(f"Drop packet from blocked Mac: {dl_src}")
            msg = of.ofp_flow_mod()
            msg.match.dl_src = dl_src
            msg.priority = 65535
            msg.hard_timeout = 0
            msg.idle_timeout = 0
            connection.send(msg)
            return

        if match.dl_type == packet.ARP_TYPE and match.nw_proto == arp.REQUEST:
            self.replyToARP(packet, match, event)
            return

        if match.dl_type == packet.IP_TYPE:
            ip_packet = packet.find('ipv4')
            if ip_packet:
                print(f"IP packet.protocol = {ip_packet.protocol}")
                if ip_packet.protocol == ipv4.TCP_PROTOCOL:
                    log.debug("TCP it is !")

                src_ip = ip_packet.srcip
                log.debug(f"nw_src = {src_ip}")

                if dl_src in self.mac_ip_map:
                    if self.mac_ip_map[dl_src] != src_ip:
                        log.warning(f"spoof detected MAC {dl_src} (OG IP {self.mac_ip_map[dl_src]}) uses IP {src_ip}")
                        self.blocked_macs.add(dl_src)
                        msg = of.ofp_flow_mod()
                        msg.match.dl_src = dl_src
                        msg.priority = 65535
                        msg.hard_timeout = 0
                        msg.idle_timeout = 0
                        connection.send(msg)
                        return
                else:
                    self.mac_ip_map[dl_src] = src_ip
                    log.info(f"Port sec: legitimate mapping: MAC {dl_src} -> IP {src_ip}")

            else:
                log.warning(f"  Ethernet type IP_TYPE, but no IPv4 packet parsed. Skipping Port Security check.")
        else:
            log.info(f"  Non-IP/ARP packet (type={packet.type}). Falling through to general firewall/forwarding.")

        self.replyToIP(packet, match, event, self.rules)


    def replyToARP(self, packet, match, event):
        r = arp.arp()
        r.opcode = arp.REPLY
        arp_pkt = packet.find('arp')
        if arp_pkt:
            r.hwsrc = arp_pkt.protodst_hw
            r.protodst = arp_pkt.protosrc
            r.protosrc = arp_pkt.protodst
            r.hwdst = arp_pkt.hwsrc

            e = ethernet(type=packet.ARP_TYPE, src=r.hwsrc, dst=r.hwdst)
            e.set_payload(r)

            msg = of.ofp_packet_out()
            msg.data = e.pack()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
            msg.in_port = event.port
            event.connection.send(msg)
            log.debug(f"Replied to ARP for {r.protodst} with MAC {r.hwsrc}")
        else:
            log.warning("Could not parse ARP packet for reply.")


    def allowOther(self, event):
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(event.parsed, event.port)
        msg.idle_timeout = 60
        msg.hard_timeout = 0
        msg.actions.append(of.ofp_action_output(port = of.OFPP_NORMAL))
        msg.data = event.ofp
        event.connection.send(msg)
        log.debug(f"Installed allowOther (OFPP_NORMAL) flow for {dpidToStr(event.dpid)}")


    def installFlow(self, event, priol, srcmac1, dstmac1, s_ip1, d_ip1, s_port1, d_port1, nw_proto1):
        msg = of.ofp_flow_mod()
        match = of.ofp_match()

        if srcmac1 is not None:
            match.dl_src = srcmac1
        if dstmac1 is not None:
            match.dl_dst = dstmac1

        is_ip_match = (s_ip1 is not None or d_ip1 is not None or
                       s_port1 is not None or d_port1 is not None or nw_proto1 is not None)
        if is_ip_match:
            match.dl_type = ethernet.IP_TYPE

        if s_ip1 is not None:
            match.nw_src = s_ip1
        if d_ip1 is not None:
            match.nw_dst = d_ip1

        if nw_proto1 is not None:
            match.nw_proto = nw_proto1

        if s_port1 is not None:
            if nw_proto1 == ipv4.TCP_PROTOCOL:
                match.tp_src = s_port1
        if d_port1 is not None:
            if nw_proto1 == ipv4.TCP_PROTOCOL:
                match.tp_dst = d_port1

        msg.match = match
        msg.hard_timeout = 0
        msg.idle_timeout = 200
        msg.priority = priol + priority

        event.connection.send(msg)
        log.debug(f"Installed L3 flow rule (potentially drop): priority={msg.priority}, match={match}")


    def replyToIP(self, packet, match, event, fwconfig):
        log.debug("You are in original code block ...")

        srcmac1 = EthAddr(match.dl_src) if match.dl_src != 'any' else None
        dstmac1 = EthAddr(match.dl_dst) if match.dl_dst != 'any' else None

        ip_packet = packet.find('ipv4')
        s_ip1 = ip_packet.srcip if ip_packet else None
        d_ip1 = ip_packet.dstip if ip_packet else None

        tcp_packet = packet.find('tcp')

        s_port1 = tcp_packet.srcport if tcp_packet else None
        d_port1 = tcp_packet.dstport if tcp_packet else None

        nw_proto1 = 0
        if ip_packet:
            if ip_packet.protocol == ipv4.TCP_PROTOCOL:
                nw_proto1 = ipv4.TCP_PROTOCOL
            elif ip_packet.protocol == ipv4.ICMP_PROTOCOL:
                nw_proto1 = ipv4.ICMP_PROTOCOL
                s_port1 = None
                d_port1 = None
            elif ip_packet.protocol == ipv4.UDP_PROTOCOL:
                nw_proto1 = ipv4.UDP_PROTOCOL
            else:
                log.debug("PROTOCOL field is mandatory, Choose between ICMP, TCP, UDP or check rule logic.")
        else:
            log.debug("Packet is not IPv4, cannot apply L3/L4 rules based on this original block.")

        print (f"{priority}, {s_ip1}, {d_ip1}, {s_port1}, {d_port1}, {nw_proto1}")
        self.installFlow(event, priority, srcmac1, dstmac1, s_ip1, d_ip1, s_port1, d_port1, nw_proto1)
        self.allowOther(event)

        found_match_and_blocked = False
        for rule in self.rules:
            is_match = True

            if rule['src_mac'] is not None and rule['src_mac'] != match.dl_src:
                is_match = False
            if rule['dst_mac'] is not None and rule['dst_mac'] != match.dl_dst:
                is_match = False

            ip_packet = packet.find('ipv4')
            if ip_packet and is_match:
                if rule['src_ip'] is not None and rule['src_ip'] != ip_packet.srcip:
                    is_match = False
                if rule['dst_ip'] is not None and rule['dst_ip'] != ip_packet.dstip:
                    is_match = False

                if rule['nw_proto'] != 0 and rule['nw_proto'] != ip_packet.protocol:
                    is_match = False

                if is_match and (rule['src_port'] is not None or rule['dst_port'] is not None):
                    if ip_packet.protocol == ipv4.TCP_PROTOCOL:
                        tcp_packet = packet.find('tcp')
                        if not tcp_packet:
                            is_match = False
                        else:
                            if rule['src_port'] is not None and rule['src_port'] != tcp_packet.srcport:
                                is_match = False
                            if rule['dst_port'] is not None and rule['dst_port'] != tcp_packet.dstport:
                                is_match = False
                    else:
                        is_match = False
            elif (rule['src_ip'] or rule['dst_ip'] or rule['nw_proto'] or
                  rule['src_port'] or rule['dst_port']):
                is_match = False

            if is_match:
                log.info(f"  Packet matched L3 Firewall rule (priority {rule['priority']}). Installing blocking flow.")
                print(f"{rule['priority']}, {rule['src_ip']}, {rule['dst_ip']}, {rule['src_port']}, {rule['dst_port']}, {rule['nw_proto']}")
                self.installFlow(event, rule['priority'], rule['src_mac'], rule['dst_mac'],
                                 rule['src_ip'], rule['dst_ip'],
                                 rule['src_port'], rule['dst_port'],
                                 rule['nw_proto'])
                found_match_and_blocked = True
                break

        if not found_match_and_blocked:
            log.info("  No L3 Firewall rule explicitly blocked the packet. Allowing other traffic.")
            self.allowOther(event)


def launch(l2config="l2firewall.config", l3config="l3firewall.config"):
    parser = argparse.ArgumentParser(description="L3 Firewall with Port Security")
    parser.add_argument('--l2config', action='store', dest='l2config',
                        help='Layer 2 config file', default='l2firewall.config')
    parser.add_argument('--l3config', action='store', dest='l3config',
                        help='Layer 3 config file', default='l3firewall.config')
    args = parser.parse_args()

    core.registerNew(Firewall, l2config=args.l2config, l3config=args.l3config)
    log.info("L3Firewall (with Port Security) module launched.")
