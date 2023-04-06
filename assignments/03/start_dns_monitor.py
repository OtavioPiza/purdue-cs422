#!/usr/bin/env python

############################################################################
##
##     This file is part of Purdue CS 422.
##
##     Purdue CS 422 is free software: you can redistribute it and/or modify
##     it under the terms of the GNU General Public License as published by
##     the Free Software Foundation, either version 3 of the License, or
##     (at your option) any later version.
##
##     Purdue CS 422 is distributed in the hope that it will be useful,
##     but WITHOUT ANY WARRANTY; without even the implied warranty of
##     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##     GNU General Public License for more details.
##
##     You should have received a copy of the GNU General Public License
##     along with Purdue CS 422. If not, see <https://www.gnu.org/licenses/>.
##
#############################################################################

import threading
from collections import defaultdict

from scapy.all import *
from utils.rest import install_rule, delete_rule, install_group


class PacketHandler:

    def __init__(self, intf, mac_map, ip_map):
        self.intf = intf
        self.mac_map = mac_map
        self.ip_map = ip_map
        self.unrequested_dns = {}
        self.dns_requests = {}
        self.blocked_hosts = set()
        self.delete_queue = []
        # TODO: Create and initialize additional instance variables
        #       for detection and mitigation
        # add code here ...

    def start(self):
        t = threading.Thread(target=self._sniff, args=(self.intf,))
        t.start()

    def incoming(self, pkt, intf):
        macs = self.mac_map[intf]

        res = (pkt[Ether].src in macs or
               pkt[Ether].dst in macs)
        return res

    def handle_packet(self, packet):
        
        # Empty the delete queue
        # while len(self.delete_queue) > 0:
        #     sip, dip, did = self.delete_queue.pop()
        #     delete_rule(
        #         table="forward",
        #         ipv4_src=sip,
        #         ipv4_dst=dip,
        #         dns_id=did
        #     )

        # Check if packet is an IP packet and a DNS packet
        if IP not in packet or DNS not in packet:
            return

        # Extract the source and destination ip addresses from the packet.
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[UDP].sport
        dest_port = packet[UDP].dport
        dns_id = packet[DNS].id
        
        print("IP Packet received")
        print "DNS ID: %s is a %s" % (dns_id, "request" if packet[DNS].qr == 0 else "response")
        print "Src: %s:%d Dst: %s:%d" % (src_ip, src_port, dst_ip, dest_port)
        print({dst_ip})

        # If the packet is a DNS request add the requester to the dns_requests dictionary
        # or increment the number of requests if the requester is already in the dictionary
        # and install a rule to allow a response from the destination ip to the source ip.
        if packet[DNS].qr == 0:
            # If there is no entry for the source ip in the dns_requests dictionary, create
            # a new set and add the DNS ID to the set.
            if src_ip not in self.dns_requests:
                self.dns_requests[src_ip] = set()

            # Create a flow rule that allows packets from the destination ip to the source ip
            # with the same DNS ID.
            self.dns_requests[src_ip].add(dns_id)
            print "Installing rule for %s to %s" % (dst_ip, src_ip)
            install_rule(
                table="forward",
                priority=1000,
                is_permanent=True,
                ipv4_src=dst_ip,
                ipv4_dst=src_ip,
                dns_id=dns_id,
                output=2
            )

        # Determine if the packet is a DNS response and if the response is unrequested.
        else:

            # If the DNS ID is not in the dns_requests dictionary the response is unrequested.
            if dst_ip not in self.dns_requests or dns_id not in self.dns_requests[dst_ip]:
                # If there is no entry for the (src_ip, dst_ip) pair in the unrequested_dns
                # dictionary, create a new entry with a value of 1.
                if (src_ip, dst_ip) not in self.unrequested_dns:
                    self.unrequested_dns[(src_ip, dst_ip)] = 0

                # Add the (src_ip, dst_ip) pair to the unrequested_dns dictionary or increment
                # the number of unrequested DNS responses if the pair is already in the dictionary.
                self.unrequested_dns[(src_ip, dst_ip)] += 1

                # If the number of unrequested DNS responses is greater than 5, create a flow
                # rule to drop packets from the source ip to the destination ip in the future.
                if self.unrequested_dns[(src_ip, dst_ip)] > 5 and (src_ip, dst_ip) not in self.blocked_hosts:
                    print "Dropping packets from %s to %s" % (src_ip, dst_ip)
                    install_rule(
                        table="forward",
                        priority=100,
                        is_permanent=True,
                        l4_src=53,
                        ipv4_src=src_ip,
                        ipv4_dst=dst_ip
                    )
                    self.blocked_hosts.add((src_ip, dst_ip));

            else:
                # Remove the DNS ID from the dns_requests dictionary and delete the flow rule
                # that allows packets from the destination ip to the source ip with the same
                # DNS ID.
                self.dns_requests[dst_ip].remove(dns_id)
                self.delete_queue.append((src_ip, dst_ip, dns_id))
                print "Deleting rule for %s to %s" % (dst_ip, src_ip)


    def _sniff(self, intf):
        sniff(iface=intf, prn=lambda x: self.handle_packet(x),
              lfilter=lambda x: self.incoming(x, intf))


if __name__ == "__main__":
    # TODO: Install flow rules to clone DNS packets from the switch to the monitor
    # install_rule("m1-eth1", "in_port=1,dl_type=0x0800,nw_proto=17,tp_dst=53,actions=clone:NXM_NX_REG0[]")
    install_rule(
        table="monitor",
        priority=100,
        is_permanent=True,
        monitor=True,
        l4_dst=53,
    )
    install_rule(
        table="monitor",
        priority=100,
        is_permanent=True,
        monitor=True,
        l4_src=53,
    )
    intf = "m1-eth1"
    mac_map = {intf: ["00:00:00:00:00:02", "00:00:00:00:00:03"]}
    ip_map = {intf: ["10.0.0.2", "10.0.0.3"]}
    handler = PacketHandler(intf, mac_map, ip_map)
    handler.start()

