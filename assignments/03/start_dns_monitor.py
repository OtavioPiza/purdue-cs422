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

    def handle_packet(self, pkt):
        # TODO: process the packet and install flow rules to perform DNS reflection
        #       attack detection and mitigation
        
        # Check if packet is an IP packet
        if IP not in pkt:
            pass
            
        print("Packet received")
        print(pkt)
        print(self)
        pass

    def _sniff(self, intf):
        sniff(iface=intf, prn=lambda x: self.handle_packet(x),
              lfilter=lambda x: self.incoming(x, intf))


if __name__ == "__main__":
    # TODO: Install flow rules to clone DNS packets from the switch to the monitor
    # install_rule("m1-eth1", "in_port=1,dl_type=0x0800,nw_proto=17,tp_dst=53,actions=clone:NXM_NX_REG0[]")
    install_rule(
        priority=100,
        table="monitor",
        is_permanent=True,
        monitor=True,
        l4_src=53,
        l4_dst=53,
    )

    intf = "m1-eth1"
    mac_map = {intf: ["00:00:00:00:00:02", "00:00:00:00:00:03"]}
    ip_map = {intf: ["10.0.0.2", "10.0.0.3"]}
    handler = PacketHandler(intf, mac_map, ip_map)
    handler.start()

