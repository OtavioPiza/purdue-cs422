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

import json
import argparse
import contextlib
import p4runtime_sh.shell as p4sh
from p4.v1 import p4runtime_pb2 as p4rt

###############################################################################
# Default parameters
###############################################################################

# Relative path of the configuration, logs, and topo directories
CFG_DIR = 'cfg'
LOGS_DIR = 'logs'

# Bridge ID and number of ports
BRIDGE_ID = 1
BRIDGE_CPU_PORT = 255

# Logs threshold
NUM_LOGS_THRESHOLD = 10

# Ethernet type values (https://en.wikipedia.org/wiki/EtherType)
ETH_TYPE_ARP = 0x0806
ETH_TYPE_VLAN = 0x8100


###############################################################################
# Helper functions
###############################################################################

# MAC address in bytes to string
def mac2str(mac):
    return ':'.join('{:02x}'.format(b) for b in mac)


###############################################################################
# Multicast group functions
###############################################################################

# Create a multicast group entry
def InstallMcastGrpEntry(mcast_group_id, bridge_ports):
    mcast_entry = p4sh.MulticastGroupEntry(mcast_group_id)
    for port in bridge_ports:
        mcast_entry.add(port)
    mcast_entry.insert()

# Delete a multicast group entry
def DeleteMcastGrpEntry(mcast_group_id):
    mcast_entry = p4sh.MulticastGroupEntry(mcast_group_id)
    mcast_entry.delete()


###############################################################################
# Packet processing functions
###############################################################################

# Process incoming packets
def ProcPacketIn(switch_name, logs_dir, num_logs_threshold):
    try:
        num_logs = 0
        while True:
            rep = p4sh.client.get_stream_packet("packet", timeout=1)
            if rep is not None:
                # Read the raw packet
                payload = rep.packet.payload
                
                 # Parse Metadata
                ingress_port_in_bytes = rep.packet.metadata[0].value
                ingress_port = int.from_bytes(ingress_port_in_bytes, "big")

                # Parse Ethernet header
                dst_mac_in_bytes = payload[0:6]
                dst_mac = mac2str(dst_mac_in_bytes)
                src_mac_in_bytes = payload[6:12]
                src_mac = mac2str(src_mac_in_bytes)
                eth_type_in_bytes = payload[12:14]
                eth_type = int.from_bytes(eth_type_in_bytes, "big")

                if eth_type == ETH_TYPE_VLAN:
                    # Parse VLAN header
                    vlan_id_in_bytes = payload[14:16]
                    vlan_id = int.from_bytes(vlan_id_in_bytes, "big")

                    print("PacketIn: dst={0} src={1} vlan={2} port={3}".format(
                        dst_mac, src_mac, vlan_id, ingress_port))
                else:
                    print("PacketIn: dst={0} src={1} port={2}".format(
                        dst_mac, src_mac, ingress_port))

                try:
                    with contextlib.redirect_stdout(None):  # A hack to suppress print statements 
                        # within the table_entry.match get/set objects
                        
                        ##################################################################################
                        # Learning Switch Logic - Begins #################################################
                        ##################################################################################

                        # TODO: For each incoming ARP packet, learn the mapping between the tuple (source 
                        # Ethernet address, VLAN ID) to ingress port. For non-VLAN packets, set the VLAN 
                        # ID to 0. 
                        # Install flow entries in switch table (you specified in the P4 program):
                        #   - Match fields: Ethernet address, VLAN ID
                        #   - Action: `MyIngress.forward`` | parameter: `port``
                        #
                        # NOTE: please follow p4rt-src/bridge.py for a reference example on how to install
                        # table entries.
                        table_entry = p4sh.TableEntry('MyIngress.switch_table')(action='forward')
                        table_entry.match['hdr.ethernet.dstAddr'] = src_mac
                        table_entry.action['port'] = str(ingress_port)
                        table_entry.insert()

                        ##################################################################################
                        # Learning Switch Logic - Ends ###################################################
                        ##################################################################################
                        
                except:
                    pass

            # Log the Ethernet address to port mapping
            num_logs += 1
            if num_logs == num_logs_threshold:
                num_logs = 0
                with open('{0}/{1}-table.json'.format(logs_dir, switch_name), 'w') as outfile:
                    with contextlib.redirect_stdout(outfile):
                        p4sh.TableEntry('MyIngress.switch_table').read(lambda te: print(te))
                print(
                    "INFO: Log committed to {0}/{1}-table.json".format(logs_dir, switch_name))
    except KeyboardInterrupt:
        return None


###############################################################################
# Main 
###############################################################################
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Switch Script')
    parser.add_argument('--grpc-port', help='GRPC Port', required=True,
                        type=str, action="store", default='50001')
    parser.add_argument('--topo-config', help='Topology Configuration File', required=True,
                        type=str, action="store")
    args = parser.parse_args()

    # Create a bridge name postfixed with the grpc port number
    switch_name = 'switch-{0}'.format(args.grpc_port)

    # Get Multicast/VLAN ID to ports mapping
    with open(args.topo_config, 'r') as infile:
        topo_config = json.loads(infile.read())

    mcast_group_id = topo_config['switch'][args.grpc_port]['mcast']['id']
    mcast_group_ports = topo_config['switch'][args.grpc_port]['mcast']['ports']

    vlan_id_to_ports_map = {}
    for vlan_id, ports in topo_config['switch'][args.grpc_port]['vlan_id_to_ports'].items():
        vlan_id_to_ports_map[int(vlan_id)] = ports

    # Setup the P4Runtime connection with the bridge
    p4sh.setup(
        device_id=BRIDGE_ID, grpc_addr='127.0.0.1:{0}'.format(args.grpc_port), election_id=(0, 1),
        config=p4sh.FwdPipeConfig(
            '{0}/{1}-p4info.txt'.format(CFG_DIR, switch_name),  # Path to P4Info file
            '{0}/{1}.json'.format(CFG_DIR, switch_name)  # Path to config file
        )
    )

    print("Switch Started @ Port: {0}".format(args.grpc_port))
    print("Press CTRL+C to stop ...")

    # Install broadcast rule
    InstallMcastGrpEntry(mcast_group_id, mcast_group_ports + [BRIDGE_CPU_PORT])

    print(vlan_id_to_ports_map)

    # Install VLAN rules
    with contextlib.redirect_stdout(None):  # A hack to suppress print statements 
        # within the table_entry.match get/set objects

        ##################################################################################
        # Install VLAN Rules - Begins ####################################################
        ##################################################################################

        # TODO: Install flow entries to let packets traverse only those egress ports that 
        # match its VLAN ID.
        # Install flow entries in the VLAN table (as specified in the P4 program):
        #   - Match fields: `standard_metadata.egress_port`, VLAN ID
        #   - Action: `MyEgress.noop`
        #
        # NOTE: please follow p4rt-src/bridge.py for a reference example on how to install
        # table entries.

        for vlan_id in vlan_id_to_ports_map:
            for port in vlan_id_to_ports_map[vlan_id]:
                
                # Create rules to allow VID to traverse ports in the same VLAN.
                table_entry = p4sh.TableEntry('MyEgress.vlan_table')(action='noop')
                table_entry.match["standard_metadata.egress_port"] = str(port)
                table_entry.match["meta.vid"] = str(vlan_id)
                table_entry.insert()

        ##################################################################################
        # Install VLAN Rules - Ends ######################################################
        ##################################################################################

    with open('{0}/{1}-vlan-table.json'.format(LOGS_DIR, switch_name), 'w') as outfile:
        with contextlib.redirect_stdout(outfile):
            p4sh.TableEntry('MyEgress.vlan_table').read(lambda te: print(te))
        print("INFO: Log committed to {0}/{1}-vlan-table.json".format(LOGS_DIR, switch_name))

    # Start the packet-processing loop
    ProcPacketIn(switch_name, LOGS_DIR, NUM_LOGS_THRESHOLD)

    print("Switch Stopped")

    # Delete broadcast rule
    DeleteMcastGrpEntry(mcast_group_id)

    # Delete VLAN rules
    with contextlib.redirect_stdout(None):  # A hack to suppress print statements 
        # within the table_entry.match get/set objects

        ##################################################################################
        # Delete VLAN Rules - Begins #####################################################
        ##################################################################################

        # TODO: Delete VLAN flow entries.
        # Delete flow entries from the VLAN table (as specified in the P4 program):
        #   - Match fields: `standard_metadata.egress_port`, VLAN ID
        #   - Action: `MyEgress.noop`
        #
        # NOTE: please follow p4rt-src/bridge.py for a reference example on how to install
        # table entries.

        for vlan_id in vlan_id_to_ports_map:
            for port in vlan_id_to_ports_map[vlan_id]:
                
                # Create rules to allow VID to traverse ports in the same VLAN.
                table_entry = p4sh.TableEntry('MyEgress.vlan_table')(action='noop')
                table_entry.match["standard_metadata.egress_port"] = str(port)
                table_entry.match["meta.vid"] = str(vlan_id)
                table_entry.delete()

        ##################################################################################
        # Delete VLAN Rules - Ends #######################################################
        ##################################################################################

    # Close the P4Runtime connection
    p4sh.teardown()
