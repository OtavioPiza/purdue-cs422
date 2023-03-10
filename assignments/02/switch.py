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

import argparse
import json
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

# Flows and logs threshold
NUM_ENTRIES_THRESHOLD = 100
NUM_LOGS_THRESHOLD = 10

# Ethernet type values (https://en.wikipedia.org/wiki/EtherType)
# - ARP: 0x0806
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
def ProcPacketIn(switch_name, mcast_group_id,
                 eth_to_port_map, num_entries_threshold,
                 vlan_id_to_ports_map,
                 logs_dir, num_logs_threshold):
    try:
        logs_count = 0
        
        while True:
            # Receive packet
            rep = p4sh.client.get_stream_packet("packet", timeout=1)
            
            # Process packet
            if rep is not None:
                # Read the raw packet
                payload = rep.packet.payload

                ##################################################################################
                # Packet parsing logic - Begins ##################################################
                ##################################################################################

                # Parse metadata
                ingress_port_in_bytes = rep.packet.metadata[0].value
                ingress_port = int.from_bytes(
                    ingress_port_in_bytes, byteorder='big')

                # Parse Ethernet header
                dst_mac_in_bytes = payload[0:6]
                dst_mac = mac2str(dst_mac_in_bytes)
                src_mac_in_bytes = payload[6:12]
                src_mac = mac2str(src_mac_in_bytes)

                # Check if the packet is a VLAN packet
                eth_type_in_bytes = payload[12:14]
                eth_type = int.from_bytes(eth_type_in_bytes, byteorder='big')

                # Parse VLAN header if present
                vlan_tag = None
                if eth_type == ETH_TYPE_VLAN:
                    # Extract VLAN tag
                    vlan_tag_in_bytes = payload[14:16]
                    vlan_tag = int.from_bytes(
                        vlan_tag_in_bytes, byteorder='big')

                    # Update Ethernet type
                    eth_type_in_bytes = payload[16:18]
                    eth_type = int.from_bytes(eth_type_in_bytes, byteorder='big')

                # Print packet info
                print("PacketIn: dst={0} src={1} port={2}".format(dst_mac, src_mac, ingress_port))

                ##################################################################################
                # Packet parsing logic - Ends ####################################################
                ##################################################################################

                # Decrement table entry's counter
                del_mac_list = []
                for mac in eth_to_port_map:
                    eth_to_port_map[mac]['count'] -= 1
                    if eth_to_port_map[mac]['count'] == 0:
                        print("INFO: Flow entry deleted: mac={0} port={1}".format(
                            mac, eth_to_port_map[mac]['port']))
                        del_mac_list.append(mac)

                for mac in del_mac_list:
                    del eth_to_port_map[mac]

                ##################################################################################
                # Learning switch logic - Begins #################################################
                ##################################################################################
                
                # Process ARP request
                if eth_type == ETH_TYPE_ARP:
                    # Add src MAC to port mapping
                    eth_to_port_map[src_mac] = {
                        'port': ingress_port,
                        'count': num_entries_threshold
                    }

                    # Handle VLAN broadcast
                    if vlan_tag:
                        ProcPacketOut(payload,
                                      vlan_tag.to_bytes(4, byteorder='big'),
                                      ingress_port.to_bytes(4, byteorder='big'))

                    # Handle non-VLAN broadcast
                    else:
                        ProcPacketOut(payload,
                                      mcast_group_id.to_bytes(4, byteorder='big'),
                                      ingress_port.to_bytes(4, byteorder='big'))

                # Process non-ARP packet
                else:
                    # Look for the destination MAC address in the Ethernet address to port mapping
                    dst_port = eth_to_port_map.get(dst_mac, None)
                    
                    # Drop the packet if no mapping exists or dst port is the same as ingress port.
                    if dst_port is None or dst_port['port'] == ingress_port:
                        None

                    # Forward the packet to the destination port if vlan tag is not present
                    # or if the destination port is a member of the VLAN.
                    elif vlan_tag is None or dst_port['port'] in vlan_id_to_ports_map[vlan_tag]:
                        # Update the table entry's counter
                        dst_port['count'] = num_entries_threshold

                        # Send the packet out
                        ProcPacketOut(
                            payload,
                            ingress_port_in_bytes=ingress_port.to_bytes(4, byteorder='big'),
                            egress_port_in_bytes=dst_port['port'].to_bytes(4, byteorder='big'))
                        
                    # Update the table entry's counter
                    eth_to_port_map[src_mac] = {
                        'port': ingress_port,
                        'count': num_entries_threshold
                    }

                ##################################################################################
                # Learning switch logic - Ends ###################################################
                ##################################################################################

            # Logs the Ethernet address to port mapping
            logs_count += 1
            if logs_count == num_logs_threshold:
                logs_count = 0
                with open('{0}/{1}-table.json'.format(logs_dir, switch_name), 'w') as outfile:
                    json.dump(eth_to_port_map, outfile)

                print(
                    "INFO: Logs committed to {0}/{1}-table.json".format(logs_dir, switch_name))

    except KeyboardInterrupt:
        return None


# Process outgoing packets
def ProcPacketOut(payload, mcast_grp_in_bytes=b'\00\00', ingress_port_in_bytes=None, egress_port_in_bytes=None):
    req = p4rt.StreamMessageRequest()
    packet = req.packet
    packet.payload = payload

    metadata = p4rt.PacketMetadata()
    # Append multicast group ID
    metadata.metadata_id = 1
    metadata.value = mcast_grp_in_bytes
    packet.metadata.append(metadata)
    if ingress_port_in_bytes is not None:
        # Append ingress port
        metadata.metadata_id = 2
        metadata.value = ingress_port_in_bytes
        packet.metadata.append(metadata)
    if egress_port_in_bytes is not None:
        # Append egress port
        metadata.metadata_id = 4
        metadata.value = egress_port_in_bytes
        packet.metadata.append(metadata)

    # Send packet out
    p4sh.client.stream_out_q.put(req)

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

    # Create a Ethernet address to port mapping
    eth_to_port_map = {}

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
            # Path to P4Info file
            '{0}/{1}-p4info.txt'.format(CFG_DIR, switch_name),
            '{0}/{1}.json'.format(CFG_DIR, switch_name)  # Path to config file
        )
    )

    print("Switch Started @ Port: {0}".format(args.grpc_port))
    print("Press CTRL+C to stop ...")

    # Install broadcast rule
    InstallMcastGrpEntry(mcast_group_id, mcast_group_ports)

    ##################################################################################
    # Install VLAN Broadcast Rules - Begins ##########################################
    ##################################################################################

    # For each VLAN ID, install a broadcast rule that forwards the packet to all the
    # ports that are members of the VLAN
    for vlan_tag, ports in vlan_id_to_ports_map.items():
        InstallMcastGrpEntry(vlan_tag, ports)
        
    ##################################################################################
    # Install VLAN Broadcast Rules - Ends ############################################
    ##################################################################################

    # Start the packet-processing loop
    ProcPacketIn(switch_name, mcast_group_id,
                 eth_to_port_map, NUM_ENTRIES_THRESHOLD,
                 vlan_id_to_ports_map,
                 LOGS_DIR, NUM_LOGS_THRESHOLD)

    print("Switch Stopped")

    # Delete broadcast rule
    DeleteMcastGrpEntry(mcast_group_id)

    ##################################################################################
    # Delete VLAN Broadcast Rules - Begins ###########################################
    ##################################################################################

    for vlan_tag in vlan_id_to_ports_map.keys():
        DeleteMcastGrpEntry(vlan_tag)

    ##################################################################################
    # Delete VLAN Broadcast Rules - Ends #############################################
    ##################################################################################

    # Close the P4Runtime connection
    p4sh.teardown()
