import json
import re
import uuid

import paramiko
import socket
from subprocess import PIPE, Popen
from collections import namedtuple
from .device import Topology


def cmdline(command):
    process = Popen(args=command, stdout=PIPE, shell=True)
    return process.communicate()[0]


def parse_output(input, oid_str, input_type):
    output = str(input)
    output = output.replace('\\n', ',').replace('\n', ','). \
        replace('\\r', ',').replace('\r', ',').replace("b'", ''). \
        replace('"', '').replace("'", '')
    output = output.rstrip("'").rstrip(",")
    output = re.sub(
            r'{}.[0-9]+.[0-9]+ = {}: '.format(oid_str, input_type),
            '',
            output
    )
    return output

def find_esxi_neighbors(esxi_host, ssh_cred_list):
    for ssh_username, ssh_password  in ssh_cred_list:
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                esxi_host,
                username=ssh_username,
                password=ssh_password,
                look_for_keys=False,
                timeout=9
            )
        except Exception as e:
            print ("SSH failed for {} with username: {} : {}".format(
                esxi_host, ssh_username, str(e)
            ))
        else:
            cmd = 'vim-cmd hostsvc/net/query_networkhint | egrep  "devId = \".*\"" -o | cut -d = -f2'
            _in, out, err = ssh.exec_command(cmd)
            output = out.read().decode().replace(", \n", ",")
            device_names = set(eval(output))
            neighbors = [
                (socket.gethostbyname(name), name) for name in device_names
            ]
            return neighbors
    return []

def get_esxis_neighbors(esxis, ssh_cred_list):
    result = {}
    for esxi_host in esxis:
        ip_address = esxi_host['ip_address']
        esxi_host_neighbors = find_esxi_neighbors(ip_address, ssh_cred_list)
        result[ip_address] = esxi_host_neighbors
    return result


def get_host_neighbors(devices, snmp_cred_list):
    """
    This function takes the discovery scan result
    and runs the snmpwalk command for each ip in the result.

    Args:
        devices (list of dicts): discovery scan result.

    Returns:
        dict of hostnames.
        Each dict value is a list of lldp neighbor hostnames.

    Sample i/p:
        [
            {'hostname': 'hostname1', 'ip_address': '0.0.0.1', 'snmp_cred_index': 1,...},
            {'hostname': 'hostname2', 'ip_address': '0.0.0.2', 'snmp_cred_index': 2,...},
        ]

    Sample o/p:
        {
            'hostip1': [('hostip2', 'hostname2'), ('hostip3', 'hostname3'),...],
            'hostip2': [('hostip3', 'hostname3'), ('hostip4', 'hostname4'),...],
        }
    """

    host_lldp_neighbors = {}
    oid_str_name = 'SNMPv2-SMI::enterprises.9.9.23.1.2.1.1.6'
    oid_str_ip = 'SNMPv2-SMI::enterprises.9.9.23.1.2.1.1.4'

    for device in devices:
        ip = device.get('ip_address')
        name = device.get('hostname')
        snmp_version = device.get('snmpversion')
        # each device dict has an 'snmp_cred_index' key
        # the value of this key is the index of the credentials
        # in snmp_cred_list that are used for this device
        index = device.get('snmp_cred_index')
        if not index and not isinstance(index, int):
            print("SNMP not enabled. Moving to the next device")
            continue

        snmp_details = snmp_cred_list[index]

        if snmp_version == 3:
            try:
                if snmp_details['security_level'] == 'noAuthNoPriv':
                    priv_prot = 'noAuthNoPriv'
                elif snmp_details['security_level'] == 'authNoPriv':
                    priv_prot = 'authNoPriv'
                elif snmp_details['security_level'] == 'authPriv':
                        priv_prot = 'authPriv'

                command = 'snmpwalk -a {} -A {} -l {} -u {} -v 3 -x {} -X {} {}'
                command = command.format(
                    snmp_details['auth_protocol'],
                    snmp_details['auth_password'],
                    priv_prot,
                    snmp_details['security_username'],
                    snmp_details['privacy_protocol'],
                    snmp_details['privacy_password'],
                    ip
                )
                command_ip = f'{command} {oid_str_ip}'
                command_name = f'{command} {oid_str_name}'
            except KeyError:
                continue
        else:
            command_ip = f'snmpwalk -v2c -c ul4ever {ip} {oid_str_ip}'
            command_name = f'snmpwalk -v2c -c ul4ever {ip} {oid_str_name}'

        output_ip = cmdline(command_ip)
        output_ip = parse_output(output_ip, oid_str_ip, 'Hex-STRING')
        output_ip = output_ip.replace(' ,', ',')
        output_ip = output_ip.rstrip()

        output_name = cmdline(command_name)
        output_name = parse_output(output_name, oid_str_name, 'STRING')

        if output_name[:10] == 'SNMPv2-SMI' or not output_name:
            print("No result returned")
            continue

        neighbor_names = output_name.split(',')
        neighbor_names = list(set(neighbor_names))
        # this creates a list of neighbors ips
        # ips are in hex so they need to be converted to decimal
        neighbor_ips = output_ip.split(',')
        for i in range(len(neighbor_ips)):
            ip_hex = neighbor_ips[i].split(" ")
            ip_decimal = ".".join([str(int(c, base=16)) for c in ip_hex])
            neighbor_ips[i] = ip_decimal

        neighbor_ips = list(set(neighbor_ips))
        # save the neighbor ips and names in another list
        neighbors_list = list(zip(neighbor_ips, neighbor_names))
        host_lldp_neighbors[ip] = neighbors_list

    return host_lldp_neighbors


def generate_nodes_data(devices, all_neighbors_list):
    """
    This function takes the discovery scan result
    and adds an id to each record.
    This id is used to create the links for nodes.

    Args:
        devices (list of dicts): discovery scan result.
        neighbors_list (list of tuples): ips and names of 
                                         all neighbors detected.

    Returns:
        devices (list of dicts): discovery scan result
        with id appended.

    Sample i/p:
    devices
        [
            {'hostname': 'hostname1', 'ip_address': '0.0.0.1',...},
            {'hostname': 'hostname2', 'ip_address': '0.0.0.2',...},
        ]

    neighbors_list
        [('ip1', 'hostname1'), ('ip2', 'hostname2'), ('ip3', 'hostname3'),...]

    Sample o/p:
        [
            {'hostname': 'hostname1', 'ip_address': '0.0.0.1', 'id': 0},
            {'hostname': 'hostname2', 'ip_address': '0.0.0.2', 'id': 1},
            {'hostname': 'hostname3', 'ip_address': '0.0.0.3', 'id': 2}
        ]
    """

    device_ips = [device['ip_address'] for device in devices]

    for ip, hostname in all_neighbors_list:
        if ip not in device_ips:
            device_ips.append(ip)
            devices.append({
                'hostname': hostname,
                'ip_address': ip,
                'device_type': '',
                'unique_id': str(uuid.uuid4())
            })

    for i in range(len(devices)):
        device = devices[i]
        device['id'] = i
        device['onboarded'] = False

    return devices


def generate_links_data(lldp_data, nodes):
    """
    This function takes the lldp data and the nodes data and 
    creates a  list that contains the topology links information.

    Args:
        lldp_data (dict of hostnames).
        Each dict value is a list of lldp neighbor hostnames.

        nodes(list of dicts): discovery scan result.

    Returns:
        links result (list of dicts): link nodes


    Sample i/p:
    lldp_data:
        {
            'hostip1': [('hostip2', 'hostname2'), ('hostip3', 'hostname3'),...],
            'hostip2': [('hostip3', 'hostname3'), ('hostip4', 'hostname4'),...],
        }
    nodes:
        [
            {'hostname': 'hostname1', 'ip_address': '0.0.0.1', 'id': 0},
            {'hostname': 'hostname2', 'ip_address': '0.0.0.2', 'id': 1},
            {'hostname': 'hostname3', 'ip_address': '0.0.0.3', 'id': 2}
        ]

    nodes_map
        {
            'ip_address': {
                'hostname': 'hostname1', 'ip_address': '0.0.0.1', 'id': 0
            },
            'ip_address': {
                'hostname': 'hostname2', 'ip_address': '0.0.0.2', 'id': 1
            },
            'ip_address': {
                'hostname': 'hostname3', 'ip_address': '0.0.0.3', 'id': 2
            }
        }

    Sample o/p:
        [
            {
                "source_id":0,
                "source_ip":"ip1",
                "source_hostname":"hostname1",
                "target_id":2,
                "target_ip":"ip3",
                "target_hostname":"hostname3"
            },
            {
                "source_id":0,
                "source_ip":"ip1",
                "source_hostname":"hostname1",
                "target_id":3,
                "target_ip":"ip4",
                "target_hostname":"hostname4"
            },
            {
                "source_id":0,
                "source_ip":"ip1",
                "source_hostname":"hostname1",
                "target_id":4,
                "target_ip":"ip5",
                "target_hostname":"hostname5"
            },
        ]
    """

    result = []
    # convert nodes into a dictionary
    nodes_map = {node['ip_address']: node for node in nodes}

    for source_ip, values in nodes_map.items():
        source_id = values.get('id')
        source_uuid = values.get('unique_id')
        source_hostname = values.get('hostname')
        source_device_type = values.get('device_type')

        for key in lldp_data:
            if key == source_ip:
                for target_ip, target_hostname in lldp_data[key]:
                    target_id = nodes_map.get(target_ip).get('id')
                    target_uuid = nodes_map.get(target_ip).get('unique_id')
                    target_device_type = nodes_map.get(target_ip).get('device_type')
                    result.append({
                        'source_id': source_id,
                        'source_uuid': source_uuid,
                        'source_ip': source_ip,
                        'source_hostname': source_hostname,
                        'source_device_type': source_device_type,
                        'target_id': target_id,
                        'target_uuid': target_uuid,
                        'target_ip': target_ip,
                        'target_hostname': target_hostname,
                        'target_device_type': target_device_type
                    })

    return result


def generate_topology1(devices, snmp_cred_list, ssh_cred_list):
    """
    This function takes the discovery scan result as
    an input and returns the topology data to the caller.

    Args:
        devices (list of dicts): discovery scan result.

    Returns:
        topology_data (dict): topology data with two items
        (nodes and links).
    """
    esxis_devices = []
    other_devices = []
    for device in devices:
        if device['device_type'] == 'hypervisor':
            esxis_devices.append(device)
        else:
            other_devices.append(device)

    esxis_lldp_data = get_esxis_neighbors(
        esxis_devices, ssh_cred_list
    )
    other_lldp_data = get_host_neighbors(
        other_devices, snmp_cred_list
    )

    lldp_data = {}
    lldp_data.update(esxis_lldp_data)
    lldp_data.update(other_lldp_data)
    all_neighbors_list = []
    for neighbors_list in lldp_data.values():
        all_neighbors_list.extend(neighbors_list)

    nodes = generate_nodes_data(devices, all_neighbors_list)
    links = generate_links_data(lldp_data, nodes)

    topology_data = {"nodes": nodes, "links":links}
    print(topology_data)

    return json.dumps(topology_data)

def generate_topology(devices, snmp_cred_list, ssh_cred_list):
    for device in devices:
        device['id'] = device['unique_id']
        
    topology = Topology(devices, snmp_cred_list, ssh_cred_list)
    topology.find_topology()
    links = []

    for source, target_devices in topology.topology_graph.items():
        for source_if_index, target_info in target_devices.items():
            target, target_if_index = target_info
            links.append({
                        'source_id': source.id,
                        'source_uuid': source.id,
                        'source_ip': source.ip_address,
                        'source_hostname': source.name,
                        'source_device_type': source.DEVICE_TYPE,
                        'source_if_index': source_if_index,
                        'target_id': target.id,
                        'target_uuid': target.id,
                        'target_ip': target.ip_address,
                        'target_hostname': target.name,
                        'target_device_type': target.DEVICE_TYPE,
                        'target_if_index': target_if_index
                    })

    topology_data = {"nodes": devices, "links":links}
    return json.dumps(topology_data)

if __name__ == '__main__':
    # TODO: for testing, remove later
    devices = [
        {
            'hostname': 'ar3.sf9.unitedlayer.com',
            'ip_address': '209.237.224.244',
            'manufacturer': 'cisco',
            'snmp_cred_index': 0,
            'snmpversion': 0
        },
        {
            'hostname': 'sw1-mgmt.sf10',
            'ip_address': '10.128.7.1',
            'snmp_cred_index': 0,
            'snmpversion': 0,
            'manufacturer': 'cisco',
        }
    ]
    snmp_cred_list = [{"cstring": "ul4ever", "version": 'SNMPv2'}, ]
    ssh_cred_list = [('uladmin', 'aEDq:c7y')]

