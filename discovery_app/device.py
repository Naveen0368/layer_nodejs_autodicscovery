import re
from subprocess import PIPE, Popen
from collections import namedtuple, defaultdict, ChainMap
from netaddr import EUI


def cmdline(command):
    process = Popen(args=command, stdout=PIPE, shell=True)
    return process.communicate()[0]

def snmp_result_to_py_obj(result):
    key, value = result.split(' = ')
    EMPTY = '""'
    # No Such Object available on this agent at this OID
    INVALID = 'No Such '
    if INVALID in value:
        return
    if value == EMPTY:
        value = eval(value)
    if value:
        datatype, value = value.split(':', 1)
        value = value.strip()
        if datatype == 'INTEGER':
            value = int(value)
        if datatype == 'STRING':
            value = eval(value) if value.startswith('"') else value 
        if datatype == 'Hex-STRING':
            value = value.strip()
        if datatype == 'Timeticks':
            value = value.split(')') if value else ''
            if isinstance(value, list):
                value = value[1].lstrip()

    return key, value

def do_snmp_walk(credential, ip, oid, vlan_number=None):
    if credential['version'] == 'SNMPv2' or credential['version'] == 'SNMPv1':
        community_string = credential['cstring']
        if vlan_number:
            community_string += '@'+str(vlan_number)

        command = f'snmpwalk -v2c -c {community_string} {ip} {oid} -One'
    elif credential['version'] == 'SNMPv3':
        if credential['security_level'] == 'noAuthNoPriv':
            priv_prot = 'noAuthNoPriv'
        elif credential['security_level'] == 'authNoPriv':
            priv_prot = 'authNoPriv'
        elif credential['security_level'] == 'authPriv':
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
        command = f'{command} {oid}'
    else:
        return {}
    output = cmdline(command)
    decoded_output = output.decode()
    if not decoded_output:
        return {}
    output_list = decoded_output.split('\n.1')
    result_list = []
    for row in output_list:
        if not row.startswith('.1'):
            row = 'iso' + row
        if row.startswith('.1'):
           row = row.replace('.1', 'iso', 1)
        if row.endswith('\n'):
            row = row.strip()
        data = snmp_result_to_py_obj(row)
        if data:
            result_list.append(data)       
    return dict(result_list) if result_list else {}

def hex_ip_to_decimal_ip(hex_string):
    if hex_string:
        decimal_list = [str(int(i, 16)) for i in hex_string.split(' ')]
        return '.'.join(decimal_list)


#Neighbor  = namedtuple('Neighbor', ['name','ip_address', 'if_id_type', 'if_id']) # if_id_type  ['index' ,'name', 'desc', 'mac', 'local']
Vlan  = namedtuple('Vlan', ['number','name', 'ip_address'])

def normalize_mac_address(value):
    cleaned_value = value.replace(" ", "")
    if cleaned_value:
        return str(EUI(cleaned_value))
    else:
        return None


class Neighbor(object):
    def __init__(self, name, ip_address, if_id_type, if_id):
        self.name = name
        self.ip_address = ip_address
        self.if_id_type =if_id_type # if_id_type  ['index' ,'name', 'desc', 'mac', 'local']
        if if_id_type == 'mac':
            self.if_id = normalize_mac_address(if_id)
        else:
            self.if_id = if_id

class Interface(object):
    def __init__(self, index, name, description, mac, _type, status):
        self.index = index
        self.name = name
        self.description = description
        self.mac =  normalize_mac_address(mac)
        self.type = _type
        self.status = status

        self.remote_device = None

    @property
    def local_name(self):
        # locally assigned
        if len(self.name) > 5:
            pattern = re.compile(r'([a-zA-Z-]+)([0-9/]+)')
            name, number = pattern.match(self.name).groups()
            return name[:3] + number
        else:
            return self.name


class Device(object):
    DEVICE_TYPE = None

    def __init__(self, details, snmp_cred_list, ssh_cred_list):
        self.snmp_cred_list = snmp_cred_list
        self.ssh_cred_list = ssh_cred_list

        self._mac_address = None
        self._if_index = None
        self._ssh_credential = None
        self._snmp_credential = None

        self.id = details.get('unique_id')
        self.name= details.get('hostname')
        self.description = details.get('SysDescription')
        self.ip_address= details.get('ip_address')
        #self.mac_address= details.get('MacAddress')
        self.if_index = details.get('ifIndex')
        self.manufacturer= details.get('manufacturer')
        self.model= details.get('model')
        self.serial_number = details.get('SerialNumber')
        self.operating_system = details.get('os')

        if details.get('snmp_cred_index') is not None:
            self.snmp_credential = snmp_cred_list[details.get('snmp_cred_index')]
        
        self._arp_table = None
        self._lldp_info = {}
        self._cdp_info = {}
        self._neighbors = {}
        self._interfaces = {}
        self._port_if_index_map = {}
        self._uptime = None

    def __repr__(self):
        return self.name

    def get_all_ip_addresses(self):
        oid = 'iso.3.6.1.2.1.4.20.1.1'
        result = self.do_snmp_walk(oid)
        return [ip for key, ip in result.items()]

    def get_mac_address(self):
        if not self._mac_address and self.if_index:
            oid = 'iso.3.6.1.2.1.2.2.1.6.{0}'.format(self.if_index)
            result = self.do_snmp_walk(oid)
            if result:
                self._mac_address = normalize_mac_address(result[oid])
        return self._mac_address

    def set_mac_address(self, value):
        self._mac_address = normalize_mac_address(value)

    def get_if_index(self):
        if not self._if_index:
            oid_dict = {
                'default': 'iso.3.6.1.2.1.4.20.1.2',
                'supermicro': 'iso.3.6.1.2.1.4.34.1.3.1.4'
            }
            manufacturer = self.manufacturer.lower()
            base_iod = oid_dict.get(manufacturer) or oid_dict.get('default')
            oid = '{base_oid}.{ip_address}'.format(base_oid=base_iod, ip_address=self.ip_address )
            result = self.do_snmp_walk(oid)
            if result:
                self._if_index = result[oid]

        return self._if_index

    def set_if_index(self, value):
        self._if_index = value

    mac_address = property(get_mac_address, set_mac_address)
    if_index = property(get_if_index, set_if_index)

    def get_port_name_by_number(self, port_number):
        base_port_if_index_oid = 'iso.3.6.1.2.1.17.1.4.1.2.{0}'.format(port_number)
        result = self.do_snmp_walk(base_port_if_index_oid)
        if_index = result[base_port_if_index_oid]
        if_name_oid = 'iso.3.6.1.2.1.31.1.1.1.1.{0}'.format(if_index)
        result = self.do_snmp_walk(if_name_oid)
        if_name = result[if_name_oid]
        return if_name

    def get_if_index_by_port_number(self, port_number):
        if_index = self.port_if_index_map.get(int(port_number))
        if if_index:
            return if_index
        else:
            print ('could not find if_index for '+ self.ip_address + 'port_number :'+ str(port_number))

        # base_port_if_index_oid = 'iso.3.6.1.2.1.17.1.4.1.2.{0}'.format(port_number)
        # result = self.do_snmp_walk(base_port_if_index_oid)
        # if_index = result[base_port_if_index_oid]
        # return if_index

    def get_if_index_by_port_number_m2(self, port_number):
        # this works only for cisco iso devices
        # https://stackoverflow.com/questions/71133538/how-to-properly-map-switch-interfaces-to-lldp-devices-using-snmp
        lldp_loc_port_desc_oid = 'iso.0.8802.1.1.2.1.3.7.1.4.{0}'.format(port_number)
        result = self.do_snmp_walk(lldp_loc_port_desc_oid)
        if result:
            if_desc = result[lldp_loc_port_desc_oid]
            for if_index, interface in self.interfaces.items():
                if interface.description == if_desc:
                    return if_index

    @property
    def port_if_index_map(self):
        if not self._port_if_index_map:
            for vlan_number in self.vlans.keys() or [None]:
                base_port_if_index_oid = 'iso.3.6.1.2.1.17.1.4.1.2'
                result = self.do_snmp_walk(base_port_if_index_oid, vlan_number)
                for key, value in result.items():
                    port_number = key.split('.')[-1]
                    if_index = value
                    self._port_if_index_map[int(port_number)] = int(if_index)

        return self._port_if_index_map
                
    def get_snmp_credential(self):
        if self._snmp_credential is None:
            system_object_id_oid = 'iso.3.6.1.2.1.1.2.0'
            for credential in self.snmp_cred_list:
                result = do_snmp_walk(credential, self.ip_address, system_object_id_oid)
                if result:
                    self._snmp_credential = credential
                    return self._snmp_credential

            self._snmp_credential = False
        return self._snmp_credential

    def set_snmp_credential(self, value):
        self._snmp_credential = value

    def get_ssh_credential(self):
        if not self._ssh_credential:
            for credential in self.ssh_cred_list:
                username, password = credential
                output = run_command(self.ip_address, username, password, 'hostname')
                if output:
                    self._ssh_credential = credential
                    break
        return self._ssh_credential

    def set_ssh_credential(self, value):
        self._ssh_credential = value

    snmp_credential = property(get_snmp_credential, set_snmp_credential)
    ssh_credential =  property(get_ssh_credential, set_ssh_credential)

    @property
    def arp_table(self):
        return self._arp_table

    @property
    def interfaces(self):
        if not self._interfaces:
            if_index_oid =  'iso.3.6.1.2.1.2.2.1.1'
            if_desc_oid =   'iso.3.6.1.2.1.2.2.1.2'
            if_mac_oid =    'iso.3.6.1.2.1.2.2.1.6'
            if_name_oid =   'iso.3.6.1.2.1.31.1.1.1.1'
            if_type_oid =   'iso.3.6.1.2.1.2.2.1.3'
            if_status_oid = 'iso.3.6.1.2.1.2.2.1.8'
            if_index_result = self.do_snmp_walk(if_index_oid)
            if_desc_result = self.do_snmp_walk(if_desc_oid)
            if_name_result = self.do_snmp_walk(if_name_oid)
            if_mac_result = self.do_snmp_walk(if_mac_oid)
            if_type_result = self.do_snmp_walk(if_type_oid)
            if_status_result = self.do_snmp_walk(if_status_oid)

            for index in if_index_result.values():
                str_index = str(index)
                desc = if_desc_result[if_desc_oid + '.'+ str_index]
                name = if_name_result.get(if_name_oid + '.'+ str_index)
                mac = if_mac_result[if_mac_oid + '.'+ str_index]
                _type = if_type_result[if_type_oid + '.'+ str_index]
                status = if_status_result[if_status_oid + '.'+ str_index]

                interface = Interface(index, name, desc, mac, _type, status)
                self._interfaces[index] = interface 

        return self._interfaces

    @property
    def uptime(self):
        if not self._uptime:
            if_uptime_oid = '1.3.6.1.2.1.1.3.0'
            if_uptime_result = self.do_snmp_walk(if_uptime_oid)
            self._uptime = if_uptime_result['iso.3.6.1.2.1.1.3.0']
            # self._uptime = snmp_result_to_py_obj(if_uptime_result)
        return self._uptime

    def get_interface_by_desc(self, if_desc):
        for if_index, interface in self.interfaces.items():
            if interface.description  == if_desc:
                return interface

    def get_interface_by_mac(self, if_mac):
        for if_index, interface in self.interfaces.items():
            if interface.mac  == if_mac:
                return interface

    def get_interface_by_name(self, if_name):
        for if_index, interface in self.interfaces.items():
            if interface.name  == if_name:
                return interface

    def get_interface_by_local_name(self, if_name):
        for if_index, interface in self.interfaces.items():
            if interface.local_name  == if_name:
                return interface

    @property
    def lldp_info(self):
        if not self._lldp_info:
            remote_system_name_oid =     'iso.0.8802.1.1.2.1.4.1.1.9'
            remote_system_port_id_type_oid = 'iso.0.8802.1.1.2.1.4.1.1.6'
            remote_system_port_id_oid = 'iso.0.8802.1.1.2.1.4.1.1.7'

            remote_system_name_result = self.do_snmp_walk(remote_system_name_oid)
            remote_system_port_id_type_result = self.do_snmp_walk(remote_system_port_id_type_oid)
            remote_system_port_id_result = self.do_snmp_walk(remote_system_port_id_oid)

            for key, value in remote_system_name_result.items():
                if not value:
                    continue
                if value == 'not advertised':
                    continue
                    
                key_split = key.split('.')
                number1, local_port_num_or_if_index, number2 = key_split[-3], key_split[-2], key_split[-1]
                remote_system_port_id_type = remote_system_port_id_type_result[remote_system_port_id_type_oid + '.' +number1 + '.' + local_port_num_or_if_index + '.' + number2]
                remote_system_port_id = remote_system_port_id_result[remote_system_port_id_oid + '.' +number1 + '.' + local_port_num_or_if_index + '.' + number2]
                
                remote_system_name = value
                remote_system_if_id_type = None
                remote_system_if_id = None


                if remote_system_port_id_type == 7: # 7: port Locally assigned
                    remote_system_if_id_type = 'local'
                    remote_system_if_id = remote_system_port_id
                if remote_system_port_id_type == 5: # 5: Interface name
                    remote_system_if_id_type = 'name'
                    remote_system_if_id = remote_system_port_id
                if remote_system_port_id_type == 3: # 3: MAC address
                    remote_system_if_id_type = 'mac'
                    remote_system_if_id = remote_system_port_id

                # this could be port number or interface index, so to confirm first will check in interface list,
                # if not a found then it is port number     
                is_if_index = bool(self.interfaces.get(int(local_port_num_or_if_index)))
                if  is_if_index:
                    local_if_index = local_port_num_or_if_index
                else:
                    local_if_index = self.get_if_index_by_port_number(local_port_num_or_if_index)

                if local_if_index:
                    self._lldp_info[int(local_if_index)] = Neighbor(remote_system_name, None, remote_system_if_id_type, remote_system_if_id)
        return self._lldp_info

    @property
    def cdp_info(self):
        if not self._cdp_info:
            if 'cisco' in self.manufacturer.lower():
                remote_system_ip_oid = 'iso.3.6.1.4.1.9.9.23.1.2.1.1.4'
                remote_system_name_oid = 'iso.3.6.1.4.1.9.9.23.1.2.1.1.6'
                remote_system_if_desc_oid = 'iso.3.6.1.4.1.9.9.23.1.2.1.1.7'

                remote_system_ip_result = self.do_snmp_walk(remote_system_ip_oid)
                remote_system_name_result = self.do_snmp_walk(remote_system_name_oid)
                remote_system_if_desc_result = self.do_snmp_walk(remote_system_if_desc_oid)
                for key, hex_string_ip in remote_system_ip_result.items():
                    key_split = key.split('.')
                    local_if_index, number = key_split[-2], key_split[-1]
                    remote_system_ip = hex_ip_to_decimal_ip(hex_string_ip)
                    remote_system_name = remote_system_name_result[remote_system_name_oid + '.' + local_if_index + '.' + number]
                    remote_system_if_desc = remote_system_if_desc_result[remote_system_if_desc_oid + '.' + local_if_index + '.' + number]
                    self._cdp_info[int(local_if_index)] = Neighbor(remote_system_name, remote_system_ip, 'desc', remote_system_if_desc)

        return self._cdp_info

    @property
    def neighbors(self):
        if not self._neighbors:
            self._neighbors = self.cdp_info or self.lldp_info
        return self._neighbors

    def do_snmp_walk(self, oid, vlan_number=None):
        if self.snmp_credential:
            return do_snmp_walk(self.snmp_credential, self.ip_address, oid, vlan_number)
        else:
            return {}

class Router(Device):
    DEVICE_TYPE = 'router'
    pass

class Switch(Device):

    DEVICE_TYPE = 'switch'
    def __init__(self, *args, **kwargs):
        super(Switch, self).__init__(*args, **kwargs)
        self._mac_address_table = None
        self._mac_address_table_by_if_index = None
        self._vlans = {}

    @property
    def mac_address_table(self):
        if not self._mac_address_table:
            self._mac_address_table = {}
            mac_address_list_oid = 'iso.3.6.1.2.1.17.4.3.1.1'
            port_number_list_oid = 'iso.3.6.1.2.1.17.4.3.1.2'
            for vlan_number in self.vlans.keys() or [None]:
                mac_address_list = self.do_snmp_walk(mac_address_list_oid, vlan_number).values()
                mac_address_list = [normalize_mac_address(value) for value  in mac_address_list] # converting all type of mac string to mac obj
                port_number_list = self.do_snmp_walk(port_number_list_oid, vlan_number).values()
                if_index_list = map(self.get_if_index_by_port_number, port_number_list)

                self._mac_address_table.update(dict(zip(mac_address_list, if_index_list)))

        return self._mac_address_table

    @property
    def mac_address_table_by_if_index(self):
        if not self._mac_address_table_by_if_index:
            self._mac_address_table_by_if_index = defaultdict(list)
            for mac_address, if_index in self.mac_address_table.items():
                self._mac_address_table_by_if_index[if_index].append(mac_address)
        return self._mac_address_table_by_if_index

    @property
    def vlans(self):
        if not self._vlans:
            vlan_name_oid = 'iso.3.6.1.4.1.9.9.46.1.3.1.1.4.1'
            vlan_ip_oid = 'iso.3.6.1.4.1.9.9.46.1.3.1.1.6.1'
            vlan_name_result = self.do_snmp_walk(vlan_name_oid)
            vlan_ip_result = self.do_snmp_walk(vlan_ip_oid)

            for key, value in vlan_name_result.items():
                vlan_number = key.split('.')[-1]
                vlan_name = value
                vlan_ip = vlan_ip_result[vlan_ip_oid+ '.'+ vlan_number]
                vlan_ip = hex_ip_to_decimal_ip(vlan_ip)
                vlan = Vlan(int(vlan_number), vlan_name, vlan_ip)
                self._vlans[int(vlan_number)] = vlan
        return self._vlans

class Firewall(Device):
    DEVICE_TYPE = 'firewall'
    pass

class Loadbalancer(Device):
    DEVICE_TYPE = 'loadbalancer'
    pass

class Server(Device):

    def is_esxi(self):
        if 'esxi' in self.operating_system.lower():
            return True
        else:
            return False

    def get_vm_names(self):
        if self.is_esxi():
            vm_name_oid = 'iso.3.6.1.4.1.6876.2.1.1.2'
            result = self.do_snmp_walk(vm_name_oid)
            return [name for key, name in result.items()]
        else:
            return []



class Hypervisor(Server):
    DEVICE_TYPE = 'hypervisor'
    pass

class Baremetal(Server):
    DEVICE_TYPE = 'baremetal'
    pass

class VirtualMachine(Device):
    DEVICE_TYPE = 'vm'
    pass

class Storage(Device):
    DEVICE_TYPE = 'storage'

class Topology(object):
    def __init__(self, devices_dict, snmp_cred_list, ssh_cred_list):
        self.devices_dict = devices_dict
        self.topology_graph = defaultdict(dict)

        #devices by type
        self.routers = {}
        self.switches = {}
        self.firewalls = {}
        self.loaderbalancers = {}
        self.baremetals = {}
        self.hypervisors = {}
        self.vms = {}
        self.storage = {}
        self._devices_by_ip_address = {}
        self._devices_by_name = {}

        DEVICE_TYPE_MAP ={
            'router': (Router, self.routers),
            'switch': (Switch, self.switches),
            'firewall': (Firewall, self.firewalls),
            'loadbalancer': (Loadbalancer, self.loaderbalancers),
            'hypervisor': (Hypervisor, self.hypervisors),
            'baremetal': (Baremetal, self.baremetals),
            'server': (Baremetal, self.baremetals),
            'virtual_machine': (VirtualMachine, self.vms),
            'storage':(Storage, self.storage),
        }

        for device_data in self.devices_dict:
            device_type = device_data.get('device_type')
            if not device_type:
                continue
            if not DEVICE_TYPE_MAP.get(device_type):
                continue
            clasz, variable = DEVICE_TYPE_MAP[device_type]
            device = clasz(device_data, snmp_cred_list, ssh_cred_list)
            variable[device.id] = device

        self.networking_devices = ChainMap(self.routers, self.switches, self.firewalls, self.loaderbalancers)
        self.servers = ChainMap(self.baremetals, self.hypervisors)
        self.all_devices = ChainMap(self.networking_devices, self.servers, self.vms)

    def find_topology(self):
        networking_devices_neighbor_info = []
        for id, device in self.networking_devices.items():
            for local_if_index, neighbor in device.neighbors.items():
                if neighbor.ip_address:
                    remote_device = self.devices_by_ip_address.get(neighbor.ip_address)
                elif neighbor.name:
                    remote_device = self.devices_by_name.get(neighbor.name)
                if not remote_device:
                    print ('Remote device:', 'ip:', neighbor.ip_address, 'name:', neighbor.name, 'Not found')
                    continue

                source_interface = device.interfaces.get(local_if_index)
                if neighbor.if_id_type == 'index':
                    remote_interface = remote_device.interfaces.get(neighbor.if_id)
                elif neighbor.if_id_type == 'desc':
                    remote_interface = remote_device.get_interface_by_desc(neighbor.if_id)
                elif neighbor.if_id_type == 'mac':
                    remote_interface = remote_device.get_interface_by_mac(neighbor.if_id)
                elif neighbor.if_id_type == 'name':
                    remote_interface = remote_device.get_interface_by_name(neighbor.if_id)
                elif neighbor.if_id_type == 'local':
                    remote_interface = remote_device.get_interface_by_local_name(neighbor.if_id)
                else:
                    remote_interface = None
                if not remote_interface:
                    #import pdb;pdb.set_trace()
                    print ('Could not find interface {} on this device {}'.format(neighbor.if_id, neighbor))
                    pass
                    continue
                source_interface.remote_device = remote_device
                remote_interface.remote_device = device

                self.topology_graph[device][local_if_index] = (remote_device, remote_interface.index)
                self.topology_graph[remote_device][remote_interface.index] = (device, local_if_index)

        for key, device in self.servers.items():   
            for root_switch in self.switches.values():
                remote_info = self.find_connected_switch(root_switch, device)
                if remote_info:
                    remote_switch, remote_if_index = remote_info
                    self.topology_graph[device][device.if_index] = (remote_switch, remote_if_index)
                    self.topology_graph[remote_switch][remote_if_index] = (device, device.if_index)
                    break

        vm_by_name = {vm.name:vm for vm in self.vms.values()}
        for key, server in self.servers.items():
            for number, vm_name in enumerate(server.get_vm_names()):
                vm = vm_by_name.get(vm_name)
                if vm:
                    self.topology_graph[server][number] = (vm, None)
                    self.topology_graph[vm][number] = (server, None)




    def find_connected_switch(self, root_switch, device):
            print ('root_switch: ', root_switch,  'device: ', device)
            switch_if_index = root_switch.mac_address_table.get(device.mac_address)
            #check how many mac addess communicated via that interface
            mac_addresss_count = len(root_switch.mac_address_table_by_if_index.get(switch_if_index, []))
            if mac_addresss_count == 1:
                print ('found ' , root_switch)
                return root_switch, switch_if_index
            '''elif mac_addresss_count > 1:
                # in this case this interface could be uplink port
                # get the physical device that is connected to this interface from neighbor data
                uplink_device = root_switch.interfaces.get(switch_if_index).remote_device
                if uplink_device and uplink_device.DEVICE_TYPE == 'switch':
                    self.find_connected_switch(uplink_device, device)
            else:
                return '''

    @property
    def devices_by_ip_address(self):
        if not self._devices_by_ip_address:
            for key, device in self.all_devices.items():
                device_ips = device.get_all_ip_addresses()
                for ip in device_ips:
                    self._devices_by_ip_address[ip] = device
                else:
                    self._devices_by_ip_address[device.ip_address] = device
        return self._devices_by_ip_address

    @property
    def devices_by_name(self):
        if not self._devices_by_name:
            for key, device in self.all_devices.items():
                self._devices_by_name[device.name] = device
        return self._devices_by_name


if __name__ == '__main__':
    # TODO: for testing, remove later
    devices = [
{
'unique_id': '10.216.0.1',
 'ip_address': '10.216.0.1',
 'hostname': 'UL-AMS2-1EA35-FW-01',
 'manufacture':'juniper',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'firewall'
 },
{
'unique_id': '10.216.0.2',
 'ip_address': '10.216.0.2',
 'hostname': 'UL-AMS2-1EA35-SW-01.unitedlayer.com',
 'manufacture':'cisco',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'switch'
 },
{
'unique_id': '10.216.0.3',
 'ip_address': '10.216.0.3',
 'hostname': 'UL-AMS2-1EA35-SW-02',
 'manufacture':'cisco',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'switch'
 },
{
'unique_id': '10.216.0.4',
 'ip_address': '10.216.0.4',
 'hostname': 'UL-AMS2-1EA35-SW-03',
 'manufacture':'cisco',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'switch'
 },
{
'unique_id': '10.216.0.11',
 'ip_address': '10.216.0.11',
 'hostname': 'UL-AMS2-1EA35-HV-01',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 },
{
'unique_id': '10.216.0.12',
 'ip_address': '10.216.0.12',
 'hostname': 'UL-AMS2-1EA35-HV-02',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 },
{
'unique_id': '10.216.0.31',
 'ip_address': '10.216.0.31',
 'hostname': 'LT-AMS2-1EA35-ESX-01',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 },
{
'unique_id': '10.216.0.32',
 'ip_address': '10.216.0.32',
 'hostname': '10.216.0.32',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 },
{
'unique_id': '10.216.0.33',
 'ip_address': '10.216.0.33',
 'hostname': 'LT-AMS2-1EA35-ESX-03',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 },
{
'unique_id': '10.216.0.34',
 'ip_address': '10.216.0.34',
 'hostname': 'LT-AMS2-1EA35-ESX-04',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 },
{
'unique_id': '10.216.0.35',
 'ip_address': '10.216.0.35',
 'hostname': 'LT-AMS2-1EA35-ESX-05',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 },
{
'unique_id': '10.216.0.36',
 'ip_address': '10.216.0.36',
 'hostname': 'LT-AMS2-1EA35-ESX-06',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 
 },
{
'unique_id': '10.216.0.37',
 'ip_address': '10.216.0.37',
 'hostname': 'LT-AMS2-1EA35-ESX-07',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 
 },
{
'unique_id': '10.216.0.38',
 'ip_address': '10.216.0.38',
 'hostname': 'LT-AMS2-1EA35-ESX-08',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 
 },
{
'unique_id': '10.216.0.39',
 'ip_address': '10.216.0.39',
 'hostname': 'LT-AMS2-1EA35-ESX-09',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 },
{
'unique_id': '10.216.0.40',
 'ip_address': '10.216.0.40',
 'hostname': 'LT-AMS2-1EA35-ESX-10',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 },
{
'unique_id': '10.216.0.41',
 'ip_address': '10.216.0.41',
 'hostname': 'LT-AMS2-1EA35-ESX-11',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 },
{
'unique_id': '10.216.0.42',
 'ip_address': '10.216.0.42',
 'hostname': 'LT-AMS2-1EA35-ESX-12',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 },
{
'unique_id': '10.216.0.43',
 'ip_address': '10.216.0.43',
 'hostname': 'LT-AMS2-1EA35-ESX-13',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 },
{
'unique_id': '10.216.0.44',
 'ip_address': '10.216.0.44',
 'hostname': 'LT-AMS2-1EA34-ESX-14',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 },
{
'unique_id': '10.216.0.45',
 'ip_address': '10.216.0.45',
 'hostname': 'LT-AMS2-1EA34-ESX-14',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 },
{
'unique_id': '10.216.0.46',
 'ip_address': '10.216.0.46',
 'hostname': 'LT-AMS2-1EA35-ESX-16',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 },
{
'unique_id': '10.216.0.47',
 'ip_address': '10.216.0.47',
 'hostname': 'LT-AMS2-1EA35-ESX-17',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 },
{
'unique_id': '10.216.0.48',
 'ip_address': '10.216.0.48',
 'hostname': 'LT-AMS2-1EA35-ESX-18',
 'manufacture':'',
 'snmp_cred_index':0,
 'snmpversion': 0,
 'device_type': 'hypervisor'
 }
]
    snmp_cred_list = [{"cstring": "ul4ever", "version": 'SNMPv2'}, ]
    ssh_cred_list = [('uladmin', 'aEDq:c7y')]
    t = Topology(devices, snmp_cred_list, ssh_cred_list)
    t.find_topology()
    print (t.topology_graph)
    
