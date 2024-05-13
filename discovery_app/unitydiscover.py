import sys
import math
import easysnmp
import csv
import paramiko
import spur
import traceback
import winrm
import xlsxwriter
import uuid
import re
import json
import ipaddress
import datetime
import os
from datetime import datetime
from pathlib import Path
from collections import OrderedDict

from socket import *
from subprocess import PIPE, Popen
from concurrent.futures import ThreadPoolExecutor

from pysnmp.hlapi import *
from scapy.all import *

if sys.version_info[:2] >= (3, 8):  # pragma: no cover
    from collections.abc import Mapping, MutableMapping
else:  # pragma: no cover
    from collections import Mapping, MutableMapping

from celery.utils.log import get_task_logger
from django.utils import timezone

try:
    from .portscanner import scan_network
except ImportError:
    from portscanner import scan_network

logger = get_task_logger(__name__)

DEBUG = True
MAX_DISCOVERY_THREADS = 256

global_device_dict = {}
linux_machines = []
windows_machines = []

device_headers = ['hostname', 'ip_address', 'Location', 'manufacturer', 'model', 'OEMfirmwareversion', 'os', 'version',
                  'SerialNumber', 'device_type', 'CPU', 'Memory', 'DiskSize', 'Processor', 'IP SCAN', 'DNS',
                  'MacAddress', 'ListeningPorts', 'snmp', 'ssh', 'winrm', 'activedirectory', 'OStype', 'linux_ssh',
                  'windows_wrm', 'snmpversion', 'unique_id', 'snmp_cred_index', 'discovery_method', 'device_type_found',
                  'SysDescription', 'SystemInfo', 'Interfaces', 'uptime']

final_headers = ['hostname', 'ip_address', 'MacAddress', 'manufacturer', 'model', 'os', 'OStype', 'version',
                 'device_type', 'CPU', 'SerialNumber', 'Memory', 'DiskSize', 'Processor', 'unique_id', 'snmpversion',
                 'snmp_cred_index', 'discovery_method', 'snmp', 'device_type_found', 'SysDescription',
                 'Interfaces', 'uptime']


def get_windows_machines():
    device_types_exclude = ['switch','firewall', 'loadbalancer','hypervisor']
    return [e for e in global_device_dict if global_device_dict[e]['winrm'] and \
            global_device_dict[e]['device_type'] not in device_types_exclude \
            #and not(global_device_dict[e]['linux_ssh'])
            ]

def bytes_to_GB(bytes):
    bytes = str(bytes).strip()
    GB = int(bytes)/1024**3
    GB_str = math.ceil(GB)
    return str(GB_str) + ' GB'


def active_snmp_devices(snmp_auth_index):
    # return ['10.128.7.97', '10.128.7.80']
    # return ['10.128.7.1', '10.128.7.11', '10.128.7.12', '10.128.7.13', '10.128.7.14', '10.128.7.16', '10.128.7.24',
    #         '10.128.7.25', '10.128.7.32', '10.128.7.33', '10.128.7.34', '10.128.7.36', '10.128.7.37']
    # return ['10.128.7.1', '10.128.7.11', '10.128.7.12', '10.128.7.13', '10.128.7.14', '10.128.7.16', '10.128.7.24',
    #         '10.128.7.25', '10.128.7.32', '10.128.7.33', '10.128.7.34', '10.128.7.36', '10.128.7.37', '10.128.7.71',
    #         '10.128.7.74', '10.128.7.76', '10.128.7.78', '10.128.7.80']

    # return [k for k, v in global_device_dict.items()]
    return [k for k, v in global_device_dict.items() if global_device_dict[k]['snmp'] and global_device_dict[k]['snmp_cred_index'] == snmp_auth_index ]


def get_ssh_enabled():
    # return [e for e in global_device_dict]
    return [e for e in global_device_dict if global_device_dict[e]['ssh']]


def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return process.communicate()[0]


def run_command(ip_address, username, password, command):
    """ Connect to a device, run a command, and return the output."""

    ssh = paramiko.SSHClient()
    # Load SSH host keys.
    ssh.load_system_host_keys()
    # Add SSH host key when missing.
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    total_attempts = 1
    for attempt in range(total_attempts):
        try:
            print("Attempt to connect: %s %s" % (attempt,command) )
            # Connect to router using username/password authentication.
            ssh.connect(ip_address,
                        username=username,
                        password=password,
                        look_for_keys=False,
                        timeout=9
                        )
            # Run command.
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)
            # Read output from command.
            output = ssh_stdout.readlines()
            # Close connection.
            ssh.close()
            return output

        except Exception as error_message:
            if DEBUG:
                print("Unable to connect to linux ssh host %s %s " % (ip_address, command))
                print(error_message)
    # nothing worked
    return None


def get_arp_hosts(cidr_address):
    arp_dict = {}
    try:
        # IP Address for the destination
        # create ARP packet
        arp = ARP(pdst=cidr_address)
        # create the Ether broadcast packet
        # `ff:ff`:ff:ff:ff:ff MAC address indicates broadcasting
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        # stack them
        packet = ether / arp
        result = srp(packet, timeout=0.5, verbose=0)[0]

        for sent, received in result:
            arp_dict[received.psrc] = received.hwsrc

        arp_values_dict = {}
        for k, v in arp_dict.items():
            if v in arp_values_dict:
                arp_values_dict[v] += 1
            else:
                arp_values_dict[v] = 1

        # values to be deleted
        delete_ip_list = []
        for k, v in arp_dict.items():
            if arp_values_dict[v] > 1:
                delete_ip_list.append(k)

        for e in delete_ip_list:
            del arp_dict[e]
        return arp_dict
    except :
        return arp_dict


def get_icmp_alive_hosts(cidr_address):
    active_hosts = []

    #from concurrent.futures import ThreadPoolExecutor

    def get_icmp_status(ip):
        try:
            nonlocal active_hosts
            # icmp = IP(dst=str(ip), ttl=255) / ICMP()
            # resp = sr1(icmp, timeout=3, verbose=0)
            # if resp is not None:
            #     active_hosts.append(str(ip))

            response = os.system("ping -c 1 >/dev/null " + str(ip) )
            if response == 0:
                active_hosts.append(str(ip))

        except:
            traceback.print_exc()

    try:
        # Get all hosts on that network
        if '/' in cidr_address:
            all_hosts = list(ipaddress.ip_network(cidr_address, False).hosts())
        else:
            all_hosts = [ipaddress.ip_address(cidr_address)]

        # Create a thread pool with 4 threads
        with ThreadPoolExecutor(max_workers=MAX_DISCOVERY_THREADS) as executor:
            for ip in all_hosts:
                executor.submit(get_icmp_status, ip)
        active_hosts.sort(key = lambda x: ''.join(['%03d'%int(e) for e in  x.split('.')]) )
        print ('Active hosts are ... ')
        print (active_hosts)
        return active_hosts
    except:
        traceback.print_exc()
        return []


def get_host_status_with_icmp(devices_to_ping):
    total_active_hosts = {}

    def get_icmp_status(device):
        try:
            nonlocal total_active_hosts
            device_key = device['type'] + '-' + device['id']
            ip = device['ip']
            response = os.system("ping -c 1 >/dev/null " + str(ip))
            total_active_hosts[device_key] = {'ip': ip, 'type': device['type'], 'id': device['id'],
                                              'last_status': device['last_status'] if 'last_status' in device else None}

            if response == 0:
                total_active_hosts[device_key]['current_status'] = True
            else:
                total_active_hosts[device_key]['current_status'] = False
            total_active_hosts[device_key]['last_updated_on'] = str(datetime.now())
        except Exception as e:
            traceback.print_exc()
    try:
        # Create a thread pool with 4 threads
        with ThreadPoolExecutor(max_workers=MAX_DISCOVERY_THREADS) as executor:
            for key, device in devices_to_ping.items():
                executor.submit(get_icmp_status, device)
        return total_active_hosts
    except Exception as e:
        traceback.print_exc(e)
        return []


def run_discovery(cidr_address):
    if not cidr_address:
        return None

    # First try arp
    #arp_host_dict = get_arp_hosts(cidr_address) or {}
    arp_host_dict = {}

    # Second try icmp
    active_ip = get_icmp_alive_hosts(cidr_address)

    for e in active_ip:
        if e not in arp_host_dict:
            arp_host_dict[e] = ''
        try:
            arp_host_dict[e] = getmacbyip(e)
        except :
            pass

    for ip_addr, mac_addr in arp_host_dict.items():
        global_device_dict[ip_addr] = dict.fromkeys(device_headers, '')
        # defacto copy the ip and mac address
        global_device_dict[ip_addr]['MacAddress'] = mac_addr
        global_device_dict[ip_addr]['ip_address'] = ip_addr
        global_device_dict[ip_addr]['unique_id'] = str(uuid.uuid4())
    # final dict built
    return global_device_dict


def get_pysnmp_oid_value(hostname,**kwargs,):
    try:
        if kwargs['version'] == 1:
            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(SnmpEngine(),
                       CommunityData(kwargs['community'], mpModel=0),
                       UdpTransportTarget((hostname, 161),timeout=5, retries=2),
                       ContextData(),
                       ObjectType(ObjectIdentity(*kwargs['oids']))
                       )
            )
        elif kwargs['version'] == 2 :
            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(SnmpEngine(),
                       CommunityData(kwargs['community'], mpModel=1),
                       UdpTransportTarget((hostname, 161),timeout=5, retries=2),
                       ContextData(),
                       ObjectType(ObjectIdentity(*kwargs['oids']))
                       )
            )
        elif kwargs['version'] == 3:
            sec_level = kwargs['security_level']
            if sec_level == "NoAuthNoPriv":
                errorIndication, errorStatus, errorIndex, varBinds = next(
                    getCmd(SnmpEngine(),
                           UsmUserData('usr-none-none'),
                           UdpTransportTarget((hostname, 161)),
                           ContextData(),
                           ObjectType(ObjectIdentity(*kwargs['oids']))
                ))
            elif sec_level == "AuthNoPriv":
                if "sha" in kwargs['auth_protocol'].lower():
                    authProtocol = usmHMACSHAAuthProtocol
                else:
                    authProtocol = usmHMACMD5AuthProtocol

                if "aes" in kwargs['privacy_protocol'].lower():
                    privProtocol = usmAesCfb128Protocol
                else :
                    privProtocol = usmDESPrivProtocol

                if "sha" in kwargs['auth_protocol'].lower():
                    user_name = 'usr-sha-none'
                else:
                    user_name = 'usr-md5-none'

                errorIndication, errorStatus, errorIndex, varBinds = next(
                    getCmd(SnmpEngine(),
                           # UsmUserData(kwargs['security_username'], kwargs['auth_password'], authProtocol= authProtocol, privProtocol = privProtocol),
                           UsmUserData(user_name, kwargs['auth_password'], authProtocol= authProtocol, privProtocol = privProtocol),
                           UdpTransportTarget((hostname, 161)),
                           ContextData(),
                           ObjectType(ObjectIdentity(*kwargs['oids'])))
                )
            else :
                if "sha" in kwargs['auth_protocol'].lower():
                    authProtocol = usmHMACSHAAuthProtocol
                else:
                    authProtocol = usmHMACMD5AuthProtocol

                if "aes" in kwargs['privacy_protocol'].lower():
                    privProtocol = usmAesCfb128Protocol
                else :
                    privProtocol = usmDESPrivProtocol

                errorIndication, errorStatus, errorIndex, varBinds = next(
                    getCmd(SnmpEngine(),
                           UsmUserData(kwargs['security_username'], kwargs['auth_password'], kwargs['privacy_password'],
                                       authProtocol= authProtocol, privProtocol = privProtocol),
                           UdpTransportTarget((hostname, 161)),
                           ContextData(),
                           ObjectType(ObjectIdentity(*kwargs['oids'])))
                )

        value_list = []
        if errorIndication:
            print(f"Error: {errorIndication}")
        elif errorStatus:
            print(f"Error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}")
        else:
            for varBind in varBinds:
                oid_value = varBind.prettyPrint().split('=')[1].strip()
                excluded_words = ["no such", "oid","nosuchname"]
                if not any(  e in oid_value.lower()  for e in excluded_words ) :
                    value_list.append(oid_value)
        return value_list
    except Exception as ex:
        print ('+' * 24)
        print ('get_pysnmp_oid_value failed !!')
        print (ex)
        print ('-' * 24)
        return None


def update_snmp_sysdescription(snmp_index_pos, **kwargs):
    def sub_update_snmp_sysdescription(eachip, **kwargs):
        # must be called first to set the snmp flag for further calls
        try:
            # return if snmp is already figured out
            if global_device_dict[eachip]['snmp']:
                return None

            kwargs.update(dict(oids= ['SNMPv2-MIB', 'sysDescr', 0], hostname=eachip))
            sysdec_info_result = get_pysnmp_oid_value(**kwargs)


            if sysdec_info_result:
                # update the values to mention that the snmp went well
                global_device_dict[eachip]['snmp'] = 1
                global_device_dict[eachip]['snmp_cred_index'] = snmp_index_pos
            else :
                global_device_dict[eachip]['snmp'] = 0
                global_device_dict[eachip]['snmp_cred_index'] = snmp_index_pos
                return None

            # check the length
            if len(sysdec_info_result):
                sysdec_info = sysdec_info_result[0]
                sysdec_info_l = sysdec_info.lower()
            else:
                sysdec_info = ''
                sysdec_info_l = ''

            # any thing big then update
            if len(sysdec_info_l) > len(global_device_dict[eachip]['SysDescription']):
                global_device_dict[eachip]['SysDescription'] = sysdec_info


            if global_device_dict[eachip]['snmp']:
                global_device_dict[eachip]['discovery_method'] += 'snmp'
            # snmp version
            global_device_dict[eachip]['snmpversion'] = kwargs['version']

            # this is for internal purpose
            # for our internal codevice
            if "windows" in sysdec_info_l:
                global_device_dict[eachip]['OStype'] = "windows"
            elif "linux" in sysdec_info_l:
                global_device_dict[eachip]['OStype'] = "linux"
            elif "mac" in sysdec_info_l:
                global_device_dict[eachip]['OStype'] = "mac os"
            elif "ios" in sysdec_info_l:
                global_device_dict[eachip]['OStype'] = "linux"
            elif "novell" in sysdec_info_l:
                global_device_dict[eachip]['OStype'] = "novell netware"
            elif "junos" in sysdec_info_l:
                global_device_dict[eachip]['OStype'] = "junos os"
            elif "ubuntu" in sysdec_info_l:
                global_device_dict[eachip]['OStype'] = "linux"
            elif "debian" in sysdec_info_l:
                global_device_dict[eachip]['OStype'] = "linux"
            elif "esxi" in sysdec_info_l:
                global_device_dict[eachip]['OStype'] = "esxi"

        except Exception as ex:
            traceback.print_exc()
            if DEBUG:
                print('update_snmp_sysdescription:: Tried to connect to  ' + eachip)
                print(ex)
                print('*' * 24)
    # # actual execution
    with ThreadPoolExecutor(max_workers=MAX_DISCOVERY_THREADS) as executor:
        for eachip in global_device_dict:
           executor.submit(sub_update_snmp_sysdescription, eachip, **kwargs)


def update_hostname_details(snmp_auth_index, **kwargs):
    def sub_update_hostname_details(eachip, **kwargs):
        try:
            if global_device_dict[eachip]['hostname']:
                return None

            kwargs.update(dict(oids=['SNMPv2-MIB', 'sysName', 0], hostname=eachip))
            hostname = get_pysnmp_oid_value(**kwargs)

            if not hostname or not len(hostname[0]):
                return None

            global_device_dict[eachip]['hostname'] = hostname[0]

        except Exception as ex:
            traceback.print_exc()
            if DEBUG:
                print('Hostname not found in ' + eachip)
                print(ex)
                print('%' * 24)

    # actual execution
    with ThreadPoolExecutor(max_workers=MAX_DISCOVERY_THREADS) as executor:
        for eachip in active_snmp_devices(snmp_auth_index):
           executor.submit(sub_update_hostname_details, eachip, **kwargs)


def update_snmp_serialnumber(snmp_auth_index, **kwargs):
    def sub_update_snmp_serialnumber(eachip, **kwargs):
        try:
            # # for serial number via snmp walk
            kwargs.update(dict(oids=['iso.3.6.1.2.1.47.1.1.1.1.11.1'], hostname=eachip))
            serial_number_result = get_pysnmp_oid_value(**kwargs)
            if not serial_number_result or not len(serial_number_result[0]) :
                return None
            serialnumber_info = serial_number_result[0]
            global_device_dict[eachip]['SerialNumber'] = serialnumber_info
            # print ('Serial number is %s '%serialnumber_info)

        except Exception as ex:
            traceback.print_exc()
            if DEBUG:
                print('Serial Number not in ' + eachip)
                print(ex)
                print('%' * 24)

    # actual execution
    with ThreadPoolExecutor(max_workers=MAX_DISCOVERY_THREADS) as executor:
        for eachip in active_snmp_devices(snmp_auth_index):
           executor.submit(sub_update_snmp_serialnumber, eachip, **kwargs)


def update_snmp_interfaces(snmp_auth_index, **kwargs):
    def sub_update_snmp_interfaces(eachip, **kwargs):
        try:
            kwargs.update(dict(oids='1.3.6.1.2.1.31.1.1.1.1', hostname=eachip))
            interface_name_result = fetch_snmpwalk_oid_data(**kwargs)

            kwargs.update(dict(oids='1.3.6.1.2.1.2.2.1.3', hostname=eachip))
            interface_type_result = fetch_snmpwalk_oid_data(**kwargs)

            kwargs.update(dict(oids='1.3.6.1.2.1.2.2.1.2', hostname=eachip))
            interface_description_result = fetch_snmpwalk_oid_data(**kwargs)

            kwargs.update(dict(oids='1.3.6.1.2.1.2.2.1.8', hostname=eachip))
            interface_status_result = fetch_snmpwalk_oid_data(**kwargs)

            kwargs.update(dict(oids='1.3.6.1.2.1.2.2.1.6', hostname=eachip))
            interface_mac_result = fetch_snmpwalk_oid_data(**kwargs)

            interface_info = prepare_interface_data(interface_name_result, interface_description_result,
                                                    interface_type_result, interface_status_result,
                                                    interface_mac_result)
            global_device_dict[eachip]['Interfaces'] = interface_info

        except Exception as ex:
            traceback.print_exc()
            if DEBUG:
                print('Interface not in ' + eachip)
                print(ex)
                print('%' * 24)

    with ThreadPoolExecutor(max_workers=MAX_DISCOVERY_THREADS) as executor:
        for eachip in active_snmp_devices(snmp_auth_index):
            executor.submit(sub_update_snmp_interfaces, eachip, **kwargs)


def update_uptime_details(snmp_auth_index, **kwargs):
    def sub_update_uptime_details(eachip, **kwargs):
        try:
            kwargs.update(dict(oids='1.3.6.1.2.1.1.3.0', hostname=eachip))
            uptime = get_pysnmp_oid_value(**kwargs)
            if not uptime or not len(uptime[0]) :
                return None
            uptime_info = uptime[0]
            if uptime_info:
                value = uptime_info.split(')')
                if isinstance(value, list):
                    value = value[1].lstrip()
                else:
                    value = ''
            global_device_dict[eachip]['uptime'] = value

        except Exception as ex:
            traceback.print_exc()
            if DEBUG:
                print('Uptime details not in ' + eachip)
                print(ex)
                print('%' * 24)

    with ThreadPoolExecutor(max_workers=MAX_DISCOVERY_THREADS) as executor:
        for eachip in active_snmp_devices(snmp_auth_index):
            executor.submit(sub_update_uptime_details, eachip, **kwargs)


def fetch_snmpwalk_oid_data(**kwargs):
    if kwargs['version'] == 3:
        if kwargs['security_level'] == 'noAuthNoPriv':
            priv_prot = 'noAuthNoPriv'
        elif kwargs['security_level'] == 'authNoPriv':
            priv_prot = 'authNoPriv'
        elif kwargs['security_level'] == 'authPriv':
            priv_prot = 'authPriv'

        cmd_args = (priv_prot, kwargs['security_username'], kwargs['auth_protocol'], kwargs['auth_password'],
                    kwargs['privacy_protocol'], kwargs['privacy_password'], kwargs['hostname'], kwargs['oids'])
        command_str = 'snmpwalk -v3  -l %s -u %s -a %s -A %s  -x %s -X %s %s %s'
        command = command_str % cmd_args
    elif kwargs['version'] == 2:
        command = 'snmpwalk -v2c -c %s %s %s -One' % (kwargs['community'], kwargs['hostname'], kwargs['oids'])
    elif kwargs['version'] == 1:
        command = 'snmpwalk -v1 -c %s %s %s -One' % (kwargs['community'], kwargs['hostname'], kwargs['oids'])

    try:
        output = cmdline(command)
        if output:
            output_str = output.decode("utf-8")
            if " \n" in output_str:
                output_data = output_str.split(" \n")
            elif "\n" in output_str:
                output_data = output_str.split("\n")
            else:
                output_data = output_str
            return output_data
        return None
    except Exception as ex:
        if DEBUG:
            print("update_memory_and_disk_capacity failed for " + kwargs['hostname'])
            print(ex)
            print('-' * 24)


def prepare_interface_data(name_list, desc_list, type_list, status_list, mac_list):
    interface_list = list()
    name_data = prepare_json_data(name_list)
    description_data = prepare_json_data(desc_list)
    type_data = prepare_json_data(type_list)
    status_data = prepare_json_data(status_list)
    mac_data = prepare_json_data(mac_list)
    for key, item in name_data.items():
        interface_dict = {'name': name_data[key],
                          'description': description_data[key] if key in description_data else "",
                          'type': type_data[key] if key in type_data else None,
                          'status': status_data[key] if key in status_data else None,
                          'mac_address': mac_data[key] if key in mac_data else None}
        interface_list.append(interface_dict)

    return str(interface_list)


def prepare_json_data(data):
    data_dict = dict()
    if isinstance(data, list):
        for item in data:
            item_array = item.split(" = ")
            key = item_array[0].split(".")[-1]
            if len(item_array) > 1 and ":" in item_array[1]:
                if "Hex-STRING: " in item_array[1]:
                    value = item_array[1].replace("Hex-STRING: ", "")
                else:
                    value = item_array[1].replace("STRING: ", "").replace("INTEGER: ", "") \
                        if item_array[1] and item_array[1] != '""' else None
                    try:
                        value = eval(value)
                    except:
                        value= value
            else:
                value = None
            data_dict[key] = value
    elif data:
        item_array = data.split(" = ")
        key = item_array[0].split(".")[-1]
        if len(item_array) > 1 and ":" in item_array[1]:
            if "Hex-STRING: " in item_array[1]:
                value = item_array[1].replace("Hex-STRING: ", "")
            else:
                value = item_array[1].replace("STRING: ", "").replace("INTEGER: ", "") if item_array[1] else None
                try:
                    value = eval(value)
                except:
                    value = value
        else:
            value = None
        data_dict[key] = value
    return data_dict


def update_linux_details(ssh_cred_list):
    def sub_update_linux_details(ip, ssh_cred_list):
        for iindex, (uname, passwd) in enumerate(ssh_cred_list):
            # if the ssh in already connected ignore it
            if global_device_dict[ip]['linux_ssh']:
                continue

            # Run check for linux or not
            try:
                router_output = run_command(ip, uname, passwd, "ls")
                linux_check = str(router_output)
                invalid_conditions = ["unknown", "recognized", "not", "error","invalid"]
                not_linux = False
                for anyinvalid in invalid_conditions:
                    if anyinvalid.lower() in linux_check.lower():
                        print("ssh successful but not linux system -%s"%ip)
                        not_linux = True
                        break

                if not_linux:
                    continue
                else:
                    global_device_dict[ip]['ssh'] = 1
                    global_device_dict[ip]['discovery_method'] += 'ssh,'

            except Exception as ex:
                if DEBUG:
                    print(ex)
                    print('Linux remote failed for linux check %s' % ip)
                continue

            try:
                command = "which df &>/dev/null &&  df -P -B G | awk 'NR>2{sum+=$2}END{print sum}'"
                router_output = run_command(ip, uname, passwd, command)
                # Analyze show ip route output
                # Make sure we didn't receive empty output.
                if router_output != None:
                    disksize = router_output[0]
                    global_device_dict[ip]['DiskSize'] = str(disksize) + ' GB'

                    # the index of the successful ssh connection
                    global_device_dict[ip]['linux_ssh'] = '1' + '-' + str(iindex)
            except Exception as ex:
                if DEBUG:
                    print(ex)
                    print('Linux remote failed for disksize %s' % ip)

            # don't continue if the linux ssh is not good
            if not global_device_dict[ip]['linux_ssh']:
                break

            # processor
            try:
                command = "which cat  &>/dev/null && which uniq  &>/dev/null && which grep  &>/dev/null && which head  &>/dev/null &&  cat /proc/cpuinfo | uniq | grep 'model name' |  head -1"
                router_output = run_command(ip, uname, passwd, command)
                if router_output != None:
                    kk = router_output[0]
                    global_device_dict[ip]['Processor'] = kk.split(':')[1]
            except Exception as ex:
                if DEBUG:
                    print(ex)
                    print('Linux remote failed for cpuinfo %s' % ip)

            # SystemInfo
            try:
                router_output = run_command(ip, uname, passwd, "lscpu")
                if router_output != None:
                    global_device_dict[ip]['SystemInfo'] = str(router_output)
            except Exception as ex:
                if DEBUG:
                    print(ex)
                    print('Linux remote failed for %s' % ip)

            # hostname
            try:
                command = "which hostname &>/dev/null && hostname"
                router_output = run_command(ip, uname, passwd,command )
                if router_output != None:
                    if not global_device_dict[ip]['hostname']:
                        global_device_dict[ip]['hostname'] = str(
                            router_output[0].replace('\r', '').replace('\n', '').replace('\\r', '').replace('\\n', ''))
            except Exception as ex:
                if DEBUG:
                    print(ex)
                    print('Linux remote failed for hostname %s ' % ip)

            # serialnumber abhinav
            # dmidecode -s system-serial-number
            try:
                print("serial number try ")
                command = "which dmidecode &>/dev/null && dmidecode -s system-serial-number"
                router_output = run_command(ip, uname, passwd, command)
                if router_output != None:
                    if not global_device_dict[ip]['SerialNumber']:
                        global_device_dict[ip]['SerialNumber'] = str(
                            router_output[0].replace('\r', '').replace('\n', '').replace('\\r', '').replace('\\n', ''))

            except Exception as ex:
                if DEBUG:
                    print(ex)
                    print('Linux remote failed for hostname %s ' % ip)

            # memory
            try:
                command = """ which awk &>/dev/null && which column &>/dev/null && which grep &>/dev/null && awk '$3=="kB"{$2=$2/1024^2;$3="GB";} 1' /proc/meminfo | column -t | grep MemTotal """
                router_output = run_command(ip, uname, passwd, command)
                if router_output != None:
                    if not global_device_dict[ip]['Memory']:
                        memory = router_output[0].split(':')[1]
                        memory = memory.replace('\r', '').replace('\n', '').replace('\\r', '').replace('\\n', '')
                        GBmemory = memory.split()[0]
                        GBmemory = math.ceil(float(GBmemory))
                        global_device_dict[ip]['Memory'] = str(GBmemory) + ' GB'
            except Exception as ex:
                if DEBUG:
                    print(ex)
                    print('Linux remote failed for Memory %s' % ip)

            # number of cpu core
            try:
                command = " which grep &>/dev/null && which uniq &>/dev/null && grep 'cpu cores' /proc/cpuinfo | uniq"
                router_output = run_command(ip, uname, passwd, command)
                if router_output != None:
                    if not global_device_dict[ip]['CPU']:
                        cpu = router_output[0].split(':')[1]
                        cpu = cpu.replace('\r', '').replace('\n', '').replace('\\r', '').replace('\\n', '')
                        global_device_dict[ip]['CPU'] = cpu
            except Exception as ex:
                if DEBUG:
                    print(ex)
                    print('Linux remote failed for cpucores %s' % ip)

            # OS-Version hostnamectl | grep Operating

            try:
                command = " which hostnamectl &>/dev/null && hostnamectl"
                router_output = run_command(ip, uname, passwd, command)
                attr_map = {}
                for el in router_output:
                    el = el.strip()
                    el = re.sub(r"[\n\t]*", "", el)
                    k, val = el.split(":")
                    attr_map[k] = valQ

                hostname = attr_map.get('Static hostname')
                host_os = attr_map.get('Operating System')
                device_type = ''
                if attr_map.get('Chassis', '') == 'vm':
                    device_type = 'virtual_machine'
                elif attr_map.get('Chassis', '') == 'server':
                    device_type = 'baremetalserver'

                version_pattern = r'\d+(=?\.(\d+(=?\.(\d+)*)*)*)*'
                regex_matcher = re.compile(version_pattern)
                version = regex_matcher.search(host_os).group(0)

                if not global_device_dict[ip]['hostname']:
                    global_device_dict[ip]['hostname'] = hostname
                if not global_device_dict[ip]['os']:
                    global_device_dict[ip]['os'] = host_os
                if not global_device_dict[ip]['version']:
                    global_device_dict[ip]['version'] = version
                if not global_device_dict[ip]['device_type']:
                    global_device_dict[ip]['device_type'] = device_type

            except Exception as ex:
                if DEBUG:
                    print(ex)
                    print('Linux remote failed for %s' % ip)

            try:
                command = " which grep &>/dev/null && which awk &>/dev/null &&  df | grep '^/dev/[hs]d' | awk '{s+=$2} END {print s/1048576}'"
                router_output = run_command(ip, uname, passwd, command)
                disksize = re.sub(r"[\n\t]*", "", str(router_output[0]))
                if not global_device_dict[ip]['DiskSize']:
                    global_device_dict[ip]['DiskSize'] = str(disksize) + ' GB'
            except Exception as ex:
                if DEBUG:
                    print(ex)
                    print('Linux remote failed for %s' % ip)

            # common for m
            excluded_manufacturer = ['vmware']
            try:
                command = "ls /sys/devices/virtual/dmi/id/sys_vendor &>/dev/null && cat /sys/devices/virtual/dmi/id/sys_vendor"
                router_output = run_command(ip, uname, passwd, command)

                if not global_device_dict[ip]['manufacturer']:
                    if len(router_output) and not any( e in router_output[0].lower() for e in excluded_manufacturer):
                        global_device_dict[ip]['manufacturer'] = router_output[0].strip()

            except Exception as ex:
                if DEBUG:
                    print(ex)
                    print('Linux remote failed for %s' % ip)

            try:
                command = "ls /sys/devices/virtual/dmi/id/product_name &>/dev/null && cat /sys/devices/virtual/dmi/id/product_name"
                router_output = run_command(ip, uname, passwd, command)
                if not global_device_dict[ip]['model'] and not any( e in router_output[0].lower() for e in excluded_manufacturer):
                    global_device_dict[ip]['model'] = router_output[0].strip()
            except Exception as ex:
                if DEBUG:
                    print(ex)
                    print('Linux remote failed for %s' % ip)

            # Code to get details for ESXi devices
            command = 'which esxcli &>/dev/null && esxcli'
            router_output = run_command(ip, uname, passwd, command)
            if len(router_output):
                global_device_dict[ip]['device_type'] = 'hypervisor'

            try:
                command = 'vmware -v'
                router_output = run_command(ip, uname, passwd, command)
                str_op = router_output[0].strip()
                str_op = re.sub(r"[\n\t\"]*", "", str_op)
                os_fname, os_lname, version, _ = str_op.split()
                host_os = f"{os_fname} {os_lname}"
                print ( "VMWare host name is %s"%(host_os))

                if not global_device_dict[ip]['os']:
                    global_device_dict[ip]['os'] = host_os
                if not global_device_dict[ip]['version']:
                    global_device_dict[ip]['version'] = version
            except Exception as ex:
                print(ex)
                print('vmware -v failed for %s' % (ip))

            #get serial number of esxi
            # esxcfg-info | grep -w "Serial Number"
            try:
                command = 'which esxcfg-info &>/dev/null && which grep &>/dev/null && esxcfg-info | grep -w "Serial Number"'
                router_output = run_command(ip, uname, passwd, command)
                str_op = router_output[0].strip()
                str_op = re.sub(r"[\n\t\"]*", "", str_op)
                global_device_dict[ip]['SerialNumber'] = str_op

            except Exception as ex:
                print(ex)
                print('esxcfg-info failed for %s' % (ip))

            try:
                command = "which smbiosDump &>/dev/null && which grep &>/dev/null && smbiosDump |grep -A 5 'System Info' "
                router_output = run_command(ip, uname, passwd, command)
                attr_map = {}
                for el in router_output:
                    el = el.strip()
                    el = re.sub(r"[\n\t\"]*", "", el)
                    k, val = el.split(":")
                    attr_map[k] = val.strip()

                if not global_device_dict[ip]['manufacturer']:
                    global_device_dict[ip]['manufacturer'] = attr_map.get('Manufacturer')
                if not global_device_dict[ip]['model']:
                    global_device_dict[ip]['model'] = attr_map.get('Product')
            except Exception as ex:
                print(ex)
                print('smbiosDump failed for %s' % (ip))

            try:
                command = 'esxcli hardware cpu global get|grep \'CPU Cores\''
                router_output = run_command(ip, uname, passwd, command)
                str_op = re.sub(r"[\n\t]*", "", router_output[0].strip())

                if not global_device_dict[ip]['CPU']:
                    global_device_dict[ip]['CPU'] = str_op.split()[-1]
            except Exception as ex:
                print(ex)
                print('esxcli hardware cpu global failed for %s' % (ip))

            try:
                command = "which smbiosDump &>/dev/null && which grep &>/dev/null && smbiosDump | grep -A 12 'Memory Device'"
                router_output = run_command(ip, uname, passwd, command)
                size = 0
                unit = ''
                for el in router_output:
                    el = el.strip()
                    el = re.sub(r"[\n\t\"]*", "", el)
                    if el == '--':
                        continue
                    k, val = el.split(": ")
                    if k == 'Size' and re.search(r'\d', val):
                        size += int(val.split()[0])
                        if not unit:
                            unit = val.split()[1]

                if not global_device_dict[ip]['Memory']:
                    global_device_dict[ip]['Memory'] = f"{size} {unit}"
            except Exception as ex:
                print(ex)
                print('smbiosDump grep memory failed for %s' % (ip))

            try:
                command = 'smbiosDump |grep -A 20 \'Processor Info\''
                router_output = run_command(ip, uname, passwd, command)
                attr_map = {}
                for el in router_output:
                    el = el.strip()
                    el = re.sub(r"[\n\t\"]*", "", el)

                    if el == '--':
                        continue
                    k, val = el.split(":")
                    attr_map[k] = val.strip()

                if not global_device_dict[ip]['Processor']:
                    global_device_dict[ip]['Processor'] = attr_map.get('Version')
            except Exception as ex:
                print(ex)
                print('smbiosDump processor info failed for %s' % (ip))
            try:
                command = "which df &>/dev/null && which awk &>/dev/null && df -h | awk '{print $2}'"
                router_output = run_command(ip, uname, passwd, command)
                print(router_output)
                unit_map = {
                    'B': 1/1000000000,
                    'K': 1/1000000,
                    'M': 1/1000,
                    'G': 1.0,
                    'T': 1000
                }
                total_size_gb = 0
                for el in router_output[1:]:
                    el = el.strip()
                    el = re.sub(r"[\n\t\"]*", "", el)
                    unit = el[-1]
                    size_gb = float(el[:-1]) * unit_map.get(unit)
                    total_size_gb += size_gb

                if not global_device_dict[ip]['DiskSize']:
                    global_device_dict[ip]['DiskSize'] = round(total_size_gb, 2)
            except Exception as ex:
                print(ex)
                print('df remote failed for %s' % (ip))


    # for ip in get_ssh_enabled():
    #    sub_update_linux_details( ip,ssh_cred_list )

    with ThreadPoolExecutor(max_workers=MAX_DISCOVERY_THREADS) as executor:
        for ip in get_ssh_enabled():
           executor.submit(sub_update_linux_details, ip,ssh_cred_list )


def run_windows_power_shell(windows_cred_list):
    # set the following commands
    # winrm set winrm/config/client/auth '@{Basic="true"}'
    # winrm set winrm/config/service/auth '@{Basic="true"}'
    # winrm set winrm/config/service @{AllowUnencrypted="true"}

    for eachip in get_windows_machines():
        for username, password in windows_cred_list:
            try:
                s = winrm.Session(eachip, auth=(username, password))
                r = s.run_cmd('ipconfig', ['/all'])
                # r = s.run_cmd('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe Get-ComputerInfo')
                if r.std_out:
                    print(r.std_out)
                    global_device_dict[eachip]['winrm'] = 1
            except Exception as ex:
                if DEBUG:
                    print(ex)
                    print(' windows  shell command not working for %s', eachip)


def get_year_month_day_dir(basedir):
    t = timezone.datetime.today()
    ymd = '%d/%02d/%02d'%(t.year,t.month,t.day)
    fpath = os.path.join(basedir, ymd)
    Path(fpath).mkdir(parents=True, exist_ok=True)
    return fpath

def create_csv_with_fields(cidr_addr):
    ymd_dir = get_year_month_day_dir("logs/xlsx")
    now_time = timezone.datetime.now().strftime("%m-%d-%Y-%H:%M:%S")
    file_name = "%s/UD-%s-%s.xlsx"%(ymd_dir, now_time,cidr_addr.replace('/',"--"))
    workbook = xlsxwriter.Workbook(file_name)
    worksheet = workbook.add_worksheet("Discovered Devices")

    # Writing to row and column respectively
    worksheet.write_row(0, 0, device_headers)

    row = 1
    for k, v in global_device_dict.items():
        row_value = [v[ee] for ee in device_headers]
        worksheet.write_row(row, 0, row_value)
        row += 1

    workbook.close()


def scan_ports_and_load():
    ## https://docs.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/configure-winrm-for-https#more-information
    snmp_list=[161]
    ssh_list = [22]
    winrm_list = [80, 443, 5985, 5986]
    def_port_list = ssh_list + winrm_list + snmp_list
    for eachip in global_device_dict:
        port_result_dict = scan_network(eachip, def_port_list, range(5))
        ports_open_found = port_result_dict[eachip]
        ports_open_found.sort()
        ports_open_string = ','.join([str(e) for e in ports_open_found])
        global_device_dict[eachip]['ListeningPorts'] = ports_open_string

        if 22 in ports_open_found:
            global_device_dict[eachip]['ssh'] = 1
            #global_device_dict[eachip]['discovery_method'] += 'ssh,'

        if any(e in ports_open_found for e in winrm_list):
            global_device_dict[eachip]['winrm'] = 1
            # global_device_dict[eachip]['discovery_method'] += 'winrm,'

# NOT USED CURRENTLY
def update_memory_and_disk_capacity(**kwargs):
    for eachip in active_snmp_devices():

        if global_device_dict[eachip]['Memory']:
            continue
        if kwargs['version'] == 3 :
            if kwargs['security_level'] == 'noAuthNoPriv':
                priv_prot = 'noAuthNoPriv'
            elif kwargs['security_level'] == 'authNoPriv':
                priv_prot = 'authNoPriv'
            elif kwargs['security_level'] == 'authPriv':
                priv_prot = 'authPriv'

            cmd_args = (priv_prot, kwargs['security_username'], kwargs['auth_protocol'], kwargs['auth_password'],
                        kwargs['privacy_protocol'], kwargs['privacy_password'], eachip)

            command_str = 'snmpwalk -v3  -l %s -u %s -a %s -A %s  -x %s -X %s %s UCD-SNMP-MIB::memory | grep memTotalReal.0'
            command = command_str % cmd_args
        elif kwargs['version'] == 2 :
            command = 'snmpwalk -v2c -c %s %s UCD-SNMP-MIB::memory | grep memTotalReal.0' % (
            kwargs['community'], eachip)
        elif kwargs['version'] == 1 :
            command = 'snmpwalk -v1 -c %s %s UCD-SNMP-MIB::memory | grep memTotalReal.0' % (
            kwargs['community'], eachip)

        try:
            output = cmdline(command)
            if len(output):
                # print("memReal found is ::" + output)
                total_memory = str(output).split('INTEGER:')[1].replace('\\n', '').replace('\n', '').replace('\\r',
                                                                                                             '').replace(
                    '\r', '')
                global_device_dict[eachip]['Memory'] = total_memory
        except Exception as ex:
            if DEBUG:
                print("update_memory_and_disk_capacity failed for " + eachip)
                print(ex)
                print('-' * 24)


def update_windows_details(windows_cred_list):
    # set the following commands
    # winrm set winrm/config/client/auth '@{Basic="true"}'
    # winrm set winrm/config/service/auth '@{Basic="true"}'
    # winrm set winrm/config/service @{AllowUnencrypted="true"}
    # windows_machines = ['10.128.7.80']
    #  good

    def sub_update_windows_details(ip,windows_cred_list):
        for uname, passwd in windows_cred_list:
            #if global_device_dict[ip]['linux_ssh']:
            #    break

            try:
                s = winrm.Session(ip, auth=(uname, passwd))

               # preliminary check to make sure the box is windows
               # r = s.run_cmd('invalidcommand')
               # if r.std_out:
               #     aa = r.std_out
               #     aa = str(aa)
               #     if not 'batch file.' in aa.lower():
               #         print(' not Continuing  with this windows instance %s #1' % ip)
               #         continue
               # else:
               #     print(' not Continuing  with this windows instance %s #2'%ip)
               #     continue

                r = s.run_cmd('WMIC.exe computersystem get totalphysicalmemory')
                # r = s.run_cmd('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe Get-ComputerInfo')
                if r.std_out:
                    aa = r.std_out
                    Memory = str(aa).split()[1].replace('\\r', '').replace('\\n', '').replace('\r', '').replace('\n', '')
                    global_device_dict[ip]['Memory'] = bytes_to_GB(Memory)
                    global_device_dict[ip]['discovery_method'] += 'winrm,'

                r = s.run_cmd('systeminfo.exe')
                if r.std_out:
                    aa = r.std_out
                    kk = str(aa).replace('\r', '').replace('\n', '').replace('\\r', '').replace('\\n', '').split()
                    disk_str = ','.join(kk[1:])
                    global_device_dict[ip]['SystemInfo'] = disk_str

                r = s.run_cmd('WMIC.exe cpu get name')
                if r.std_out:
                    aa = r.std_out
                    proc_name = str(aa).split('\\n')[1]
                    proc_name = proc_name.replace('\r', '').replace('\n', '').replace('\\r', '').replace('\\n', '')
                    global_device_dict[ip]['Processor'] = proc_name

                # get serial number for windows systems
                r = s.run_cmd('WMIC bios get serialnumber')
                if r.std_out:
                    aa = r.std_out
                    serial_number = str(aa).split('\\n')[1]
                    serial_number = serial_number.replace('\r', '').replace('\n', '').replace('\\r', '').replace('\\n', '')
                    global_device_dict[ip]['SerialNumber'] = serial_number

            except Exception as ex:
                if DEBUG:
                    print(ex)
                    print('windows shell command not working for %s', ip)
            try:
                s = winrm.Session(ip, auth=(uname, passwd))
                r = s.run_cmd('systeminfo | ConvertTo-Json')
                if r.std_out:
                    data = r.std_out
                    attr_map = {}
                    for el in data:
                        if not el:
                            continue
                        el = el.strip()
                        el = re.sub(r"[\n\t]*", "", el)
                        k, val = el.split(":")
                        attr_map[k] = val.strip()

                    processor_count = int(attr_map.get('Processor(s)').split()[0])
                    processors = []
                    for i in range(1, processor_count + 1):
                        k = str(i)
                        if i < 10:
                            k = "[0{}]".format(k)
                        processors.append(attr_map.get(k))

                    if not global_device_dict[ip]['hostname']:
                        global_device_dict[ip]['hostname'] = attr_map.get('Host Name')
                    if not global_device_dict[ip]['os']:
                        global_device_dict[ip]['os'] = attr_map.get('OS Name')
                    if not global_device_dict[ip]['version']:
                        global_device_dict[ip]['version'] = attr_map.get('OS Version')
                    if not global_device_dict[ip]['manufacturer']:
                        global_device_dict[ip]['manufacturer'] = attr_map.get('System Manufacturer')
                    if not global_device_dict[ip]['model']:
                        global_device_dict[ip]['model'] = attr_map.get('System Model')
                    if not global_device_dict[ip]['Processor']:
                        global_device_dict[ip]['Processor'] = processors

                r = s.run_cmd('WMIC.exe diskdrive get size | ConvertTo-Json')
                if r.std_out:
                    size_list = r.std_out
                    size_list.pop(0)
                    total_size = sum(
                        [int(el.strip()) for el in size_list if el != '']
                    )
                    total_size_gb = bytes_to_GB(total_size)
                    global_device_dict[ip]['DiskSize'] = total_size_gb

                r = s.run_cmd('WMIC.exe cpu get NumberOfCores | ConvertTo-Json')
                if r.std_out:
                    cpu_count_list = r.std_out
                    cpu_count_list.pop(0)
                    cpu_count = sum(
                        [int(el.strip()) for el in cpu_count_list if el != '']
                    )
                    global_device_dict[ip]['CPU'] = cpu_count

            except Exception as ex:
                if DEBUG:
                    print(ex)
                    print('windows shell command not working for %s', ip)

    # actual execution
    with ThreadPoolExecutor(max_workers=MAX_DISCOVERY_THREADS) as executor:
        for eachip in get_windows_machines():
           executor.submit(sub_update_windows_details, eachip, windows_cred_list)

def log_all():
    cmdline('mkdir -p ./logs')
    cmdline('rm -rf ./logs/*.txt')
    for e in global_device_dict:
        cmdline('snmpwalk -v2c -c ul4ever %s > logs/%s.txt' % (e, e))


def update_location_details(snmp_auth_index, **kwargs):
    def sub_update_location_details(eachip, **kwargs):
        try:
            if global_device_dict[eachip]['Location']:
                return None
            kwargs.update(dict(oids=['iso.3.6.1.2.1.1.6.0'], hostname=eachip))
            location = get_pysnmp_oid_value(**kwargs)

            if not location or not len(location[0]):
                return None

            location_value = location[0]

            if len(location_value) > len(global_device_dict[eachip]['Location']):
                global_device_dict[eachip]['Location'] = location_value
        except Exception as ex:
            if DEBUG:
                print('update_location_details:: has exception' + eachip)
                print(ex)
                print('##')

    # actual execution
    with ThreadPoolExecutor(max_workers=MAX_DISCOVERY_THREADS) as executor:
        for eachip in active_snmp_devices(snmp_auth_index):
           executor.submit(sub_update_location_details, eachip, **kwargs)


def update_device_type(snmp_auth_index, **kwargs):
    def sub_update_device_type(eachip, **kwargs):
        try:
            # primarily check here
            # TODO not getting the following all the time
            kwargs.update(dict(oids=['iso.3.6.1.2.1.47.1.1.1.1.2.1'], hostname=eachip))
            devicetype = get_pysnmp_oid_value(**kwargs)

            if not devicetype or not len(devicetype[0]):
                return None

            val = devicetype[0]
            val = val.lower()
            found_value = ''

            if "switch" in val or "access" in val :
                found_value = "switch"
            elif "gatekeeper" in val:
                found_value = "switch"
            elif "firewall" in val or "security" in val:
                found_value = "firewall"
            elif "balancer" in val:
                found_value = "loadbalancer"
            elif "router" in val:
                found_value = "switch"
            elif "vmware" in val:
                if "appliance" in found_value:
                    found_value = "hypervisor"
                else :
                    found_value = "virtual_machine"
            elif "server" in val or "desktop" in val:
                    found_value = "server"

            if found_value:
                print('<==> Type of device with ip %s is %s '%(eachip,found_value))
                global_device_dict[eachip]['device_type'] = found_value

        except Exception as ex:
            if DEBUG:
                print('device_type OID not found for ' + eachip)
                print(ex)
                print('!' * 24)

        if not global_device_dict[eachip]['device_type']:
            if not global_device_dict[eachip]['SysDescription']:
                return None

            val = global_device_dict[eachip]['SysDescription']
            from sysdescrparser import sysdescrparser
            sysdescr = sysdescrparser(val)

            if sysdescr.devicetype != "UNKNOWN":
                global_device_dict[eachip]['device_type'] = sysdescr.devicetype
            else:
                global_device_dict[eachip]['device_type'] = ''

    # actual execution
    with ThreadPoolExecutor(max_workers=MAX_DISCOVERY_THREADS) as executor:
        for eachip in active_snmp_devices(snmp_auth_index):
           executor.submit(sub_update_device_type, eachip, **kwargs)

def update_hardwareOEM_details(snmp_auth_index, **kwargs):
    def sub_update_hardwareOEM_details(eachip, **kwargs):
        # manufacturer
        try :
            # TODO not getting the following all the time
            kwargs.update(dict(oids=['1.3.6.1.2.1.47.1.1.1.1.12.1']),hostname=eachip)
            manufacturer = get_pysnmp_oid_value(**kwargs)

            if manufacturer and len(manufacturer[0]):
                val = manufacturer[0]
                global_device_dict[eachip]['manufacturer'] = val
        except Exception as ex:
            if DEBUG:
                print('iso.3.6.1.2.1.47.1.1.1.1.12.1 not found for ' + eachip)
                print(ex)
                print('!' * 24)

        # model
        try :
            # TODO not getting the following all the time
            kwargs.update(dict(oids=['1.3.6.1.2.1.47.1.1.1.1.13.1']),hostname=eachip)
            model = get_pysnmp_oid_value(**kwargs)

            if model and len(model[0]):
                modelval = model[0]
                global_device_dict[eachip]['model'] = modelval
        except Exception as ex:
            if DEBUG:
                print('iso.3.6.1.2.1.47.1.1.1.1.13.1 not found for ' + eachip)
                print(ex)
                print('!' * 24)

        try:
            kwargs.update(dict(oids=['iso.3.6.1.2.1.1.1.0'], hostname=eachip))
            generic_string = get_pysnmp_oid_value(**kwargs)

            if generic_string and len(generic_string[0]):
                val = generic_string[0].lower()
                if DEBUG:
                    print(' OEM string is ' + val)

                if "cisco" in val:
                    values_list = val.split(',')
                    global_device_dict[eachip]['os'] = values_list[0]
                    global_device_dict[eachip]['version'] = values_list[2]
                elif "juniper" in val:
                    values_list = val.split(',')
                    global_device_dict[eachip]['os'] = 'junOS'
                    global_device_dict[eachip]['version'] = values_list[2].replace('kernel','').replace('junos','').strip()
                elif "windows" in val:
                    values_list = val.split("Software:")
                    global_device_dict[eachip]['os'] = "Windows"
                    windows_verion = values_list[1].replace("Windows","").strip()
                    windows_version = re.sub("([\(\[]).*?([\)\]])", "\g<1>\g<2>", windows_verion)
                    global_device_dict[eachip]['version'] = windows_version
                elif "vmware" in val:
                    if "server appliance" in val:
                        values_list = val.split(',')
                        first_string = values_list[0]
                        os_version = first_string.split('appliance')[1].replace('vmware','')
                        global_device_dict[eachip]['os'] = "VMware vCenter Server Appliance"
                        global_device_dict[eachip]['version'] = os_version
                    else:
                         values_list = val.split(',')
                         first_string = values_list[0]
                         os_version = ' '.join(first_string.split('esxi')[1].split()[0:2])
                         global_device_dict[eachip]['os'] = "Vmware ESXi"
                         global_device_dict[eachip]['version'] = os_version
                elif "linux" in val:
                    global_device_dict[eachip]['os'] = "Linux"

        except Exception as ex:
            if DEBUG:
                print('Make ID not found ' + eachip)
                print(ex)
                print('$' * 24)

    # for eachip in active_snmp_devices(snmp_auth_index):
    #     sub_update_hardwareOEM_details( eachip, **kwargs)

    # actual execution
    with ThreadPoolExecutor(max_workers=MAX_DISCOVERY_THREADS) as executor:
        for eachip in active_snmp_devices(snmp_auth_index):
           executor.submit(sub_update_hardwareOEM_details, eachip, **kwargs)


def update_model_manufacturer(snmp_auth_index, model_manufacturer_map, **snmp_details):
    def sub_update_model_manufacturer(eachip, model_manufacturer_map, **snmp_details):
        try :
            snmp_version = snmp_details.get('version', 0)
            oid = '1.3.6.1.2.1.1.2'
            if snmp_version == 3:
                try:
                    command = 'snmpwalk -a {} -A {} -l {} -u {} -v 3 -x {} -X {} {} {} -One'
                    command = command.format(
                        snmp_details['auth_protocol'],
                        snmp_details['auth_password'],
                        snmp_details['security_level'],
                        snmp_details['security_username'],
                        snmp_details['privacy_protocol'],
                        snmp_details['privacy_password'],
                        eachip,
                        oid
                    )
                except KeyError:
                    traceback.print_exc()
                    return None
            elif snmp_version == 2:
                snmp_community = snmp_details['community']
                command = f'snmpwalk -v2c -c {snmp_community} {eachip} {oid} -One'
            elif snmp_version == 1:
                snmp_community = snmp_details['community']
                command = f'snmpwalk -v1 -c {snmp_community} {eachip} {oid} -One'
            #  execute the command now
            output = cmdline(command)
            output = output.decode()
            li = output.split('OID: ')
            lookup_oid = li[-1].replace('iso', '1')
            lookup_oid = re.sub(r"[\n\t\s]*", "", lookup_oid)
            lookup_oid = lookup_oid.strip().lstrip('.')
            data = model_manufacturer_map.get(lookup_oid)
            if not data:
                print('Device type OID {} lookup failed for ip {}'.format(lookup_oid, eachip))
                return None
            excluded_manufacturers = ['vmware inc']
            vendor = data.get('Vendor')
            if data:
                if not any(x in vendor.lower() for x in excluded_manufacturers):
                    if not global_device_dict[eachip]['manufacturer']:
                        global_device_dict[eachip]['manufacturer'] = vendor
                    if not global_device_dict[eachip]['model']:
                        global_device_dict[eachip]['model'] = data.get('Description')
                    global_device_dict[eachip]['device_type_found'] = data.get('known_device_type')

                if not global_device_dict[eachip]['device_type']:
                    device_type_found = data.get('known_device_type').lower()
                    found_value=''
                    if any(e for e in ["access", "switch","gateway", "gatekeeper","modem","router"] if e in device_type_found ):
                        found_value = "switch"
                    elif any(e for e in ["security", "firewall","intrusion"] if e in device_type_found ):
                        found_value = "firewall"
                    elif "balancer" in device_type_found:
                        found_value = "loadbalancer"
                    elif device_type_found in ["virtual machine"]:
                        found_value = "virtual_machine"
                    elif device_type_found in ["desktop", "server"]:
                        found_value = "server"
                    elif device_type_found in ["pdu"]:
                        found_value = "power"
                    elif device_type_found in ["storage"]:
                        found_value = "storage"
                    global_device_dict[eachip]['device_type'] = found_value
                    print()
                    print (found_value*10)
                    print()
        except Exception as ex:
            import  traceback;traceback.print_exc()
            if DEBUG:
                print('Make ID not found ' + eachip)
                print(ex)
                print('$' * 24)
    # actual execution
    with ThreadPoolExecutor(max_workers=MAX_DISCOVERY_THREADS) as executor:
        for eachip in active_snmp_devices(snmp_auth_index):
           executor.submit(sub_update_model_manufacturer, eachip, model_manufacturer_map, **snmp_details)


def update_ad_fetch_details(ad_cred_list, cidr_addr):
    for eachadlist in ad_cred_list:
        username, password, host_name, ip_address = eachadlist
        try:
            s = winrm.Session(ip_address, auth=(username, password))
            rr = s.run_ps('Get-ADComputer -Filter * -Properties ipv4Address, OperatingSystem, OperatingSystemVersion | ConvertTo-Json ')
            if rr.std_out:
                aa = rr.std_out.decode()
                aa = aa.replace('\r', '').replace('\n', '').replace('\\r', '').replace('\\n', '').replace("'", "")
                final= eval( aa.replace('null','None').replace('true','True').replace('false','False'))

                arp_dict = {}

                # get the arp entries
                cmd_output = s.run_ps('arp -a | ConvertTo-Json')
                if cmd_output.std_out:
                    aa = cmd_output.std_out.decode()
                    aa = aa.replace('\r', '').replace('\n', '').replace('\\r', '').replace('\\n', '').replace("'", "")
                    arp_table = eval(aa)

                if len(arp_table) and type(arp_table) == list:
                    clean_arp_table = [ e for e in arp_table if len(e) and e.strip()[0].isdigit()]
                    for eacharp in clean_arp_table:
                        arp_values = eacharp.split()
                        arp_dict[arp_values[0]] = arp_values[1]

                for each in final:
                    # if ipaddress.ip_address(each['IPv4Address']) not in ipaddress.ip_network(cidr_addr):
                    #     continue
                    host_name = each['Name']
                    host_ip = each['IPv4Address']
                    host_os = each['OperatingSystem']
                    host_os_version = each['OperatingSystemVersion']
                    if host_ip in arp_dict:
                        host_mac = arp_dict[host_ip].replace('-',':')
                    else :
                        host_mac = get_mac_address(each['IPv4Address'])

                    if host_ip not in global_device_dict:
                        global_device_dict[host_ip] = dict.fromkeys(device_headers, '')

                    global_device_dict[host_ip]['MacAddress'] = host_mac
                    global_device_dict[host_ip]['ip_address'] = host_ip
                    global_device_dict[host_ip]['unique_id'] = str(uuid.uuid4())
                    global_device_dict[host_ip]['hostname'] = host_name
                    global_device_dict[host_ip]['os'] = host_os
                    global_device_dict[host_ip]['version'] = host_os_version
        except Exception as ex:
            if DEBUG:
                print(ex)
                print('update_ad_fetch_details :: windows shell command not working for %s', ip_address)


def load_all_manufacturer():
    model_manufacturer_map = {}
    # make a call to unity an check if it's the latest version if not make a get
    with open('discovery_app/Networking-Devices-Data.csv', mode='r', newline='', encoding='ISO-8859-1') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            model_manufacturer_map[row['SysObjectID']] = {'Vendor': row['Brand'], 'Description': row['Model'],
                                                          'known_device_type': row['Unity Category']}
    return model_manufacturer_map


def update_snmp_all(snmp_cred_list):
    model_manufacturer_map = load_all_manufacturer()
    # loop now
    for index, snmpdict in enumerate(snmp_cred_list):
        try:
            if snmpdict['version'] == 'SNMPv3':
                snmp_args = {'version': 3, 'security_level': snmpdict['security_level'],
                             'security_username': snmpdict['security_username'],
                             'auth_protocol': snmpdict['auth_protocol'],
                             'auth_password': snmpdict['auth_password'],
                             'privacy_protocol': snmpdict['privacy_protocol'],
                             'privacy_password': snmpdict['privacy_password'],
                             }
            elif snmpdict['version'] == 'SNMPv2':
                snmp_args = {"community": snmpdict['cstring'], "version": 2}
            elif snmpdict['version'] == 'SNMPv1':
                snmp_args = {"community": snmpdict['cstring'], "version": 1}

            # # # update the system description
            update_snmp_sysdescription(index, **snmp_args)

            # # # update the location details
            update_location_details(index, **snmp_args)

            # # # Device type : router,switch,firewall ..
            update_device_type(index, **snmp_args)

            # # # Update the snmp details
            update_hardwareOEM_details(index, **snmp_args)

            # # # Update the serial number
            update_snmp_serialnumber(index, **snmp_args)

            # get model and manufacturer from saved json data
            update_model_manufacturer(index, model_manufacturer_map, **snmp_args)

            # # # get the hostname
            update_hostname_details(index, **snmp_args)

            # Fetch interface details for each ip
            update_snmp_interfaces(index, **snmp_args)

            # Fetch uptime details
            update_uptime_details(index, **snmp_args)

            # # # update memory and disk
            ## NOT USED
            # update_memory_and_disk_capacity(**snmp_args)
        except Exception as ex:
            traceback.print_exc()
            if DEBUG:
                print("Exception in update_snmp_all")
                print('%%'*24)

    # return global_device_dict


def build_json_from_dict():
    result = []
    for e in sorted(global_device_dict):
        result.append( {key: global_device_dict[e][key] for key in final_headers})
        # result.append(OrderedDict( (key, global_device_dict[e][key]) for key in final_headers))
    final_ouput = json.dumps(result)
    # print(final_ouput)
    # make sure the process cleans up the
    return final_ouput


def discovery_run(cidr_addr, snmp_cred_list, ssh_cred_list, windows_cred_list, ad_cred_list):
    # # # run the actual discovery
    run_discovery(cidr_addr)

    # # get the list of devices from AD
    ## finally do the AD
    update_ad_fetch_details(ad_cred_list, cidr_addr)

    # #get all the ports open
    scan_ports_and_load()

    # create a dump of all the devices
    # log_all()

    # # # all the snmp details would be updated below
    update_snmp_all(snmp_cred_list)

    # # #get the memory,cpu information
    update_linux_details(ssh_cred_list)

    # ###
    # run_windows_power_shell(windows_cred_list)

    # ###
    update_windows_details(windows_cred_list)

    # finally_createcsv, will inlcude al the device_headers
    global global_device_dict
    print("Device dict:", global_device_dict)
    try:
        create_csv_with_fields(cidr_addr)
    except:
        pass

    final_json =  build_json_from_dict()
    global_device_dict={}

    return final_json


if __name__ == '__main__':
    # cidr_addr = "10.192.4.78/24"
    # cidr_addr = "10.128.7.23"
    # cidr_addr = "10.192.4.0/31"
    # cidr_addr = "10.177.177.1/24"
    # cidr_addr = "192.168.109.0"
    # cidr_addr = "192.168.232.17"
    # cidr_addr = "10.128.7.175"
    # cidr_addr = "10.192.4.0/27"
    # cidr_addr = "10.216.0.0/24"
    cidr_addr = "10.128.7.0/27"
    # cidr_addr = "10.192.10.0/24"
    snmp_cred_list = [
        {"cstring": "ul4ever", "version": 'SNMPv2'},
        {'version': 'SNMPv3', 'security_level': 'authPriv', 'security_username': 'uladminv3', 'auth_protocol': 'SHA',
         'auth_password': 'aEDq:c7y', 'privacy_protocol': 'AES', 'privacy_password': 'aEDq:c7y'}
    ]
    ssh_cred_list = [('uladmin', 'aEDq:c7y')]
    ssh_cred_list = []
    windows_cred_list = [(('Administrator', 'aEDq:c7y'))]
    ad_cred_list =  []
    windows_cred_list = []
    ad_cred_list = []

    # run the actual function
    discovery_run(cidr_addr, snmp_cred_list, ssh_cred_list, windows_cred_list, ad_cred_list)
