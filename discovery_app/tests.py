from django.test import TestCase
from .generate_topology import *
import json


class TestTopology(TestCase):

    def setUp(self):
        self.maxDiff = None
        self.SSH_CRED_1 = ('uladmin', 'aEDq:c7y')
        self.SSH_CRED_2 = ('root', 'aEDq:c7y')
        self.SSH_CRED_3 = ('root', 'a77wmncQ')
        self.ESXI_11 = {
                    'hostname': 'Esxi',
                    'ip_address': '10.128.7.11',
                    'device_type': 'hypervisor'
                }
        self.ESXI_12 = {
                    'hostname': 'Esxi',
                    'ip_address': '10.128.7.12',
                    'device_type': 'hypervisor'
                }

        self.ESXI_13 = {
                    'hostname': 'Esxi',
                    'ip_address': '10.128.7.13',
                    'device_type': 'hypervisor'
                }
        self.ESXI_14 = {
                    'hostname': 'Esxi',
                    'ip_address': '10.128.7.14',
                    'device_type': 'hypervisor'
                }
        self.ESXI_15 = {
                    'hostname': 'Esxi',
                    'ip_address': '10.128.7.15',
                    'device_type': 'hypervisor'
                }
        self.ESXI_16 = {
                    'hostname': 'Esxi',
                    'ip_address': '10.128.7.16',
                    'device_type': 'hypervisor'
                }

        self.ESXI_25 = {
                    'hostname': 'Esxi',
                    'ip_address': '10.128.7.25',
                    'device_type': 'hypervisor'
                }

    def test_find_esxi_neighbors(self):
        # passing correct credentail
        obtained_neighbors = find_esxi_neighbors(self.ESXI_11['ip_address'], [self.SSH_CRED_3])
        expected_neighbors = [('10.1.0.27', 'sw1-503.sf10')]
        self.assertEqual(obtained_neighbors, expected_neighbors)

        # passing wrong credentail
        obtained_neighbors = find_esxi_neighbors(self.ESXI_11['ip_address'], [self.SSH_CRED_2])
        expected_neighbors = []
        self.assertEqual(obtained_neighbors, expected_neighbors)

        # passing multiple credentail, one correct and one wrong 
        obtained_neighbors = find_esxi_neighbors(self.ESXI_11['ip_address'], [self.SSH_CRED_3, self.SSH_CRED_2])
        expected_neighbors = [('10.1.0.27', 'sw1-503.sf10')]
        self.assertEqual(obtained_neighbors, expected_neighbors)

    def test_get_esxis_neighbors(self):
        # passing correct credentail
        scan_result = [self.ESXI_11, self.ESXI_12, self.ESXI_13, self.ESXI_14]
        ssh_cred_list = [self.SSH_CRED_3]
        obtained_neighbors = get_esxis_neighbors(scan_result, ssh_cred_list)
        expected_neighbors = {
            self.ESXI_11['ip_address']: [('10.1.0.27', 'sw1-503.sf10')],
            self.ESXI_12['ip_address']: [('10.1.0.27', 'sw1-503.sf10')],
            self.ESXI_13['ip_address']: [('10.1.0.27', 'sw1-503.sf10')],
            self.ESXI_14['ip_address']: [('10.1.0.27', 'sw1-503.sf10')],
            }
        self.assertEqual(obtained_neighbors, expected_neighbors)

        # passing wrong credentail
        ssh_cred_list = [self.SSH_CRED_2]
        obtained_neighbors = get_esxis_neighbors(scan_result, ssh_cred_list)
        expected_neighbors = {
            self.ESXI_11['ip_address']: [],
            self.ESXI_12['ip_address']: [],
            self.ESXI_13['ip_address']: [],
            self.ESXI_14['ip_address']: [],
            }
        self.assertEqual(obtained_neighbors, expected_neighbors)

        # passing multiple credentail, one correct and one wrong
        ssh_cred_list = [self.SSH_CRED_3, self.SSH_CRED_2]
        obtained_neighbors = get_esxis_neighbors(scan_result, ssh_cred_list)
        expected_neighbors = {
            self.ESXI_11['ip_address']: [('10.1.0.27', 'sw1-503.sf10')],
            self.ESXI_12['ip_address']: [('10.1.0.27', 'sw1-503.sf10')],
            self.ESXI_13['ip_address']: [('10.1.0.27', 'sw1-503.sf10')],
            self.ESXI_14['ip_address']: [('10.1.0.27', 'sw1-503.sf10')],
            }
        self.assertEqual(obtained_neighbors, expected_neighbors)


        # passing multiple exsis and multiple credentail
        scan_result = []
        scan_result.append(self.ESXI_11) # SSH_CRED_3 is valid credential for this
        scan_result.append(self.ESXI_15) # SSH_CRED_3 is valid but 22 port is not allowed, so will not get neighbors
        scan_result.append(self.ESXI_25) # SSH_CRED_2 is valid credential for this
        ssh_cred_list = [self.SSH_CRED_3, self.SSH_CRED_2]
        obtained_neighbors = get_esxis_neighbors(scan_result, ssh_cred_list)
        expected_neighbors = {
            self.ESXI_11['ip_address']: [('10.1.0.27', 'sw1-503.sf10')],
            self.ESXI_15['ip_address']: [],
            self.ESXI_25['ip_address']: [('10.1.0.27', 'sw1-503.sf10')]
            }
        self.assertEqual(obtained_neighbors, expected_neighbors)

    def test_generate_topology(self):
        scan_result = []
        scan_result.append(self.ESXI_11) # SSH_CRED_3 is valid credential for this
        scan_result.append(self.ESXI_15) # SSH_CRED_3 is valid but 22 port is not allowed, so will not get neighbors
        scan_result.append(self.ESXI_25) # SSH_CRED_2 is valid credential for this
        ssh_cred_list = [self.SSH_CRED_3, self.SSH_CRED_2]
        obtained_output = generate_topology(scan_result, [], ssh_cred_list)

        expected_output = {
            "nodes": [
                {"hostname": "Esxi", "ip_address": "10.128.7.11", "device_type": "hypervisor", "id": 0, "onboarded": False},
                {"hostname": "Esxi", "ip_address": "10.128.7.15", "device_type": "hypervisor", "id": 1, "onboarded": False},
                {"hostname": "Esxi", "ip_address": "10.128.7.25", "device_type": "hypervisor", "id": 2, "onboarded": False},
                {"hostname": "sw1-503.sf10", "ip_address": "10.1.0.27", "device_type": "", "id": 3, "onboarded": False},
            ],
            "links": [
                {"source_id": 0, "source_ip": "10.128.7.11", "source_hostname": "Esxi", "target_id": 3, "target_ip": "10.1.0.27", "target_hostname": "sw1-503.sf10"},
                {"source_id": 2, "source_ip": "10.128.7.25", "source_hostname": "Esxi", "target_id": 3, "target_ip": "10.1.0.27", "target_hostname": "sw1-503.sf10"}
            ]
        }
        self.assertEqual(json.loads(obtained_output), expected_output)
