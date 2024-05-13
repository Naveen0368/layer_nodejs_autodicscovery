import requests
from requests.auth import HTTPBasicAuth
import datetime

# from .constants import (
#     CUTOMER_USER_NAME, CUSTOMER_PASSWORD, ENDPOINT
# )

aa = {'search_uuid': 'e074c920-f713-4cf7-8583-3e0ebc7024b7', 'duration': datetime.timedelta(0, 3, 638897),
      'scan_output': '[{"hostname": "sw2-mgmt.sf10.unitedlayer.com", "ip_address": "10.128.7.1", "MacAddress": "00:1b:54:3f:d8:cd", "manufacturer": "Cisco", "model": "Catalyst 37xx Switch Stack", "os": "cisco ios software", "version": " version 12.2(55)se10", "device_type": "switch", "CPU": "", "Memory": "", "DiskSize": "", "Processor": "", "SysDescription": "Cisco IOS Software, C3750 Software (C3750-IPBASEK9-M), Version 12.2(55)SE10, RELEASE SOFTWARE (fc2)\\r\\nTechnical Support: http://www.cisco.com/techsupport\\r\\nCopyright (c) 1986-2015 by Cisco Systems, Inc.\\r\\nCompiled Wed 11-Feb-15 11:40 by prod_rel_team", "unique_id": "8a9c9ca1-746d-43b6-acc8-9055cb6ffdee"}]'}

aa={'search_uuid': 'e074c920-f713-4cf7-8583-3e0ebc7024b7', 'duration': datetime.timedelta(0, 3, 634214), 'scan_output': '[{"hostname": "sw2-mgmt.sf10.unitedlayer.com", "ip_address": "10.128.7.1", "MacAddress": "00:1b:54:3f:d8:cd", "manufacturer": "Cisco", "model": "Catalyst 37xx Switch Stack", "os": "cisco ios software", "version": " version 12.2(55)se10", "device_type": "switch", "CPU": "", "Memory": "", "DiskSize": "", "Processor": "", "SysDescription": "Cisco IOS Software, C3750 Software (C3750-IPBASEK9-M), Version 12.2(55)SE10, RELEASE SOFTWARE (fc2)\\r\\nTechnical Support: http://www.cisco.com/techsupport\\r\\nCopyright (c) 1986-2015 by Cisco Systems, Inc.\\r\\nCompiled Wed 11-Feb-15 11:40 by prod_rel_team", "unique_id": "4152fe13-269c-4ab0-9037-cecf62563c4e"}]'}


auth = HTTPBasicAuth(
    username='mike@autodiscoverydemo.com', password='HelloMike#1'
)

url = 'https://unity.unitedlayer.com/customer/unity_discovery/add_devices/'
# url = 'https://209.237.237.134/'

# end_time = datetime.datetime.utcnow()
# duration = end_time - start_time
# data = {
#     'search_uuid': search_uuid,
#     'duration': duration,
#     'scan_output': scan_result
# }
# print(locals())

print('#' * 24)
print(aa)
# print(CUTOMER_USER_NAME, CUSTOMER_PASSWORD, url)

print('#' * 24)

response = requests.post(url=url, auth=auth, data=aa, verify=False)
# print(r.status_code, r.headers)

# Making a get request
# response = requests.get(url,verify=False)

# print request object
print(response)
print(response.status_code)
print(response.headers)