import copy
import datetime
import json
import requests
import traceback

from celery import shared_task
from celery.utils.log import get_task_logger
from django_redis import get_redis_connection
from requests.auth import HTTPBasicAuth

try:
    from unitydiscover import discovery_run, get_host_status_with_icmp
    from generate_topology import generate_topology
except:
    from .unitydiscover import discovery_run, get_host_status_with_icmp
    from .generate_topology import generate_topology

from .constants import PROD_USER_NAME, PROD_PASSWORD, ENDPOINT, URL_MAP
from .utils import update_status, post_to_unity

logger = get_task_logger(__name__)


@shared_task
def perform_scan(**kwargs):
    search_uuid = kwargs.get('search_uuid')
    subnet_range = kwargs.get('subnet_range')
    snmp_cred_list = kwargs.get('snmp_cred_list')
    ssh_cred_list = kwargs.get('ssh_cred_list')
    ssh_key_cred_list = kwargs.get('ssh_key_cred_list')
    windows_cred_list = kwargs.get('windows_cred_list')
    ad_cred_list = kwargs.get('ad_cred_list')
    base_url = kwargs.get('base_url')

    start_time = datetime.datetime.utcnow()
    host_details = URL_MAP.get(base_url, None)

    if host_details:
        base_url = host_details[0]
        customer_user_name = host_details[1]
        customer_password = host_details[2]
    else:
        # TODO have os environment variable to fix this for dev needs
        base_url = "https://unity.unitedlayer.com/"
        customer_user_name = PROD_USER_NAME
        customer_password = PROD_PASSWORD

    auth = HTTPBasicAuth(
        username=customer_user_name, password=customer_password
    )
    url = base_url + ENDPOINT


    scan_result = discovery_run(
        subnet_range,
        snmp_cred_list,
        ssh_cred_list,
        windows_cred_list,
        ad_cred_list
    )
    discovery_output = copy.deepcopy(scan_result)
    discovered_devices = json.loads(copy.deepcopy(scan_result))
    network_topology_data = generate_topology(
        discovered_devices, snmp_cred_list, ssh_cred_list
    )

    end_time = datetime.datetime.utcnow()
    duration = end_time - start_time
    data = {
        'search_uuid': search_uuid,
        'duration': duration,
        'scan_output': discovery_output,
        'network_topology': network_topology_data
    }

    logger.info("#"*24)
    logger.info('Run Discovery invoked with following Arguments')
    for e in kwargs:
        logger.info('%s = %s' % (e, kwargs.get(e)))
    logger.info('-'*24)

    # log search uid
    logger.info('Search_UID ' + data['search_uuid'])

    # log scan ouput
    logger.info('Discovery output is ')
    logger.info(str(scan_result))

    # log duration
    logger.info('Duration ' + str(data['duration']))

    # log network_topology
    logger.info('Network Topology output is ')
    logger.info(str(network_topology_data))

    r = requests.post(url=url, auth=auth, data=data, verify=False)

    response_code_str = 'Posted Data to unity with JobID %s and response code %s'%(search_uuid,  r.status_code)
    logger.info(response_code_str)
    logger.info("#" * 24)
    return True


@shared_task
def check_device_status(**kwargs):
    device_details = kwargs.get('device_details')
    org = kwargs.get('org')
    base_url = kwargs.get('base_url')
    end_point = kwargs.get('end_point')
    host_details = URL_MAP.get(base_url, None)
    redis = get_redis_connection('default')
    full_data = redis.get(base_url)
    full_data = json.loads(full_data) if full_data else {}
    base_ip = base_url

    if host_details:
        base_url = host_details[0]
        customer_user_name = host_details[1]
        customer_password = host_details[2]
    else:
        base_url = "https://unity.unitedlayer.com/"
        customer_user_name = PROD_USER_NAME
        customer_password = PROD_PASSWORD

    data, output, error = update_status(device_details, full_data, org, base_ip, end_point)
    url = base_url + end_point
    post_to_unity(data, customer_user_name, customer_password, url)
    return True
