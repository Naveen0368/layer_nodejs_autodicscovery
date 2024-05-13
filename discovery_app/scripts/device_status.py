import json
import logging
import requests
import traceback

from datetime import datetime
from django_redis import get_redis_connection
from requests.auth import HTTPBasicAuth

try:
    from unitydiscover import get_host_status_with_icmp
except:
    from discovery_app.unitydiscover import get_host_status_with_icmp

from discovery_app.constants import PROD_USER_NAME, PROD_PASSWORD, ENDPOINT, URL_MAP
from discovery_app.utils import update_status, post_to_unity

logger = logging.getLogger(__name__)


def device_status():
    redis = get_redis_connection('default')
    end_point = str(redis.get('ds_end_point'))
    unity_list = redis.get('base_ips')
    unity_list = json.loads(unity_list)
    start = datetime.now()
    for base_ip in unity_list:
        full_data = redis.get(base_ip)
        full_data = json.loads(full_data)
        org = full_data['org']
        db_data = full_data['device_details']
        host_details = URL_MAP.get(base_ip, None)

        if host_details:
            base_url = host_details[0]
            customer_user_name = host_details[1]
            customer_password = host_details[2]
        else:
            base_url = "https://unity.unitedlayer.com/"
            customer_user_name = PROD_USER_NAME
            customer_password = PROD_PASSWORD

        data, output, error = update_status(db_data, full_data, org, base_ip, end_point, script=True)
        url = base_url + end_point
        if output or error:
            post_to_unity(data, customer_user_name, customer_password, url)
        else:
            logger.info("No device status found for IP - %s" % str(base_ip))
        end = datetime.now()
        logger.info("Status check for IP - %s started at - %s completed at - %s" % (str(base_ip), str(start), str(end)))
        logger.info("#" * 80)
    return True


def run():
    device_status()
