import os
import glob
import json
import requests
import traceback

from celery.utils.log import get_task_logger
from django_redis import get_redis_connection
from django.conf import settings
from requests.auth import HTTPBasicAuth

try:
    from unitydiscover import get_host_status_with_icmp
except:
    from .unitydiscover import  get_host_status_with_icmp

from .constants import PROD_USER_NAME, PROD_PASSWORD, ENDPOINT, URL_MAP

logger = get_task_logger(__name__)


def update_status(device_details, full_data, org, data_key, end_point, script=False):
    try:
        redis = get_redis_connection('default')
        db_data = full_data['device_details'] if full_data and 'device_details' in full_data else {}
        output = get_host_status_with_icmp(device_details)
        last_updated = None
        if db_data or script:
            final_output = {}
            for key, value in output.items():
                if key not in db_data:
                    db_data[key] = value
                    db_data[key]['last_status'] = None
                    final_output[key] = value
                db_data[key]['last_updated_on'] = value['last_updated_on']
                if script:
                    last_updated = value['last_updated_on']
                status_changed = value['current_status'] != db_data[key]['current_status']
                ip_changed = value['ip'] != db_data[key]['ip']
                if status_changed or ip_changed:
                    db_data[key]['last_status'] = db_data[key]['current_status']
                    db_data[key]['current_status'] = value['current_status']
                    db_data[key]['ip'] = value['ip']
                    final_output[key] = value
                if db_data[key]['current_status'] != db_data[key]['last_status']:
                    db_data[key]['last_status'] = db_data[key]['current_status']
                    final_output[key] = value
                if script:
                    db_data[key]['current_status'] = value['current_status']
                    final_output[key] = value
            output = final_output
            full_data['device_details'] = db_data
            if org not in full_data['org']:
                full_data['org'].append(org)
        else:
            unity_list = redis.get('base_ips')
            unity_list = json.loads(unity_list) if unity_list else []
            if data_key not in unity_list:
                unity_list.append(data_key)
            redis.set('base_ips', json.dumps(unity_list))
            redis.set('ds_end_point', end_point)
            full_data['org'] = [org]
            for key, value in output.items():
                output[key]['last_status'] = output[key]['current_status']
            full_data['device_details'] = output
        dump = json.dumps(full_data)
        redis.set(data_key, dump)
        output_str = '\n| IP                | Last Status | Current Status | Device \n'
        for key, value in output.items():
            output_str += '| %s | %s | %s | %s \n' % (
                str(value['ip'] + ' ' * (17 - len(value['ip']))),
                str(str(value['last_status']) + ' ' * (11 - len(str(value['last_status'])))),
                str(str(value['current_status']) + ' ' * (14 - len(str(value['current_status'])))),
                str(key)
            )
        if script:
            write_to_file(output_str, data_key, last_updated)
        else:
            logger.info('Device Status output is ')
            logger.info(output_str)
        data = {"status": "success", 'device_details': output, 'org': org}
        error = False
    except Exception as e:
        output = None
        error = traceback.format_exc(e)
        logger.info("Checking device status failed due to: ", str(error))
        data = {"status": "failed", "error": str(error)}

    data = json.dumps(data)
    return data, output, error


def post_to_unity(data, customer_user_name, customer_password, url):
    auth = HTTPBasicAuth(username=customer_user_name, password=customer_password)
    headers = {'content-type': 'application/json'}
    r = requests.post(url=url, auth=auth, data=data, headers=headers, verify=False)

    response_code_str = 'Posted Data to unity with response code %s' % r.status_code
    logger.info(response_code_str)
    logger.info("#" * 24)


def save_to_file(output_str, ip, last_updated_on):
    relative_path = settings.BASE_DIR + '/logs'
    filename = 'status {} {}'.format(ip, last_updated_on)
    file_dir = relative_path + '/' + filename
    with open(file_dir, 'w') as f:
        f.write(output_str)
    clean_up(ip, relative_path)


def clean_up(ip, relative_path):
    files_starting_with_status = glob.glob(os.path.join(relative_path, 'status {}*'.format(ip)))
    sorted_files = sorted(files_starting_with_status, key=os.path.getmtime, reverse=True)
    files_to_delete = sorted_files[240:]

    for file_path in files_to_delete:
        try:
            os.remove(file_path)
        except OSError as e:
            print("Error deleting file {file_path}: {e}".format(file_path=file_path, e=e))
