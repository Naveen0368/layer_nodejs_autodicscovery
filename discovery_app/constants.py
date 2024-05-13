PROD_USER_NAME = 'mike@autodiscoverydemo.com'
PROD_PASSWORD = 'HelloMike#1'

DEV_USER_NAME = 'customer@unitedlayer.com'
DEV_PASSWORD = 'password'

# IMP whenever a new box is commissioned we have to populate the below

URL_MAP = {
    '64.29.139.245': (
        'https://unity-ams.unitedlayer.com/',
        PROD_USER_NAME,
        PROD_PASSWORD
    ),
    '10.216.129.30': (
        'https://unity-ams.unitedlayer.com/',
        PROD_USER_NAME,
        PROD_PASSWORD
    ),
    '209.237.237.141': (
        'https://unity.unitedlayer.com/',
        PROD_USER_NAME,
        PROD_PASSWORD
    ),
    '209.237.237.133': (
        'https://unity-alpha.unitedlayer.com/',
        DEV_USER_NAME,
        DEV_PASSWORD
    ),
    '209.237.237.134': (
        'https://209.237.237.134/',
        DEV_USER_NAME,
        DEV_PASSWORD
    ),
    '10.128.129.30': (
        'https://unity.unitedlayer.com/',
        PROD_USER_NAME,
        PROD_PASSWORD
    ),
    '10.10.108.21': (
        'https://unity-alpha.unitedlayer.com/',
        DEV_USER_NAME,
        DEV_PASSWORD
    ),
    '10.10.108.22':(
        'https://10.10.108.22/',
        DEV_USER_NAME,
        DEV_PASSWORD
    ),
    '10.192.11.228':(
        'http://10.192.11.228:8000/',
        DEV_USER_NAME,
        DEV_PASSWORD
    ),
    '10.192.11.234':(
        'http://10.192.11.234:8000/',
        DEV_USER_NAME,
        DEV_PASSWORD
    ),
    '10.192.11.239':(
        'http://10.192.11.239:8000/',
        DEV_USER_NAME,
        DEV_PASSWORD
    )
}
ENDPOINT = 'customer/unity_discovery/add_devices/'
