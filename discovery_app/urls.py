from rest_framework import routers

from django.conf.urls import include, url
from django.urls import path

from .views import ScanViewset, InterfaceViewset, DeviceStatusViewset, UptimeViewset


app_name = 'discovery_app'

urlpatterns = [
    url('request_scan/', ScanViewset.as_view(), name='request_scan'),
    url('interfaces/', InterfaceViewset.as_view(), name='interfaces'),
    url('device_status/', DeviceStatusViewset.as_view(), name='device_status'),
    url('uptime/', UptimeViewset.as_view(), name='uptime'),
]
