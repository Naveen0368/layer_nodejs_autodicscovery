import logging
import requests
import traceback

from rest_framework import status, viewsets
from rest_framework.authentication import BasicAuthentication
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView


from django.shortcuts import render

from .tasks import perform_scan, check_device_status
from .device import Device

try:
    from unitydiscover import discovery_run
except:
    from .unitydiscover import discovery_run

logger = logging.getLogger(__name__)


class ScanViewset(APIView):
    authentication_classes = (BasicAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        fun_args = dict(
            search_uuid=request.data.get('search_uuid'),
            subnet_range=request.data.get('subnet_range'),
            snmp_cred_list=request.data.get('snmp_cred_list'),
            ssh_cred_list=request.data.get('ssh_cred_list'),
            ssh_key_cred_list=request.data.get('ssh_key_cred_list'),
            windows_cred_list=request.data.get('windows_cred_list'),
            ad_cred_list=request.data.get('ad_cred_list'),
            base_url=request.META.get(
                'HTTP_X_FORWARDED_FOR',
                request.META.get('REMOTE_ADDR', '')
            ).split(',')[0].strip()
        )

        logger.info('+' * 24)
        logger.info('Received a Discovery Job with the following details')
        for e in request.data:
            logger.info('%s = %s'%(e,request.data.get(e)))
        logger.info('-' * 24)

        scan_result = perform_scan.delay(**fun_args)
        return Response(True, status=status.HTTP_200_OK)


class InterfaceViewset(APIView):
    authentication_classes = (BasicAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        snmp_cred_list = request.data.get('snmp_cred')
        logger.info('+'*24)
        logger.info('Receieved a Discovery interface Job with the following details')
        for e in request.data:
            logger.info('%s = %s' % (e, request.data.get(e)))
        logger.info('-' * 24)
        device = Device(request.data, snmp_cred_list, [])
        interface_result = device.interfaces
        response = list()
        for key, interface in interface_result.items():
            if interface.name:
                response.append({"name": interface.name, "type": interface.type, "status": interface.status,
                                 "mac_address": interface.mac, "description": interface.description})
        return Response(response, status=status.HTTP_200_OK)
        return Response({'error': str(error)}, status=status.HTTP_400_BAD_REQUEST)


class UptimeViewset(APIView):
    authentication_classes = (BasicAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        snmp_cred_list = request.data.get('snmp_cred')
        logger.info('+'*24)
        logger.info('Receieved a Discovery Uptime Job with the following details')
        for e in request.data:
            logger.info('%s = %s' % (e, request.data.get(e)))
        logger.info('-' * 24)
        device = Device(request.data, snmp_cred_list, [])
        uptime_details = device.uptime
        return Response(uptime_details, status=status.HTTP_200_OK)


class DeviceStatusViewset(APIView):
    authentication_classes = (BasicAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        try:
            fun_args = dict(
                device_details=request.data.get("device_details", None),
                org=request.data.get("org", None),
                end_point=request.data.get("end_point", None),
                base_url=request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', '')
                                          ).split(',')[0].strip()
            )
            logger.info('Received a Device Status update Job with the following details')
            for e in request.data:
                logger.info('%s = %s' % (e, request.data.get(e)))
            logger.info('_' * 24)

            check_device_status.delay(**fun_args)
            return Response({"status": "success"}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.info(e)
            error = traceback.format_exc(e)
            return Response({"status": "failed", "error": error}, status=status.HTTP_400_BAD_REQUEST)
