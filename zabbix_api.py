# -*- coding: utf-8 -*-

import json
import urllib2


class ZabbixAPI(object):

    headers = {'Content-type': 'application/json'}

    def __init__(self,
                 zabbix_server_schema='http',
                 zabbix_server_host='127.0.0.1',
                 zabbix_server_port='80',
                 zabbix_api_username='Admin',
                 zabbix_api_password='zabbix',
                 zabbix_api_userid=1
                 ):
        self.api_userid = zabbix_api_userid

        self.url = (
            '{schema}://{host}:{port}/zabbix/api_jsonrpc.php'
            ''.format(
                schema=zabbix_server_schema,
                host=zabbix_server_host,
                port=zabbix_server_port
            )
        )
        self.token = None
        self.token = self.api_call(
            method='user.login',
            params={
                'user': zabbix_api_username,
                'password': zabbix_api_password
            }
        )['result']

    def api_call(self, method, params):
        data = {
            'auth': self.token,
            'method': method,
            'id': self.api_userid,
            'params': params,
            'jsonrpc': 2.0
        }
        request = urllib2.Request(
            url=self.url,
            data=json.dumps(data),
            headers=self.headers
        )
        response = json.loads(urllib2.urlopen(request).next())

        if response.get('error') is not None:
            raise ValueError(response.get('error'))
        return response
