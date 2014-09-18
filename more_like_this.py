#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import optparse

import zabbix_api


DEFAULT = {
    'zabbix_server_schema': 'http',
    'zabbix_server_host': '127.0.0.1',
    'zabbix_server_port': '80',
    'zabbix_api_username': 'Admin',
    'zabbix_api_password': 'zabbix',
    'zabbix_api_userid': 1,
    'log_level': 'INFO',
    'dry_run': 'false',
    'base_host_name': None,
    'name': None,
    'primary_agent_interface_ip_address': None,
    'primary_agent_interface_dns': None,
    'primary_agent_interface_port': 10050,
    'primary_agent_interface_useip': 'true',
    'jmx_interface_ip_address': None,
    'jmx_interface_dns': None,
    'jmx_interface_port': 8080,
    'jmx_interface_useip': 'true',
    'override_hostgroups': None,
}


def get_args():

    usage = (
        'This script creates new screen '
        'by using x-axis elements and y-axis elements of user definition.'
    )
    parser = optparse.OptionParser(usage=usage)

    zabbix_authentication_option_group = optparse.OptionGroup(
        parser,
        'Zabbix authentication parameters'
    )

    zabbix_authentication_option_group.add_option(
        '--zabbix-server-schema', '-S',
        type='string', default=DEFAULT['zabbix_server_schema'],
        dest='zabbix_server_schema',
        help='Schema to access to zabbix server API. e.g: http, https.'
    )
    zabbix_authentication_option_group.add_option(
        '--zabbix-server-host', '-H',
        type='string', default=DEFAULT['zabbix_server_host'],
        dest='zabbix_server_host',
        help='Zabbix server hostname or IP address.'
    )
    zabbix_authentication_option_group.add_option(
        '--zabbix-server-port', '-P',
        type='int', default=DEFAULT['zabbix_server_port'],
        dest='zabbix_server_port',
        help='Zabbix server API port number.'
    )
    zabbix_authentication_option_group.add_option(
        '--zabbix-api-username', '-u',
        type='string', default=DEFAULT['zabbix_api_username'],
        dest='zabbix_api_username',
        help='Zabbix API username.'
    )
    zabbix_authentication_option_group.add_option(
        '--zabbix-api-password', '-p',
        type='string', default=DEFAULT['zabbix_api_password'],
        dest='zabbix_api_password',
        help='Zabbix API password.'
    ),
    zabbix_authentication_option_group.add_option(
        '--zabbix-api-userid', '-i',
        type='string', default=DEFAULT['zabbix_api_userid'],
        dest='zabbix_api_userid',
        help='Zabbix API user id.'
    )
    parser.add_option_group(zabbix_authentication_option_group)

    parser.add_option(
        '--log-level', '-l',
        type='choice', default=DEFAULT['log_level'],
        dest='log_level',
        choices=[
            'DEBUG',
            'INFO',
            'WARNING',
            'ERROR',
            'CRITICAL'
        ],
        help=(
            'Script log level. You can choose one in '
            '"DEBUG", "INFO", "WARNING", "ERROR" or "CRITICAL".'
        )
    )
    parser.add_option(
        '--dry-run', '-d',
        type='choice', default=DEFAULT['dry_run'],
        choices=[
            'true',
            'false',
            'True',
            'False'
        ],
        dest='dry_run',
        help='Dry run flag.'
    )
    parser.add_option(
        '--base-host-name', '-b',
        type='string', default=DEFAULT['base_host_name'],
        dest='base_host_name',
        help='Based host name.'
    )
    parser.add_option(
        '--name', '-n',
        type='string', default=DEFAULT['name'],
        dest='name',
        help='Created new host name.'
    )
    parser.add_option(
        '--primary-agent-interface-ip-address', '-a',
        type='string', default=DEFAULT['primary_agent_interface_ip_address'],
        dest='primary_agent_interface_ip_address',
        help='Primary zabbix agent interface IP address.'
    )
    parser.add_option(
        '--primary-agent-interface-dns', '-g',
        type='string', default=DEFAULT['primary_agent_interface_dns'],
        dest='primary_agent_interface_dns',
        help='Primary zabbix agent interface dns name(hostname).'
    )
    parser.add_option(
        '--primary-agent-interface-port', '-e',
        type='int', default=DEFAULT['primary_agent_interface_port'],
        dest='primary_agent_interface_port',
        help='Primary zabbix agent interface port.'
    )
    parser.add_option(
        '--primary-agent-interface-useip', '-t',
        type='choice', default=DEFAULT['primary_agent_interface_useip'],
        choices=[
            'true',
            'false',
            'True',
            'False'
        ],
        dest='primary_agent_interface_useip',
        help='Use whether IP address or dns name when agent observing.'
    )
    parser.add_option(
        '--jmx-interface-ip-address', '-j',
        type='string', default=DEFAULT['jmx_interface_ip_address'],
        dest='jmx_interface_ip_address',
        help='JMX interface IP address.'
    )
    parser.add_option(
        '--jmx-interface-dns', '-m',
        type='string', default=DEFAULT['jmx_interface_dns'],
        dest='jmx_interface_dns',
        help='JMX interface dns name(hostname).'
    )
    parser.add_option(
        '--jmx-interface-port', '-x',
        type='string', default=DEFAULT['jmx_interface_port'],
        dest='jmx_interface_port',
        help='JMX interface port.'
    )
    parser.add_option(
        '--jmx-interface-useip', '-J',
        type='choice', default=DEFAULT['jmx_interface_useip'],
        choices=[
            'true',
            'false',
            'True',
            'False'
        ],
        dest='jmx_interface_useip',
        help='Use whether IP address or dns name when JMX observing.'
    )
    parser.add_option(
        '--override-hostgroups', '-G',
        type='string', default=DEFAULT['override_hostgroups'],
        dest='override_hostgroups',
        help=(
            'If you want to override based host\'s hostgroups, '
            'specify "hostgroups" separated by commas to this option.'
        )
    )

    options = parser.parse_args()[0]
    return options


def set_log_level(log_level='DEBUG'):
    logging.basicConfig(
        format='[%(levelname)s] %(message)s',
        level=getattr(logging, log_level)
    )


class ZabbixHostMoreLikeThisException(BaseException):

    def __init__(self, message):
        super(ZabbixHostMoreLikeThisException, self).__init__(message)


def validate_options(options):

    if not options.base_host_name:
        raise ZabbixHostMoreLikeThisException(
            '"--base-host-name" option is required.'
        )

    if not options.name:
        raise ZabbixHostMoreLikeThisException(
            '"--name" option is required.'
        )

    if not options.primary_agent_interface_ip_address:
        raise ZabbixHostMoreLikeThisException(
            '"--primary-agent-interface-ip-address" option is required.'
        )


def convert_options(options):

    if options.override_hostgroups:
        options.override_hostgroups = [
            entry.strip() for entry in options.override_hostgroups.split(',')
        ]

    if options.dry_run.lower() == 'false':
        options.dry_run = False
    else:
        options.dry_run = True

    if options.primary_agent_interface_useip.lower() == 'false':
        options.primary_agent_interface_useip = False
    else:
        options.primary_agent_interface_useip = True

    if options.jmx_interface_useip.lower() == 'false':
        options.jmx_interface_useip = False
    else:
        options.jmx_interface_useip = True

    options.primary_agent_interface_port = int(
        options.primary_agent_interface_port
    )
    options.jmx_interface_port = int(options.jmx_interface_port)

    return options

class ZabbixHostMoreLikeThis(zabbix_api.ZabbixAPI):

    def __init__(self,
                 zabbix_server_schema='http',
                 zabbix_server_host='127.0.0.1',
                 zabbix_server_port='80',
                 zabbix_api_username='Admin',
                 zabbix_api_password='zabbix',
                 zabbix_api_userid=1
                 ):
        super(ZabbixHostMoreLikeThis, self).__init__(
            zabbix_server_schema=zabbix_server_schema,
            zabbix_server_host=zabbix_server_host,
            zabbix_server_port=zabbix_server_port,
            zabbix_api_username=zabbix_api_username,
            zabbix_api_password=zabbix_api_password,
            zabbix_api_userid=zabbix_api_userid
        )

        self.base_hostid = None
        self.host_attributes = {
            'host': None,
            'interfaces': list(),
            'groups': list(),
            'templates': list()
        }
        self.dry_run_host_attributes = {
            'host': None,
            'interfaces': list(),
            'groups': list(),
            'templates': list()
        }

    def set_host(self, host_name):
        self.host_attributes['host'] = host_name
        self.dry_run_host_attributes['host'] = host_name

    def get_hostid(self, host_name):
        response = self.api_call(
            method='host.get',
            params={
                'output': 'extend',
                'search': {
                    'name': host_name
                }
            }
        )
        if len(response['result']) <= 0:
            raise ZabbixHostMoreLikeThisException(
                'Maybe {0} host does not exist in your zabbix server.'
                ''.format(host_name)
            )
        if len(response['result']) > 1:
            raise ZabbixHostMoreLikeThisException(
                'Seems to exist tow ore more hosts in your zabbix server.'
            )
        hostid = response['result'][0]['hostid']
        logging.debug(
            'Found {0} host in zabbix server.'.format(
                response['result'][0]['host']
            )
        )
        logging.debug(
            'hostid of {0} is {1}.'.format(
                host_name,
                hostid
            )
        )

        return hostid

    def set_base_hostid(self, base_host_name):
        self.base_hostid = self.get_hostid(
            host_name=base_host_name
        )

    def get_template(self, template_name):
        """
        Get template name and template id.
        :type template_name: str
        :param template_name: template name
        :rtype: dict
        :return: {
            'name': Template Name(str),
            'templateid' Template ID(int)
        }
        """
        response = self.api_call(
            method='template.get',
            params={
                'output': ['name', 'templateid'],
                'search': {
                    'name': template_name
                }
            }
        )
        if len(response['result']) <= 0:
            raise ZabbixHostMoreLikeThisException(
                'Maybe {0} template does not exist in your zabbix server.'
                ''.format(template_name)
            )
        if len(response['result']) > 1:
            raise ZabbixHostMoreLikeThisException(
                'Seems to exist tow ore more templates in your zabbix server.'
            )
        result = response['result'][0]
        logging.debug(
            'Found {0} template in zabbix server.'.format(
                response['result'][0]['name']
            )
        )
        logging.debug(
            'hostid of {0} is {1}.'.format(
                template_name,
                result['templateid']
            )
        )

        return result

    def get_host_linked_templates(self, host_name):
        response = self.api_call(
            method='host.get',
            params={
                'search': {
                    'name': host_name
                },
                'selectParentTemplates': ['name', 'templateid']
            }
        )
        if len(response['result']) <= 0:
            raise ZabbixHostMoreLikeThisException(
                'Maybe {0} host does not exist in your zabbix server.'
                ''.format(host_name)
            )
        if len(response['result']) > 1:
            raise ZabbixHostMoreLikeThisException(
                'Seems to exist tow ore more hosts in your zabbix server.'
            )
        return response['result'][0]['parentTemplates']

    def set_templates(self, host_name):
        templates = self.get_host_linked_templates(host_name=host_name)
        self.dry_run_host_attributes['templates'] = templates

        try:
            templateids = [
                {'templateid': entry['templateid']} for entry in templates
            ]
            self.host_attributes['templates'] = templateids
        except Exception as exception:
            raise ZabbixHostMoreLikeThisException(
                exception.__str__()
            )
        return True

    def override_templates(self, template_names):
        """
        Override adding templates
        :type template_names: list
        :param template_names: Template names
        :rtype: bool
        :return: Whether API success and failure
        """
        templateids = list()
        dry_run_templates = list()
        for entry in template_names:
            template = self.get_template(template_name=entry)
            try:
                templateids.append(
                    {
                        'templateid': template['templateid']
                    }
                )
                dry_run_templates.append(dry_run_templates)
            except Exception as exception:
                raise ZabbixHostMoreLikeThisException(
                    exception.__str__()
                )

        self.host_attributes['templates'] = templateids
        self.dry_run_host_attributes['templates'] = dry_run_templates
        return True

    def get_hostgroup(self, hostgroup_name):
        """
        Get hostgroup.
        :type hostgroup_name: str
        :param hostgroup_name: hostgroup name
        :rtype: dict
        :return: hostgroup {
            'name': Host Group Name,
            'groupid': Host Group ID
        }
        """
        response = self.api_call(
            method='hostgroup.get',
            params={
                'output': ['name', 'groupid'],
                'search': {
                    'name': hostgroup_name
                }
            }
        )
        if len(response['result']) <= 0:
            raise ZabbixHostMoreLikeThisException(
                'Maybe {0} hostgroup does not exist in your zabbix server.'
                ''.format(hostgroup_name)
            )
        if len(response['result']) > 1:
            raise ZabbixHostMoreLikeThisException(
                'Seems to exist tow ore more hostgroup in your zabbix server.'
            )
        logging.debug(
            'Found {0} hostgroup in zabbix server.'.format(
                response['result'][0]['name']
            )
        )
        logging.debug(
            'groupid of {0} hostgroup is {1}.'.format(
                response['result'][0]['name'],
                response['result'][0]['groupid']
            )
        )

        return response['result'][0]

    def get_host_hostgroups(self, host_name):
        response = self.api_call(
            method='host.get',
            params={
                'search': {
                    'name': host_name
                },
                'selectGroups': ['name', 'groupid']
            }
        )
        if len(response['result']) <= 0:
            raise ZabbixHostMoreLikeThisException(
                'Maybe {0} host does not exist in your zabbix server.'
                ''.format(host_name)
            )
        if len(response['result']) > 1:
            raise ZabbixHostMoreLikeThisException(
                'Seems to exist tow ore more hosts in your zabbix server.'
            )
        return response['result'][0]['groups']

    def set_hostgroups(self, host_name):
        hostgroups = self.get_host_hostgroups(host_name=host_name)
        self.dry_run_host_attributes['groups'] = hostgroups

        try:
            groupids = [
                {'groupid': entry['groupid']} for entry in hostgroups
            ]
            self.host_attributes['groups'] = groupids
        except Exception as exception:
            raise ZabbixHostMoreLikeThisException(
                exception.__str__()
            )
        return True

    def override_hostgroups(self, hostgroup_names):
        """
        Override self.host_attribute['groups']
        :type hostgroup_names: list
        :param hostgroup_names: Host Group names
        :rtype: bool
        :return: Whether API success and failure
        """
        hostgroupids = list()
        dry_run_hostgroups = list()
        for entry in hostgroup_names:
            hostgroup = self.get_hostgroup(
                hostgroup_name=entry
            )
            self.dry_run_host_attributes['groups'] = hostgroup
            try:
                hostgroupids.append(
                    {
                        'groupid': hostgroup['groupid']
                    }
                )
                dry_run_hostgroups.append(hostgroup)
            except Exception as exception:
                raise ZabbixHostMoreLikeThisException(
                    exception.__str__()
                )

        self.host_attributes['groups'] = hostgroupids
        self.dry_run_host_attributes['groups'] = dry_run_hostgroups
        return True

    def set_primary_agent_interface(self,
                                    ip_address,
                                    dns=None,
                                    port=10050,
                                    useip=True):
        if useip:
            useip_param=1
        else:
            useip_param=0

        interface = {
            'type': 1,
            'main': 1,
            'useip': useip_param,
            'ip': ip_address,
            'dns': dns,
            'port': port
        }
        dry_run_interface = {
            'type': 'agent',
            'main': True,
            'useip': useip,
            'ip': ip_address,
            'dns': dns,
            'port': port
        }
        self.host_attributes['interfaces'].append(interface)
        self.dry_run_host_attributes['interfaces'].append(dry_run_interface)

        return True

    def set_jmx_interface(self,
                          ip_address,
                          dns=None,
                          port=10050,
                          useip=True):
        if useip:
            useip_param=1
        else:
            useip_param=0

        interface = {
            'type': 4,
            'main': 1,
            'useip': useip_param,
            'ip': ip_address,
            'dns': dns,
            'port': port
        }
        dry_run_interface = {
            'type': 'JMX',
            'main': True,
            'useip': useip,
            'ip': ip_address,
            'dns': dns,
            'port': port
        }
        self.host_attributes['interfaces'].append(interface)
        self.dry_run_host_attributes['interfaces'].append(dry_run_interface)

        return True

    def create_host(self, dry_run=True):
        if dry_run:
            logging.info(
                'Set "dry_run" flag.'
            )
            print('Host: {0}'.format(self.dry_run_host_attributes['host']))
            print('Interfaces:')
            for entry in self.dry_run_host_attributes['interfaces']:
                print('  {0}'.format(entry))
            print('Templates:')
            for entry in self.dry_run_host_attributes['templates']:
                print('  {0}'.format(entry))
            print('Host Groups:')
            for entry in self.dry_run_host_attributes['groups']:
                print('  {0}'.format(entry))

        else:
            try:
                self.api_call(
                    method='host.create',
                    params=self.host_attributes
                )
                logging.info(
                    'Succeed to create new host {0} to your zabbix.'
                    ''.format(self.host_attributes['host'])
                )
            except Exception as exception:
                raise ZabbixHostMoreLikeThisException(
                    exception.__str__()
                )

def main():
    raw_options = get_args()
    validate_options(raw_options)
    options = convert_options(raw_options)
    set_log_level(log_level=options.log_level)

    zabbix_more_like_this = ZabbixHostMoreLikeThis(
        zabbix_server_schema=options.zabbix_server_schema,
        zabbix_server_host=options.zabbix_server_host,
        zabbix_server_port=options.zabbix_server_port,
        zabbix_api_username=options.zabbix_api_username,
        zabbix_api_password=options.zabbix_api_password,
        zabbix_api_userid=options.zabbix_api_userid
    )
    zabbix_more_like_this.set_host(
        options.name
    )
    zabbix_more_like_this.set_primary_agent_interface(
        ip_address=options.primary_agent_interface_ip_address,
        dns=options.primary_agent_interface_dns,
        port=options.primary_agent_interface_port,
        useip=options.primary_agent_interface_useip
    )
    if options.jmx_interface_ip_address:
        zabbix_more_like_this.set_jmx_interface(
            ip_address=options.jmx_interface_ip_address,
            dns=options.jmx_interface_dns,
            port=options.jmx_interface_port,
            useip=options.jmx_interface_useip
        )
    zabbix_more_like_this.set_templates(
        options.base_host_name
    )
    if options.override_hostgroups:
        zabbix_more_like_this.override_hostgroups(
            options.override_hostgroups
        )
    else:
        zabbix_more_like_this.set_hostgroups(
            options.base_host_name
        )
    zabbix_more_like_this.create_host(dry_run=options.dry_run)

if __name__ == '__main__':
    main()
