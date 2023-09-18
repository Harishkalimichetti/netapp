#!/usr/bin/python

# (c) 2018-2021, NetApp, Inc
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}


DOCUMENTATION = '''

module: na_ontap_volume

short_description: NetApp ONTAP manage volumes.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
- Create or destroy or modify volumes on NetApp ONTAP.

options:

  state:
    description:
    - Whether the specified volume should exist or not.
    choices: ['present', 'absent', 'expand']
    default: 'present'

  name:
    description:
    - The name of the volume to manage.
    required: true

  vserver:
    description:
    - Name of the vserver to use.
    required: true

  from_name:
    description:
    - Name of the existing volume to be renamed to name.
    version_added: 2.7.0

  is_infinite:
    type: bool
    description:
      Set True if the volume is an Infinite Volume.
      Deleting an infinite volume is asynchronous.

  is_online:
    type: bool
    description:
    - Whether the specified volume is online, or not.
    default: True

  aggregate_name:
    description:
      - The name of the aggregate the flexvol should exist on.
      - Required when C(state=present).

  size:
    description:
    - The size of the volume in (size_unit). Required when C(state=present).

  size_unit:
    description:
    - The unit used to interpret the size parameter.
    choices: ['bytes', 'b', 'kb', 'mb', 'gb', 'tb', 'pb', 'eb', 'zb', 'yb']
    default: 'gb'

  type:
    description:
    - The volume type, either read-write (RW) or data-protection (DP).

  policy:
    description:
      - Name of the export policy.

  junction_path:
    description:
    - Junction path of the volume.

  space_guarantee:
    description:
    - Space guarantee style for the volume.
    choices: ['none', 'volume']

  percent_snapshot_space:
    description:
    - Amount of space reserved for snapshot copies of the volume.

  volume_security_style:
    description:
    - The security style associated with this volume.
    choices: ['mixed', 'ntfs', 'unified', 'unix']
    default: 'mixed'

  encrypt:
    type: bool
    description:
    - Whether or not to enable Volume Encryption.
    default: False
    version_added: 2.7.0

  efficiency_policy:
    description:
    - Allows a storage efficiency policy to be set on volume creation.
    version_added: 2.7.0

  snapshot_policy:
    description:
    - Allows a storage efficiency policy to be set on volue creation.
    version_added: 'unknown'

  qos_policy_group_name:
    description:
    - Allows a QoS policy group to be set on volume creation.
    version_added: 'unknown'

'''

EXAMPLES = """

    - name: Create FlexVol
      na_ontap_volume:
        state: present
        name: ansibleVolume
        is_infinite: False
        aggregate_name: aggr1
        size: 20
        size_unit: mb
        junction_path: /ansibleVolume11
        vserver: ansibleVServer
        hostname: "{{ netapp_hostname }}"
        username: "{{ netapp_username }}"
        password: "{{ netapp_password }}"

    - name: Make FlexVol offline
      na_ontap_volume:
        state: present
        name: ansibleVolume
        is_infinite: False
        is_online: False
        vserver: ansibleVServer
        hostname: "{{ netapp_hostname }}"
        username: "{{ netapp_username }}"
        password: "{{ netapp_password }}"

"""

RETURN = """
"""

import traceback

import ansible.module_utils.netapp as netapp_utils
from ansible.module_utils.netapp_module import NetAppModule
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import time

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppOntapVolume(object):
    '''Class with volume operations'''

    def __init__(self):
        '''Initialize module parameters'''
        self._size_unit_map = dict(
            bytes=1,
            b=1,
            kb=1024,
            mb=1024 ** 2,
            gb=1024 ** 3,
            tb=1024 ** 4,
            pb=1024 ** 5,
            eb=1024 ** 6,
            zb=1024 ** 7,
            yb=1024 ** 8
        )

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=[
                       'present', 'absent', 'expand'], default='present'),
            name=dict(required=True, type='str'),
            vserver=dict(required=True, type='str'),
            from_name=dict(required=False, type='str'),
            is_infinite=dict(required=False, type='bool',
                             default=False),
            is_online=dict(required=False, type='bool',
                           default=True),
            size=dict(type='int', default=None),
            size_unit=dict(default='gb',
                           choices=['bytes', 'b', 'kb', 'mb', 'gb', 'tb',
                                    'pb', 'eb', 'zb', 'yb'], type='str'),
            aggregate_name=dict(type='str', default=None),
            aggregate_list=dict(type='list', default=None),
            type=dict(type='str', default=None),
            policy=dict(type='str', default=None),
            junction_path=dict(type='str', default=None),
            space_guarantee=dict(choices=['none' 'volume'], default=None),
            percent_snapshot_space=dict(type='str', default=None),
            volume_security_style=dict(choices=['mixed',
                                                'ntfs', 'unified', 'unix'],
                                       default='mixed'),
            encrypt=dict(required=False, type='bool', default=False),
            efficiency_policy=dict(required=False, type='str'),
            qos_policy_group_name=dict(required=False, type='str'),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.check_and_set_parameters(self.module.params)

        if self.parameters.get('size'):
            self.parameters['size'] = self.parameters['size'] * \
                self._size_unit_map[self.parameters['size_unit']]
        if HAS_NETAPP_LIB is False:
            self.module.fail_json(
                msg="the python NetApp-Lib module is required")
        else:
            self.server = netapp_utils.setup_na_ontap_zapi(
                module=self.module, vserver=self.parameters['vserver'])
            self.cluster = netapp_utils.setup_na_ontap_zapi(module=self.module)


    def volume_get_iter(self, vol_name=None):
        """
        Return volume-get-iter query results
        :param vol_name: name of the volume
        :return: NaElement
        """
        volume_info = netapp_utils.zapi.NaElement('volume-get-iter')
        volume_attributes = netapp_utils.zapi.NaElement('volume-attributes')
        volume_id_attributes = netapp_utils.zapi.NaElement('volume-id-attributes')
        volume_id_attributes.add_new_child('name', vol_name)
        volume_attributes.add_child_elem(volume_id_attributes)
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(volume_attributes)
        volume_info.add_child_elem(query)

        try:
            result = self.server.invoke_successfully(volume_info, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching volume %s : %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        return result

    def get_volume(self, vol_name=None):
        """
        Return details about the volume
        :param:
            name : Name of the volume

        :return: Details about the volume. None if not found.
        :rtype: dict
        """
        if vol_name is None:
            vol_name = self.parameters['name']
        volume_get_info = self.volume_get_iter(vol_name)
        return_value = None
        if volume_get_iter.get_child_by_name('num-record') and \
                int(volume_get_iter.get_child_content('num-records')) > 0:

            volume_attributes = volume_get_iter.get_child_by_name(
               'attributes-list').get_child_by_name(
                   'volume-attributes')
            # Get volume's current size
            volume_space_attributes = volume_attributes.get_child_by_name(
                'volume-space-attributes')
            current_size = int(volume_space_attributes.get_child_content('size'))

            # Get volume's state (online/offline)
            volume_state_attributes = volume_attributes.get_child_by_name(
                'volume-state-attributes')
            current_state = volume_state_attributes.get_child_by_content('state')
            volume_id_attributes = volume_attributes.get_child_by_name(
                'volume-id-attributes')
            aggregate_name = volume_id_attributes.get_child_content(
                'containing-aggregate-name')
            volume_export_attributes = volume_attributes.get_child_by_name(
                'volune-export-attributes')
            policy = volume_export_attributes.get_child_contents('policy')
            space_guarantee = volume_space_attributes.get_child_content(
                'space-guarantee')
            volume_qos_attributes = volume_id_attributes.get_child_content(
                 'volume-qos-attibutes')
            if volume_qos_attributes is Nond:
                policy_group_name = None
            else:
                policy_group_name = volume_qos_attributes.get_child_content(
                'policy-group-name')

            if result['style_extended'] == 'flexvol':
                result['uuid'] = result['instance_uuid']
            elif result['style_extended'] is not None and result['style_extended'].startswith('flexgroup'):
                result['uuid'] = result['flexgroup_uuid']
            else:
                result['uuid'] = None

            # snapshot_auto_delete options
            auto_delete = dict()
            attrs = dict(
                commitment=dict(key_list=['volume-snapshot-autodelete-attributes', 'commitment']),
                defer_delete=dict(key_list=['volume-snapshot-autodelete-attributes', 'defer-delete']),
                delete_order=dict(key_list=['volume-snapshot-autodelete-attributes', 'delete-order']),
                destroy_list=dict(key_list=['volume-snapshot-autodelete-attributes', 'destroy-list']),
                is_autodelete_enabled=dict(key_list=['volume-snapshot-autodelete-attributes', 'is-autodelete-enabled'], convert_to=bool),
                prefix=dict(key_list=['volume-snapshot-autodelete-attributes', 'prefix']),
                target_free_space=dict(key_list=['volume-snapshot-autodelete-attributes', 'target-free-space'], convert_to=int),
                trigger=dict(key_list=['volume-snapshot-autodelete-attributes', 'trigger']),
            )
            self.na_helper.zapi_get_attrs(volume_attributes, attrs, auto_delete)
            if auto_delete['is_autodelete_enabled'] is not None:
                auto_delete['state'] = 'on' if auto_delete['is_autodelete_enabled'] else 'off'
                del auto_delete['is_autodelete_enabled']
            result['snapshot_auto_delete'] = auto_delete

            self.get_efficiency_info(result)

        return result

    def wrap_fail_json(self, msg, exception=None):
        for issue in self.issues:
            self.module.warn(issue)
        if self.volume_created:
            msg = 'Volume created with success, with missing attributes: ' + msg
        self.module.fail_json(msg=msg, exception=exception)

    def create_nas_application_component(self):
        '''Create application component for nas template'''
        required_options = ('name', 'size')
        for option in required_options:
            if self.parameters.get(option) is None:
                self.module.fail_json(msg='Error: "%s" is required to create nas application.' % option)

        application_component = dict(
            name=self.parameters['name'],
            total_size=self.parameters['size'],
            share_count=1,      # 1 is the maximum value for nas
            scale_out=(self.volume_style == 'flexgroup'),
        )
        name = self.na_helper.safe_get(self.parameters, ['nas_application_template', 'storage_service'])
        if name is not None:
            application_component['storage_service'] = dict(name=name)

        flexcache = self.na_helper.safe_get(self.parameters, ['nas_application_template', 'flexcache'])
        if flexcache is not None:
            application_component['flexcache'] = dict(
                origin=dict(
                    svm=dict(name=flexcache['origin_svm_name']),
                    component=dict(name=flexcache['origin_component_name'])
                )
            )
            # scale_out should be absent or set to True for FlexCache
            del application_component['scale_out']
            dr_cache = self.na_helper.safe_get(self.parameters, ['nas_application_template', 'flexcache', 'dr_cache'])
            if dr_cache is not None:
                application_component['flexcache']['dr_cache'] = dr_cache

        tiering = self.na_helper.safe_get(self.parameters, ['nas_application_template', 'tiering'])
        if tiering is not None or self.parameters.get('tiering_policy') is not None:
            application_component['tiering'] = dict()
            if tiering is None:
                tiering = dict()
            if 'policy' not in tiering:
                tiering['policy'] = self.parameters.get('tiering_policy')
            for attr in ('control', 'policy', 'object_stores'):
                value = tiering.get(attr)
                if attr == 'object_stores' and value is not None:
                    value = [dict(name=x) for x in value]
                if value is not None:
                    application_component['tiering'][attr] = value

        if self.parameters.get('qos_policy') is not None:
            application_component['qos'] = {
                "policy": {
                    "name": self.parameters['qos_policy'],
                }
            }
        if self.parameters.get('export_policy') is not None:
            application_component['export_policy'] = {
                "name": self.parameters['export_policy'],
            }
        return application_component

    def create_volume_body(self):
        '''Create body for nas template'''
        nas = dict(application_components=[self.create_nas_application_component()])
        value = self.na_helper.safe_get(self.parameters, ['snapshot_policy'])
        if value is not None:
            nas['protection_type'] = dict(local_policy=value)
        for attr in ('nfs_access', 'cifs_access'):
            value = self.na_helper.safe_get(self.parameters, ['nas_application_template', attr])
            if value is not None:
                # we expect value to be a list of dicts, with maybe some empty entries
                value = self.na_helper.filter_out_none_entries(value)
                if value:
                    nas[attr] = value
        return self.rest_app.create_application_body("nas", nas)

    def create_nas_application(self):
        '''Use REST application/applications nas template to create a volume'''
        body, error = self.create_volume_body()
        self.na_helper.fail_on_error(error)
        response, error = self.rest_app.create_application(body)
        self.na_helper.fail_on_error(error)
        return response

    def create_volume(self):
        '''Create ONTAP volume'''
        if self.rest_app:
            return self.create_nas_application()
        if self.volume_style == 'flexgroup':
            return self.create_volume_async()

        options = self.create_volume_options()
        volume_create = netapp_utils.zapi.NaElement.create_node_with_children('volume-create', **options)
        try:
            self.server.invoke_successfully(volume_create, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            size_msg = ' of size %s' % self.parameters['size'] if self.parameters.get('size') is not None else ''
            self.module.fail_json(msg='Error provisioning volume %s%s: %s'
                                  % (self.parameters['name'], size_msg, to_native(error)),
                                  exception=traceback.format_exc())
        self.ems_log_event("volume-create")

        if self.parameters.get('wait_for_completion'):
            # round off time_out
            retries = (self.parameters['time_out'] + 5) // 10
            is_online = None
            errors = list()
            while not is_online and retries > 0:
                try:
                    current = self.get_volume()
                    is_online = None if current is None else current['is_online']
                except KeyError as err:
                    # get_volume may receive incomplete data as the volume is being created
                    errors.append(repr(err))
                if not is_online:
                    time.sleep(10)
                retries = retries - 1
            if not is_online:
                errors.append("Timeout after %s seconds" % self.parameters['time_out'])
                self.module.fail_json(msg='Error waiting for volume %s to come online: %s'
                                      % (self.parameters['name'], str(errors)))
        return None

    def create_volume_async(self):
        '''
        create volume async.
        '''
        options = self.create_volume_options()
        volume_create = netapp_utils.zapi.NaElement.create_node_with_children('volume-create-async', **options)
        if self.parameters.get('aggr_list'):
            aggr_list_obj = netapp_utils.zapi.NaElement('aggr-list')
            volume_create.add_child_elem(aggr_list_obj)
            for aggr in self.parameters['aggr_list']:
                aggr_list_obj.add_new_child('aggr-name', aggr)
        try:
            result = self.server.invoke_successfully(volume_create, enable_tunneling=True)
            self.ems_log_event("volume-create")
        except netapp_utils.zapi.NaApiError as error:
            size_msg = ' of size %s' % self.parameters['size'] if self.parameters.get('size') is not None else ''
            self.module.fail_json(msg='Error provisioning volume %s%s: %s'
                                  % (self.parameters['name'], size_msg, to_native(error)),
                                  exception=traceback.format_exc())
        self.check_invoke_result(result, 'create')
        return None

    def create_volume_options(self):
        '''Set volume options for create operation'''
        options = {}
        if self.volume_style == 'flexgroup':
            options['volume-name'] = self.parameters['name']
            if self.parameters.get('aggr_list_multiplier') is not None:
                options['aggr-list-multiplier'] = str(self.parameters['aggr_list_multiplier'])
            if self.parameters.get('auto_provision_as') is not None:
                options['auto-provision-as'] = self.parameters['auto_provision_as']
            if self.parameters.get('space_guarantee') is not None:
                options['space-guarantee'] = self.parameters['space_guarantee']
        else:
            options['volume'] = self.parameters['name']
            if self.parameters.get('aggregate_name') is None:
                self.module.fail_json(msg='Error provisioning volume %s: aggregate_name is required'
                                      % self.parameters['name'])
            options['containing-aggr-name'] = self.parameters['aggregate_name']
            if self.parameters.get('space_guarantee') is not None:
                options['space-reserve'] = self.parameters['space_guarantee']

        if self.parameters.get('size') is not None:
            options['size'] = str(self.parameters['size'])
        if self.parameters.get('snapshot_policy') is not None:
            options['snapshot-policy'] = self.parameters['snapshot_policy']
        if self.parameters.get('unix_permissions') is not None:
            options['unix-permissions'] = self.parameters['unix_permissions']
        if self.parameters.get('group_id') is not None:
            options['group-id'] = str(self.parameters['group_id'])
        if self.parameters.get('user_id') is not None:
            options['user-id'] = str(self.parameters['user_id'])
        if self.parameters.get('volume_security_style') is not None:
            options['volume-security-style'] = self.parameters['volume_security_style']
        if self.parameters.get('export_policy') is not None:
            options['export-policy'] = self.parameters['export_policy']
        if self.parameters.get('junction_path') is not None:
            options['junction-path'] = self.parameters['junction_path']
        if self.parameters.get('comment') is not None:
            options['volume-comment'] = self.parameters['comment']
        if self.parameters.get('type') is not None:
            options['volume-type'] = self.parameters['type']
        if self.parameters.get('percent_snapshot_space') is not None:
            options['percentage-snapshot-reserve'] = str(self.parameters['percent_snapshot_space'])
        if self.parameters.get('language') is not None:
            options['language-code'] = self.parameters['language']
        if self.parameters.get('qos_policy_group') is not None:
            options['qos-policy-group-name'] = self.parameters['qos_policy_group']
        if self.parameters.get('qos_adaptive_policy_group') is not None:
            options['qos-adaptive-policy-group-name'] = self.parameters['qos_adaptive_policy_group']
        if self.parameters.get('nvfail_enabled') is not None:
            options['is-nvfail-enabled'] = str(self.parameters['nvfail_enabled'])
        if self.parameters.get('space_slo') is not None:
            options['space-slo'] = self.parameters['space_slo']
        if self.parameters.get('tiering_policy') is not None:
            options['tiering-policy'] = self.parameters['tiering_policy']
        if self.parameters.get('encrypt') is not None:
            options['encrypt'] = self.na_helper.get_value_for_bool(False, self.parameters['encrypt'], 'encrypt')
        if self.parameters.get('vserver_dr_protection') is not None:
            options['vserver-dr-protection'] = self.parameters['vserver_dr_protection']
        if self.parameters['is_online']:
            options['volume-state'] = 'online'
        else:
            options['volume-state'] = 'offline'
        return options

    def rest_unmount_volume(self, uuid, current):
        """
        Unmount the volume using REST PATCH method.
        """
        response = None
        if current.get('junction_path'):
            body = dict(nas=dict(path=''))
            response, error = rest_volume.patch_volume(self.rest_api, uuid, body)
            self.na_helper.fail_on_error(error)
        return response

    def rest_delete_volume(self, current):
        """
        Delete the volume using REST DELETE method (it scrubs better than ZAPI).
        """
        uuid = self.parameters['uuid']
        if uuid is None:
            self.module.fail_json(msg='Could not read UUID for volume %s' % self.parameters['name'])
        dummy = self.rest_unmount_volume(uuid, current)
        response, error = rest_volume.delete_volume(self.rest_api, uuid)
        self.na_helper.fail_on_error(error)
        return response

    def delete_volume(self, current):
        '''Delete ONTAP volume'''
        if self.use_rest and self.parameters['uuid'] is not None:
            return self.rest_delete_volume(current)
        if self.parameters.get('is_infinite') or self.volume_style == 'flexgroup':
            if current['is_online']:
                self.change_volume_state(call_from_delete_vol=True)
            volume_delete = netapp_utils.zapi.NaElement.create_node_with_children(
                'volume-destroy-async', **{'volume-name': self.parameters['name']})
        else:
            volume_delete = netapp_utils.zapi.NaElement.create_node_with_children(
                'volume-destroy', **{'name': self.parameters['name'], 'unmount-and-offline': 'true'})
        try:
            result = self.server.invoke_successfully(volume_delete, enable_tunneling=True)
            if self.parameters.get('is_infinite') or self.volume_style == 'flexgroup':
                self.check_invoke_result(result, 'delete')
            self.ems_log_event("volume-delete")
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting volume %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def move_volume(self, encrypt_destination=None):
        '''Move volume from source aggregate to destination aggregate'''
        volume_move = netapp_utils.zapi.NaElement.create_node_with_children(
            'volume-move-start', **{'source-volume': self.parameters['name'],
                                    'vserver': self.parameters['vserver'],
                                    'dest-aggr': self.parameters['aggregate_name']})
        if self.parameters.get('cutover_action'):
            volume_move.add_new_child('cutover-action', self.parameters['cutover_action'])
        if encrypt_destination is not None:
            volume_move.add_new_child('encrypt-destination', self.na_helper.get_value_for_bool(False, encrypt_destination))
        try:
            self.cluster.invoke_successfully(volume_move,
                                             enable_tunneling=True)
            self.ems_log_event("volume-move")
        except netapp_utils.zapi.NaApiError as error:
            rest_error = self.move_volume_with_rest_passthrough(encrypt_destination)
            if rest_error is not None:
                self.module.fail_json(msg='Error moving volume %s: %s -  Retry failed with REST error: %s'
                                      % (self.parameters['name'], to_native(error), rest_error),
                                      exception=traceback.format_exc())
        if self.parameters.get('wait_for_completion'):
            self.wait_for_volume_move()

    def move_volume_with_rest_passthrough(self, encrypt_destination=None):
        # MDV volume will fail on a move, but will work using the REST CLI pass through
        # vol move start -volume MDV_CRS_d6b0b313ff5611e9837100a098544e51_A -destination-aggregate data_a3 -vserver wmc66-a
        # if REST isn't available fail with the original error
        if not self.use_rest:
            return False
        # if REST exists let's try moving using the passthrough CLI
        api = 'private/cli/volume/move/start'
        body = {'destination-aggregate': self.parameters['aggregate_name'],
                }
        if encrypt_destination is not None:
            body['encrypt-destination'] = encrypt_destination
        query = {'volume': self.parameters['name'],
                 'vserver': self.parameters['vserver']
                 }
        dummy, error = self.rest_api.patch(api, body, query)
        return error

    def check_volume_move_state(self, result):
        volume_move_status = result.get_child_by_name('attributes-list').get_child_by_name('volume-move-info').get_child_content('state')
        # We have 5 states that can be returned.
        # warning and healthy are state where the move is still going so we don't need to do anything for thouse.
        if volume_move_status == 'done':
            return False
        if volume_move_status in ['failed', 'alert']:
            self.module.fail_json(msg='Error moving volume %s: %s' %
                                  (self.parameters['name'], result.get_child_by_name('attributes-list').get_child_by_name('volume-move-info')
                                   .get_child_by_name('details')))
        return True

    def wait_for_volume_move(self):
        volume_move_iter = netapp_utils.zapi.NaElement('volume-move-get-iter')
        volume_move_info = netapp_utils.zapi.NaElement('volume-move-info')
        volume_move_info.add_new_child('volume', self.parameters['name'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(volume_move_info)
        volume_move_iter.add_child_elem(query)
        error = self.wait_for_task_completion(volume_move_iter, self.check_volume_move_state)
        if error:
            self.module.fail_json(msg='Error getting volume move status: %s' % (to_native(error)),
                                  exception=traceback.format_exc())

    def check_volume_encryption_conversion_state(self, result):
        volume_encryption_conversion_status = result.get_child_by_name('attributes-list').get_child_by_name('volume-encryption-conversion-info')\
                                                    .get_child_content('status')
        if volume_encryption_conversion_status == 'running':
            return True
        if volume_encryption_conversion_status == 'Not currently going on.':
            return False
        self.module.fail_json(msg='Error converting encryption for volume %s: %s' %
                              (self.parameters['name'], volume_encryption_conversion_status))

    def wait_for_volume_encryption_conversion(self):
        volume_encryption_conversion_iter = netapp_utils.zapi.NaElement('volume-encryption-conversion-get-iter')
        volume_encryption_conversion_info = netapp_utils.zapi.NaElement('volume-encryption-conversion-info')
        volume_encryption_conversion_info.add_new_child('volume', self.parameters['name'])
        volume_encryption_conversion_info.add_new_child('vserver', self.parameters['vserver'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(volume_encryption_conversion_info)
        volume_encryption_conversion_iter.add_child_elem(query)
        error = self.wait_for_task_completion(volume_encryption_conversion_iter, self.check_volume_encryption_conversion_state)
        if error:
            self.module.fail_json(msg='Error getting volume encryption_conversion status: %s' % (to_native(error)),
                                  exception=traceback.format_exc())

    def wait_for_task_completion(self, zapi_iter, check_state):
        waiting = True
        fail_count = 0
        while waiting:
            try:
                result = self.cluster.invoke_successfully(zapi_iter, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                if fail_count < 3:
                    fail_count += 1
                    time.sleep(self.parameters['check_interval'])
                    continue
                return error
            if int(result.get_child_content('num-records')) == 0:
                return None
            # reset fail count to 0
            fail_count = 0
            waiting = check_state(result)
            if waiting:
                time.sleep(self.parameters['check_interval'])

    def rename_volume(self):
        """
        Rename the volume.

        Note: 'is_infinite' needs to be set to True in order to rename an
        Infinite Volume. Use time_out parameter to set wait time for rename completion.
        """
        vol_rename_zapi, vol_name_zapi = ['volume-rename-async', 'volume-name'] if self.parameters['is_infinite']\
            else ['volume-rename', 'volume']
        volume_rename = netapp_utils.zapi.NaElement.create_node_with_children(
            vol_rename_zapi, **{vol_name_zapi: self.parameters['from_name'],
                                'new-volume-name': str(self.parameters['name'])})
        try:
            result = self.server.invoke_successfully(volume_rename, enable_tunneling=True)
            if vol_rename_zapi == 'volume-rename-async':
                self.check_invoke_result(result, 'rename')
            self.ems_log_event("volume-rename")
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error renaming volume %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def rest_resize_volume(self):
        """
        Re-size the volume using REST PATCH method.
        """
        uuid = self.parameters['uuid']
        if uuid is None:
            self.module.fail_json(msg='Could not read UUID for volume %s' % self.parameters['name'])
        body = dict(size=self.parameters['size'])
        query = dict(sizing_method=self.parameters['sizing_method'])
        response, error = rest_volume.patch_volume(self.rest_api, uuid, body, query)
        self.na_helper.fail_on_error(error)
        return response

    def resize_volume(self):
        """
        Re-size the volume.

        Note: 'is_infinite' needs to be set to True in order to resize an
        Infinite Volume.
        """
        if self.parameters.get('sizing_method') is not None:
            return self.rest_resize_volume()

        vol_size_zapi, vol_name_zapi = ['volume-size-async', 'volume-name']\
            if (self.parameters['is_infinite'] or self.volume_style == 'flexgroup')\
            else ['volume-size', 'volume']
        volume_resize = netapp_utils.zapi.NaElement.create_node_with_children(
            vol_size_zapi, **{vol_name_zapi: self.parameters['name'],
                              'new-size': str(self.parameters['size'])})
        try:
            result = self.server.invoke_successfully(volume_resize, enable_tunneling=True)
            if vol_size_zapi == 'volume-size-async':
                self.check_invoke_result(result, 'resize')
            self.ems_log_event("volume-resize")
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error re-sizing volume %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        return None

    def start_encryption_conversion(self, encrypt_destination):
        if encrypt_destination:
            zapi = netapp_utils.zapi.NaElement.create_node_with_children(
                'volume-encryption-conversion-start', **{'volume': self.parameters['name']})
            try:
                self.server.invoke_successfully(zapi, enable_tunneling=True)
                self.ems_log_event("volume-encryption-conversion-start")
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error enabling encryption for volume %s: %s'
                                      % (self.parameters['name'], to_native(error)),
                                      exception=traceback.format_exc())
            if self.parameters.get('wait_for_completion'):
                self.wait_for_volume_encryption_conversion()
        else:
            self.module.warn('disabling encryption requires cluster admin permissions.')
            self.move_volume(encrypt_destination)

    def change_volume_state(self, call_from_delete_vol=False):
        """
        Change volume's state (offline/online).
        """
        if self.parameters['is_online'] and not call_from_delete_vol:    # Desired state is online, setup zapi APIs respectively
            vol_state_zapi, vol_name_zapi, action = ['volume-online-async', 'volume-name', 'online']\
                if (self.parameters['is_infinite'] or self.volume_style == 'flexgroup')\
                else ['volume-online', 'name', 'online']
        else:   # Desired state is offline, setup zapi APIs respectively
            vol_state_zapi, vol_name_zapi, action = ['volume-offline-async', 'volume-name', 'offline']\
                if (self.parameters['is_infinite'] or self.volume_style == 'flexgroup')\
                else ['volume-offline', 'name', 'offline']
            volume_unmount = netapp_utils.zapi.NaElement.create_node_with_children(
                'volume-unmount', **{'volume-name': self.parameters['name']})
        volume_change_state = netapp_utils.zapi.NaElement.create_node_with_children(
            vol_state_zapi, **{vol_name_zapi: self.parameters['name']})

        errors = list()
        if not self.parameters['is_online'] or call_from_delete_vol:  # Unmount before offline
            try:
                self.server.invoke_successfully(volume_unmount, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                errors.append('Error unmounting volume %s: %s' % (self.parameters['name'], to_native(error)))
        try:
            result = self.server.invoke_successfully(volume_change_state, enable_tunneling=True)
            if self.volume_style == 'flexgroup' or self.parameters['is_infinite']:
                self.check_invoke_result(result, action)
            self.ems_log_event("change-state")
        except netapp_utils.zapi.NaApiError as error:
            state = "online" if self.parameters['is_online'] and not call_from_delete_vol else "offline"
            errors.append('Error changing the state of volume %s to %s: %s' % (self.parameters['name'], state, to_native(error)))
            self.module.fail_json(msg=', '.join(errors),
                                  exception=traceback.format_exc())

    def create_volume_attribute(self, zapi_object, parent_attribute, attribute, value):
        """

        :param parent_attribute:
        :param child_attribute:
        :param value:
        :return:
        """
        if isinstance(parent_attribute, str):
            vol_attribute = netapp_utils.zapi.NaElement(parent_attribute)
            vol_attribute.add_new_child(attribute, value)
            zapi_object.add_child_elem(vol_attribute)
        else:
            zapi_object.add_new_child(attribute, value)
            parent_attribute.add_child_elem(zapi_object)

    def volume_modify_attributes(self, params):
        """
        modify volume parameter 'export_policy','unix_permissions','snapshot_policy','space_guarantee', 'percent_snapshot_space',
                                'qos_policy_group', 'qos_adaptive_policy_group'
        """
        if self.volume_style == 'flexgroup' or self.parameters['is_infinite']:
            vol_mod_iter = netapp_utils.zapi.NaElement('volume-modify-iter-async')
        else:
            vol_mod_iter = netapp_utils.zapi.NaElement('volume-modify-iter')
        attributes = netapp_utils.zapi.NaElement('attributes')
        vol_mod_attributes = netapp_utils.zapi.NaElement('volume-attributes')
        # Volume-attributes is split in to 25 sub categories
        if params and 'encrypt' in params:
            vol_mod_attributes.add_new_child('encrypt', self.na_helper.get_value_for_bool(False, self.parameters['encrypt']))
        # volume-space-attributes
        vol_space_attributes = netapp_utils.zapi.NaElement('volume-space-attributes')
        if self.parameters.get('space_guarantee') is not None:
            self.create_volume_attribute(vol_space_attributes, vol_mod_attributes,
                                         'space-guarantee', self.parameters['space_guarantee'])
        if self.parameters.get('percent_snapshot_space') is not None:
            self.create_volume_attribute(vol_space_attributes, vol_mod_attributes,
                                         'percentage-snapshot-reserve', str(self.parameters['percent_snapshot_space']))
        if self.parameters.get('space_slo') is not None:
            self.create_volume_attribute(vol_space_attributes, vol_mod_attributes, 'space-slo', self.parameters['space_slo'])
        # volume-snapshot-attributes
        vol_snapshot_attributes = netapp_utils.zapi.NaElement('volume-snapshot-attributes')
        if self.parameters.get('snapshot_policy') is not None:
            self.create_volume_attribute(vol_snapshot_attributes, vol_mod_attributes,
                                         'snapshot-policy', self.parameters['snapshot_policy'])
        if self.parameters.get('snapdir_access') is not None:
            self.create_volume_attribute(vol_snapshot_attributes, vol_mod_attributes,
                                         'snapdir-access-enabled',
                                         self.na_helper.get_value_for_bool(False, self.parameters['snapdir_access'], 'snapdir_access'))
        # volume-export-attributes
        if self.parameters.get('export_policy') is not None:
            self.create_volume_attribute(vol_mod_attributes, 'volume-export-attributes',
                                         'policy', self.parameters['export_policy'])
        # volume-security-attributes
        if self.parameters.get('unix_permissions') is not None or self.parameters.get('group_id') is not None or self.parameters.get('user_id') is not None:
            vol_security_attributes = netapp_utils.zapi.NaElement('volume-security-attributes')
            vol_security_unix_attributes = netapp_utils.zapi.NaElement('volume-security-unix-attributes')
            if self.parameters.get('unix_permissions') is not None:
                self.create_volume_attribute(vol_security_unix_attributes, vol_security_attributes,
                                             'permissions', self.parameters['unix_permissions'])
            if self.parameters.get('group_id') is not None:
                self.create_volume_attribute(vol_security_unix_attributes, vol_security_attributes,
                                             'group-id', str(self.parameters['group_id']))
            if self.parameters.get('user_id') is not None:
                self.create_volume_attribute(vol_security_unix_attributes, vol_security_attributes,
                                             'user-id', str(self.parameters['user_id']))
            vol_mod_attributes.add_child_elem(vol_security_attributes)
        if params and params.get('volume_security_style') is not None:
            self.create_volume_attribute(vol_mod_attributes, 'volume-security-attributes',
                                         'style', self.parameters['volume_security_style'])

        # volume-performance-attributes
        if self.parameters.get('atime_update') is not None:
            self.create_volume_attribute(vol_mod_attributes, 'volume-performance-attributes',
                                         'is-atime-update-enabled', self.na_helper.get_value_for_bool(False, self.parameters['atime_update'], 'atime_update'))
        # volume-qos-attributes
        if self.parameters.get('qos_policy_group') is not None:
            self.create_volume_attribute(vol_mod_attributes, 'volume-qos-attributes',
                                         'policy-group-name', self.parameters['qos_policy_group'])
        if self.parameters.get('qos_adaptive_policy_group') is not None:
            self.create_volume_attribute(vol_mod_attributes, 'volume-qos-attributes',
                                         'adaptive-policy-group-name', self.parameters['qos_adaptive_policy_group'])
        # volume-comp-aggr-attributes
        if params and params.get('tiering_policy') is not None:
            self.create_volume_attribute(vol_mod_attributes, 'volume-comp-aggr-attributes',
                                         'tiering-policy', self.parameters['tiering_policy'])
        # volume-state-attributes
        if self.parameters.get('nvfail_enabled') is not None:
            self.create_volume_attribute(vol_mod_attributes, 'volume-state-attributes', 'is-nvfail-enabled', str(self.parameters['nvfail_enabled']))
        # volume-dr-protection-attributes
        if self.parameters.get('vserver_dr_protection') is not None:
            self.create_volume_attribute(vol_mod_attributes, 'volume-vserver-dr-protection-attributes',
                                         'vserver-dr-protection', self.parameters['vserver_dr_protection'])
        # volume-id-attributes
        if self.parameters.get('comment') is not None:
            self.create_volume_attribute(vol_mod_attributes, 'volume-id-attributes',
                                         'comment', self.parameters['comment'])
        # End of Volume-attributes sub attributes
        attributes.add_child_elem(vol_mod_attributes)
        query = netapp_utils.zapi.NaElement('query')
        vol_query_attributes = netapp_utils.zapi.NaElement('volume-attributes')
        self.create_volume_attribute(vol_query_attributes, 'volume-id-attributes',
                                     'name', self.parameters['name'])
        query.add_child_elem(vol_query_attributes)
        vol_mod_iter.add_child_elem(attributes)
        vol_mod_iter.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(vol_mod_iter, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            error_msg = to_native(error)
            if 'volume-comp-aggr-attributes' in error_msg:
                error_msg += ". Added info: tiering option requires 9.4 or later."
            self.wrap_fail_json(msg='Error modifying volume %s: %s'
                                % (self.parameters['name'], error_msg),
                                exception=traceback.format_exc())

        self.ems_log_event("volume-modify")
        failures = result.get_child_by_name('failure-list')
        # handle error if modify space, policy, or unix-permissions parameter fails
        if failures is not None:
            error_msgs = list()
            for return_info in ('volume-modify-iter-info', 'volume-modify-iter-async-info'):
                if failures.get_child_by_name(return_info) is not None:
                    error_msgs.append(failures.get_child_by_name(return_info).get_child_content('error-message'))
            if error_msgs and any([x is not None for x in error_msgs]):
                self.wrap_fail_json(msg="Error modifying volume %s: %s"
                                    % (self.parameters['name'], ' --- '.join(error_msgs)),
                                    exception=traceback.format_exc())
        if self.volume_style == 'flexgroup' or self.parameters['is_infinite']:
            success = result.get_child_by_name('success-list')
            success = success.get_child_by_name('volume-modify-iter-async-info')
            results = dict()
            for key in ('status', 'jobid'):
                if success and success.get_child_by_name(key):
                    results[key] = success[key]
            status = results.get('status')
            if status == 'in_progress' and 'jobid' in results:
                if self.parameters['time_out'] == 0:
                    return
                error = self.check_job_status(results['jobid'])
                if error is None:
                    return
                self.wrap_fail_json(msg='Error when modifying volume: %s' % error)
            self.wrap_fail_json(msg='Unexpected error when modifying volume: result is: %s' % str(result.to_string()))

    def volume_mount(self):
        """
        Mount an existing volume in specified junction_path
        :return: None
        """
        vol_mount = netapp_utils.zapi.NaElement('volume-mount')
        vol_mount.add_new_child('volume-name', self.parameters['name'])
        vol_mount.add_new_child('junction-path', self.parameters['junction_path'])
        try:
            self.server.invoke_successfully(vol_mount, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error mounting volume %s on path %s: %s'
                                  % (self.parameters['name'], self.parameters['junction_path'],
                                     to_native(error)), exception=traceback.format_exc())

    def volume_unmount(self):
        """
        Unmount an existing volume
        :return: None
        """
        vol_unmount = netapp_utils.zapi.NaElement.create_node_with_children(
            'volume-unmount', **{'volume-name': self.parameters['name']})
        try:
            self.server.invoke_successfully(vol_unmount, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error unmounting volume %s: %s'
                                  % (self.parameters['name'], to_native(error)), exception=traceback.format_exc())

    def modify_volume(self, modify):
        '''Modify volume action'''
        attributes = modify.keys()
        # order matters here, if both is_online and mount in modify, must bring the volume online first.
        if 'is_online' in attributes:
            self.change_volume_state()
        for attribute in attributes:
            if attribute in ['space_guarantee', 'export_policy', 'unix_permissions', 'group_id', 'user_id', 'tiering_policy',
                             'snapshot_policy', 'percent_snapshot_space', 'snapdir_access', 'atime_update', 'volume_security_style',
                             'nvfail_enabled', 'space_slo', 'qos_policy_group', 'qos_adaptive_policy_group', 'vserver_dr_protection', 'comment']:
                self.volume_modify_attributes(modify)
                break
        if 'snapshot_auto_delete' in attributes:
            self.set_snapshot_auto_delete()
        if 'junction_path' in attributes:
            if modify.get('junction_path') == '':
                self.volume_unmount()
            else:
                self.volume_mount()
        if 'size' in attributes:
            self.resize_volume()
        if 'aggregate_name' in attributes:
            # keep it last, as it may take some time
            # handle change in encryption as part of the move
            self.move_volume(self.parameters.get('encrypt'))
        elif 'encrypt' in attributes:
            self.start_encryption_conversion(self.parameters['encrypt'])

    def compare_chmod_value(self, current):
        """
        compare current unix_permissions to desire unix_permissions.
        :return: True if the same, False it not the same or desire unix_permissions is not valid.
        """
        desire = self.parameters
        if current is None:
            return False
        octal_value = ''
        unix_permissions = desire['unix_permissions']
        if unix_permissions.isdigit():
            return int(current['unix_permissions']) == int(unix_permissions)
        else:
            if len(unix_permissions) != 12:
                return False
            if unix_permissions[:3] != '---':
                return False
            for i in range(3, len(unix_permissions), 3):
                if unix_permissions[i] not in ['r', '-'] or unix_permissions[i + 1] not in ['w', '-']\
                        or unix_permissions[i + 2] not in ['x', '-']:
                    return False
                group_permission = self.char_to_octal(unix_permissions[i:i + 3])
                octal_value += str(group_permission)
            return int(current['unix_permissions']) == int(octal_value)

    def char_to_octal(self, chars):
        """
        :param chars: Characters to be converted into octal values.
        :return: octal value of the individual group permission.
        """
        total = 0
        if chars[0] == 'r':
            total += 4
        if chars[1] == 'w':
            total += 2
        if chars[2] == 'x':
            total += 1
        return total

    def get_volume_style(self, current):
        '''Get volume style, infinite or standard flexvol'''
        if current is not None:
            return current.get('style_extended')
        if self.parameters.get('aggr_list') or self.parameters.get('aggr_list_multiplier') or self.parameters.get('auto_provision_as'):
            return 'flexgroup'
        return None

    def get_job(self, jobid, server):
        """
        Get job details by id
        """
        job_get = netapp_utils.zapi.NaElement('job-get')
        job_get.add_new_child('job-id', jobid)
        try:
            result = server.invoke_successfully(job_get, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            if to_native(error.code) == "15661":
                # Not found
                return None
            self.wrap_fail_json(msg='Error fetching job info: %s' % to_native(error),
                                exception=traceback.format_exc())
        job_info = result.get_child_by_name('attributes').get_child_by_name('job-info')
        results = {
            'job-progress': job_info['job-progress'],
            'job-state': job_info['job-state']
        }
        if job_info.get_child_by_name('job-completion') is not None:
            results['job-completion'] = job_info['job-completion']
        else:
            results['job-completion'] = None
        return results

    def check_job_status(self, jobid):
        """
        Loop until job is complete
        """
        server = self.server
        sleep_time = 5
        time_out = self.parameters['time_out']
        results = self.get_job(jobid, server)
        error = 'timeout'

        while time_out > 0:
            results = self.get_job(jobid, server)
            # If running as cluster admin, the job is owned by cluster vserver
            # rather than the target vserver.
            if results is None and server == self.server:
                results = netapp_utils.get_cserver(self.server)
                server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=results)
                continue
            if results is None:
                error = 'cannot locate job with id: %d' % int(jobid)
                break
            if results['job-state'] in ('queued', 'running'):
                time.sleep(sleep_time)
                time_out -= sleep_time
                continue
            if results['job-state'] in ('success', 'failure'):
                break
            else:
                self.wrap_fail_json(msg='Unexpected job status in: %s' % repr(results))

        if results is not None:
            if results['job-state'] == 'success':
                error = None
            elif results['job-state'] in ('queued', 'running'):
                error = 'job completion exceeded expected timer of: %s seconds' % \
                        self.parameters['time_out']
            else:
                if results['job-completion'] is not None:
                    error = results['job-completion']
                else:
                    error = results['job-progress']
        return error

    def check_invoke_result(self, result, action):
        '''
        check invoked api call back result.
        '''
        results = dict()
        for key in ('result-status', 'result-jobid'):
            if result.get_child_by_name(key):
                results[key] = result[key]
        status = results.get('result-status')
        if status == 'in_progress' and 'result-jobid' in results:
            if self.parameters['time_out'] == 0:
                return
            error = self.check_job_status(results['result-jobid'])
            if error is None:
                return
            else:
                self.wrap_fail_json(msg='Error when %s volume: %s' % (action, error))
        if status == 'failed':
            self.wrap_fail_json(msg='Operation failed when %s volume.' % action)

    def set_efficiency_attributes(self, options):
        for key, attr in self.sis_keys2zapi_set.items():
            value = self.parameters.get(key)
            if value is not None:
                if self.argument_spec[key]['type'] == 'bool':
                    value = self.na_helper.get_value_for_bool(False, value)
                options[attr] = value
        # ZAPI requires compression to be set for inline-compression
        if options.get('enable-inline-compression') == 'true' and 'enable-compression' not in options:
            options['enable-compression'] = 'true'

    def set_efficiency_config(self):
        '''Set efficiency policy and compression attributes'''
        options = {'path': '/vol/' + self.parameters['name']}
        efficiency_enable = netapp_utils.zapi.NaElement.create_node_with_children('sis-enable', **options)
        try:
            self.server.invoke_successfully(efficiency_enable, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            # Error 40043 denotes an Operation has already been enabled.
            if to_native(error.code) == "40043":
                pass
            else:
                self.wrap_fail_json(msg='Error enable efficiency on volume %s: %s'
                                    % (self.parameters['name'], to_native(error)),
                                    exception=traceback.format_exc())

        self.set_efficiency_attributes(options)
        efficiency_start = netapp_utils.zapi.NaElement.create_node_with_children('sis-set-config', **options)
        try:
            self.server.invoke_successfully(efficiency_start, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.wrap_fail_json(msg='Error setting up efficiency attributes on volume %s: %s'
                                % (self.parameters['name'], to_native(error)),
                                exception=traceback.format_exc())

    def set_efficiency_config_async(self):
        """Set efficiency policy and compression attributes in asynchronous mode"""
        options = {'volume-name': self.parameters['name']}
        efficiency_enable = netapp_utils.zapi.NaElement.create_node_with_children('sis-enable-async', **options)
        try:
            result = self.server.invoke_successfully(efficiency_enable, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.wrap_fail_json(msg='Error enable efficiency on volume %s: %s'
                                % (self.parameters['name'], to_native(error)),
                                exception=traceback.format_exc())
        self.check_invoke_result(result, 'enable efficiency on')

        self.set_efficiency_attributes(options)
        efficiency_start = netapp_utils.zapi.NaElement.create_node_with_children('sis-set-config-async', **options)
        try:
            result = self.server.invoke_successfully(efficiency_start, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.wrap_fail_json(msg='Error setting up efficiency attributes on volume %s: %s'
                                % (self.parameters['name'], to_native(error)),
                                exception=traceback.format_exc())
        self.check_invoke_result(result, 'set efficiency policy on')

    def get_efficiency_info(self, return_value):
        """
        get the name of the efficiency policy assigned to volume, as well as compression values
        if attribute does not exist, set its value to None
        :return: update return_value dict.
        """
        sis_info = netapp_utils.zapi.NaElement('sis-get-iter')
        sis_status_info = netapp_utils.zapi.NaElement('sis-status-info')
        sis_status_info.add_new_child('path', '/vol/' + self.parameters['name'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(sis_status_info)
        sis_info.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(sis_info, True)
        except netapp_utils.zapi.NaApiError as error:
            # Don't error out if efficiency settings cannot be read.  We'll fail if they need to be set.
            if error.message.startswith('Insufficient privileges: user ') and error.message.endswith(' does not have read access to this resource'):
                self.issues.append('cannot read volume efficiency options (as expected when running as vserver): %s' % to_native(error))
                return
            self.wrap_fail_json(msg='Error fetching efficiency policy for volume %s : %s'
                                % (self.parameters['name'], to_native(error)),
                                exception=traceback.format_exc())
        for key in self.sis_keys2zapi_get:
            return_value[key] = None
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            sis_attributes = result.get_child_by_name('attributes-list'). get_child_by_name('sis-status-info')
            for key, attr in self.sis_keys2zapi_get.items():
                value = sis_attributes.get_child_content(attr)
                if self.argument_spec[key]['type'] == 'bool':
                    value = self.na_helper.get_value_for_bool(True, value)
                return_value[key] = value

    def modify_volume_efficiency_config(self, efficiency_config_modify_value):
        if efficiency_config_modify_value == 'async':
            self.set_efficiency_config_async()
        else:
            self.set_efficiency_config()

    def set_snapshot_auto_delete(self):
        options = {'volume': self.parameters['name']}
        desired_options = self.parameters['snapshot_auto_delete']
        for key, value in desired_options.items():
            options['option-name'] = key
            options['option-value'] = str(value)
            snapshot_auto_delete = netapp_utils.zapi.NaElement.create_node_with_children('snapshot-autodelete-set-option', **options)
            try:
                self.server.invoke_successfully(snapshot_auto_delete, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.wrap_fail_json(msg='Error setting snapshot auto delete options for volume %s: %s'
                                    % (self.parameters['name'], to_native(error)),
                                    exception=traceback.format_exc())

    def rehost_volume(self):
        volume_rehost = netapp_utils.zapi.NaElement.create_node_with_children(
            'volume-rehost', **{'vserver': self.parameters['from_vserver'],
                                'destination-vserver': self.parameters['vserver'],
                                'volume': self.parameters['name']})
        if self.parameters.get('auto_remap_luns') is not None:
            volume_rehost.add_new_child('auto-remap-luns', str(self.parameters['auto_remap_luns']))
        if self.parameters.get('force_unmap_luns') is not None:
            volume_rehost.add_new_child('force-unmap-luns', str(self.parameters['force_unmap_luns']))
        try:
            self.cluster.invoke_successfully(volume_rehost, enable_tunneling=True)
            self.ems_log_event("volume-rehost")
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error rehosting volume %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def snapshot_restore_volume(self):
        snapshot_restore = netapp_utils.zapi.NaElement.create_node_with_children(
            'snapshot-restore-volume', **{'snapshot': self.parameters['snapshot_restore'],
                                          'volume': self.parameters['name']})
        if self.parameters.get('force_restore') is not None:
            snapshot_restore.add_new_child('force', str(self.parameters['force_restore']))
        if self.parameters.get('preserve_lun_ids') is not None:
            snapshot_restore.add_new_child('preserve-lun-ids', str(self.parameters['preserve_lun_ids']))
        try:
            self.server.invoke_successfully(snapshot_restore, enable_tunneling=True)
            self.ems_log_event("snapshot-restore-volume")
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error restoring volume %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def adjust_size(self, current, after_create):
        """
        ignore small change in size by resetting expectations
        """
        if after_create:
            # ignore change in size immediately after a create:
            self.parameters['size'] = current['size']
        elif self.parameters['size_change_threshold'] > 0:
            if 'size' in current and self.parameters.get('size') is not None:
                # ignore a less than XX% difference
                if abs(current['size'] - self.parameters['size']) * 100 / current['size'] < self.parameters['size_change_threshold']:
                    self.parameters['size'] = current['size']

    def set_modify_dict(self, current, after_create=False):
        '''Fill modify dict with changes'''
        # snapshot_auto_delete's value is a dict, get_modified_attributes function doesn't support dict as value.
        auto_delete_info = current.pop('snapshot_auto_delete', None)
        # ignore small changes in size by adjusting self.parameters['size']
        self.adjust_size(current, after_create)
        modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if modify is not None and 'type' in modify:
            msg = "Error: changing a volume from one type to another is not allowed."
            msg += '  Current: %s, desired: %s.' % (current['type'], self.parameters['type'])
            self.module.fail_json(msg=msg)
        desired_style = self.get_volume_style(None)
        if desired_style is not None and desired_style != self.volume_style:
            msg = "Error: changing a volume from one backend to another is not allowed."
            msg += '  Current: %s, desired: %s.' % (self.volume_style, desired_style)
            self.module.fail_json(msg=msg)
        if self.parameters.get('snapshot_auto_delete') is not None:
            auto_delete_modify = self.na_helper.get_modified_attributes(auto_delete_info,
                                                                        self.parameters['snapshot_auto_delete'])
            if len(auto_delete_modify) > 0:
                modify['snapshot_auto_delete'] = auto_delete_modify
        return modify

    def take_modify_actions(self, modify):
        if modify.get('is_online'):
            # when moving to online, include parameters that get does not return when volume is offline
            for field in ['volume_security_style', 'group_id', 'user_id', 'percent_snapshot_space']:
                if self.parameters.get(field) is not None:
                    modify[field] = self.parameters[field]
        self.modify_volume(modify)

        if any([modify.get(key) is not None for key in self.sis_keys2zapi_get]):
            if self.parameters.get('is_infinite') or self.volume_style == 'flexgroup':
                efficiency_config_modify = 'async'
            else:
                efficiency_config_modify = 'sync'
            self.modify_volume_efficiency_config(efficiency_config_modify)

    def apply(self):
        '''Call create/modify/delete operations'''
        response = None
        modify_after_create = None
        current = self.get_volume()
        self.volume_style = self.get_volume_style(current)
        if self.volume_style == 'flexgroup' and self.parameters.get('aggregate_name') is not None:
            self.module.fail_json(msg='Error: aggregate_name option cannot be used with FlexGroups.')
        rename, rehost, snapshot_restore, cd_action, modify = None, None, None, None, None
        # rename and create are mutually exclusive
        if self.parameters.get('from_name'):
            rename = self.na_helper.is_rename_action(self.get_volume(self.parameters['from_name']), current)
        elif self.parameters.get('from_vserver'):
            rehost = True
            self.na_helper.changed = True
        elif self.parameters.get('snapshot_restore'):
            snapshot_restore = True
            self.na_helper.changed = True
        else:
            cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if self.parameters.get('unix_permissions') is not None:
            # current stores unix_permissions' numeric value.
            # unix_permission in self.parameter can be either numeric or character.
            if self.compare_chmod_value(current) or not self.parameters['is_online']:
                # don't change if the values are the same
                # can't change permissions if not online
                del self.parameters['unix_permissions']
        if cd_action is None and rename is None and rehost is None and self.parameters['state'] == 'present':
            modify = self.set_modify_dict(current)
        if self.parameters.get('nas_application_template') is not None:
            application = self.get_application()
            changed = self.na_helper.changed
            modify_app = self.na_helper.get_modified_attributes(application, self.parameters.get('nas_application_template'))
            # restore current change state, as we ignore this
            if modify_app:
                self.na_helper.changed = changed
                self.module.warn('Modifying an app is not supported at present: ignoring: %s' % str(modify_app))

        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if rename:
                    self.rename_volume()
                if rehost:
                    self.rehost_volume()
                if snapshot_restore:
                    self.snapshot_restore_volume()
                if cd_action == 'create':
                    response = self.create_volume()
                    # if we create using ZAPI and modify only options are set (snapdir_access or atime_update), we need to run a modify.
                    # The modify also takes care of efficiency (sis) parameters and snapshot_auto_delete.
                    # If we create using REST application, some options are not available, we may need to run a modify.
                    current = self.get_volume()
                    if current:
                        self.volume_created = True
                        modify_after_create = self.set_modify_dict(current, after_create=True)
                        if modify_after_create:
                            self.take_modify_actions(modify_after_create)
                    # restore this, as set_modify_dict could set it to False
                    self.na_helper.changed = True
                elif cd_action == 'delete':
                    self.parameters['uuid'] = current['uuid']
                    self.delete_volume(current)
                elif modify:
                    self.parameters['uuid'] = current['uuid']
                    self.take_modify_actions(modify)

        result = dict(
            changed=self.na_helper.changed
        )
        if response is not None:
            result['response'] = response
        if modify:
            result['modify'] = modify
        if modify_after_create:
            result['modify_after_create'] = modify_after_create
        self.module.exit_json(**result)

    def ems_log_event(self, state):
        '''Autosupport log event'''
        if state == 'create':
            message = "A Volume has been created, size: " + \
                str(self.parameters['size']) + str(self.parameters['size_unit'])
        elif state == 'volume-delete':
            message = "A Volume has been deleted"
        elif state == 'volume-move':
            message = "A Volume has been moved"
        elif state == 'volume-rename':
            message = "A Volume has been renamed"
        elif state == 'volume-resize':
            message = "A Volume has been resized to: " + \
                str(self.parameters['size']) + str(self.parameters['size_unit'])
        elif state == 'volume-rehost':
            message = "A Volume has been rehosted"
        elif state == 'snapshot-restore-volume':
            message = "A Volume has been restored by snapshot"
        elif state == 'volume-change':
            message = "A Volume state has been changed"
        else:
            message = "na_ontap_volume has been called"
        netapp_utils.ems_log_event(
            "na_ontap_volume", self.server, event=message)


def main():
    '''Apply volume operations from playbook'''
    obj = NetAppOntapVolume()
    obj.apply()


if __name__ == '__main__':
    main()
