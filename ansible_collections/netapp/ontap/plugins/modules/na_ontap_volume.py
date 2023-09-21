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

            is_online = (current_state == "online")
            return_value = {
                'name': vol_name,
                'size': current_size,
                'is_online': is_online
                'aggregate_name': aggregate_name,
                'ploicy': policy,
                'space_guarantee': space_guarantee,
                'qos_policy_group_name': policy_group_name,
            }

        return return_value

    def create_volume(self):
        '''Create ONTAP volume'''
        aggr_list = []
        aggr_multiplier = None
        if self.parameters.get('aggregate_name') is None and self.parameters.get('aggregate_list') is None:
            self.module.fail_json(msg='Error provisioning volume %s: \
                                  aggregate_name or aggregate_list is required'
                                  %s self.parameters['name'])

        elif self.parameters.get('aggregate_name') is not None and self.parameters.get('aggregate_list') is None:
            options = {'volume': self.parameters['name'],
                       'containing-aggr-name': self.parameters['aggregate_name'],
                       'size': str(self.parameters['size'])}
            if self.parameters.get('percent_snapshot_spact'):
                options['percentage-snapshot-reserve'] = self.parameters['percent_snapshot_space']
            if self.parameters.get('type'):
                 options['volume-type'] = self.parameters['type']
            if self.parameters.get('policy'):
                 options['export-policy'] = self.parameters['policy']
            if self.parameters.get('junction_path'):
                 options['junction-path'] = self.parameters['junction_path']
            if self.parameters.get('space_guarantee'):
                 options['space-reserve'] = self.parameters['space_guarantee']
            if self.parameters.get('volume_security_style'):
                 options['volume-security-style'] = self.parameters['volume_security_style']
            if self.parameters.get('snapshot_policy'):
                 options['snapshot-policy'] = self.parameters['snapshot_policy']
            if self.parameters.get('efficiency_policy'):
                 options['efficiency-policy'] = self.parameters['efficiency_policy']
            if self.parameters.get('qos_policy_group_name'):
                 options['qos-policy-group-name'] = self.parameters['qos_policy_group_name']
            volume_create = netapp_utils.zapi.NaElement.create_node_with_children('volume-create', **options)

        elif self.parameters.get('aggregate_name') is None and self.parameters.get('aggregate_list') is not None:
            possible_aggregate_list = self.parameters.get( 'aggregate_list' )
          ##
          ##
          ##
            ##
            ##
            ##
            ##
            ##
            ##
            ##
            ##
            ##
            ##
            aggr_multiplier = '1'
            if len( possible_aggregate_list ) < 1:
                self.module.fail_json( msg='Error provisioning flexgroup %s \
                                        of size %s: %s'
                                 % (self.parameters['name'], self.parameters['size'], to_native(error)),
                                 exception=traceback.format_exec())

            volume_create = netapp_utils.zapi.NaElement ( 'volume-create-async' )
            zapi_aggr_list = netapp_utils.zapi.NaElement ( 'aggr-list' )
            for aggr in possible_aggregate_list:
                zapi_aggr_list.add_new_child( 'aggr-name', aggr )
            volume_create.add_new_child( 'aggr-list-multiplier', str( aggr_multiplier ) )
            volume_create.add_new_child( 'size', str( self.parameters['size'] ) )
            volume_create.add_new_child( 'volume-name', str( self.parameters['name'] ) )
            volume_create.add_child_elem( zapi_aggr_list )

            if self.parameters.get('percent_snapshot_space'):
                volume_create.add_new_child( 'percentage-snapshot-reserve', str( self.parameters['percent_snapshot_space'] ) )
            if self.parameters.get('type'):
                volume_create.add_new_child( 'volume-type', self.parameters['type'] )
            if self.parameters.get('policy'):
                volume_create.add_new_child( 'export-policy', self.parameters['policy'] )
            if self.parameters.get('junction_path'):
                volume_create.add_new_child( 'junction-path', self.parameters['junction_path'] )
            if self.parameters.get('space_guarantee'):
                volume_create.add_new_child( 'space-reserve', self.parameters['space_guarantee'] )
            if self.parameters.get('volume_security_stype'):
                volume_create.add_new_child( 'volume-security-stype', self.parameters['volume_security_stype'] )
            if self.parameters.get('snapshot_policy'):
                volume_create.add_new_child( 'snapshot-policy', self.parameters['snapshot_policy'] )
            if self.parameters.get('efficiency_policy'):
                volume_create.add_new_child( 'efficiency-policy', self.parameters['efficiency_policy'] )
            if self.parameters.get('qos_policy_group_name'):
                volume_create.add_new_child( 'qos-policy-group-name', self.parameters['qos_policy_group_name'] )

        try:
            volume_create_output = self.server.invoke_successfully(volume_create,
                                            enable_tunneling=True)
            self.ems_log_event("volume-create")
            self.volume_create_facts = {}
            if aggr_list is not None:
                self.volume_create_facts['aggr-list'] = aggr_list
            if aggr multiplier is not None:
                self.volume_create_facts['aggr-list-multiplier'] = aggr_multiplier
                self.volume_create_jobid = volume_create_output.get_child_by_name( 'result-jobid' ).get_content()
                self.volume_create_facts['jobid'] = self.volume_create_jobid

        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error provisioning volume %s \
                                  of size %s: %s'
                                  % (self.parameters['name'], self.parameters['size'], to_native(error)),
                                  exception=traceback.format_exc())

        #if self.volume_create_jobid is not None:
        if aggr_multiplier is not None:
            ## Ok, we're dealing with a FlexGroup here since we've received a jobid
            ## Let's keep polling the cluster for the status of the job id
            time.sleep(5)
            retry_limt = 90
            retry = 0
            success = False

            while retry <= retry_limit and not success:
                retry+=1

                try:
                    job_info = netapp_utils.zapi.NaElement('job-get-iter')
                    query_details = netapp_utils.zapi.NaElement.create_node_with_children('job-info', **{'job-id': self.volume_create_jobid})
                    query = netapp_utils.zapi.NaElement('query')
                    query.add_child_elem(query_details)
                    job_info.add_child_elem(query)
                    ##
                    ##
                    ##
                    ##
                    result = self.server.invoke_successfully( job_info, enable_tunneling=False )
                    changed = True

               except:
                   err = get_exception()
                   self.module.fail_json(msg='Error gathering job info on job %s' %self.jobid, exceptions=str( err ))

               attr_list = result.get_child_by_name( 'attributes-list' )
               job_state = attr_list.get_child_by_name( 'job-info' ).get_child_by_name( 'job-state' ).get_content()

               if job_state == "running":
                   time.sleep(5)
               else:
                   success = True

            self.volume_create_facts['job-state'] = job_state


    def delete_volume(self, current):
        '''Delete ONTAP volume'''
        if self.parameters.get('is_infinite'):
            volume_delete = netapp_utils.zapi\
                .NaElement.create_node_with_children(
                    'volume-destory-async', **{'volume-name': self.parameters['name']})
        else:
            volume_delete = netapp_utils.zapi\
                .NaElement.create_node_with_children(
                    'volume-destroy', **{'name': self.parameters['name'],
                                         'unmount-and-offline': 'true'})
        try:
            self.server.invoke_successfully(volume_delete, enable_tunneling=True)
            self.ems_log_event("delete")
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting volume %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
          
    def move_volume(self):
        '''Move volume from source aggregate to destination aggregate'''
        volume_move = netapp_utils.zapi.NaElement.create_node_with_children(
            'volume-move-start', **{'source-volume': self.parameters['name'],
                                    'vserver': self.parameters['vserver'],
                                    'dest-aggr': self.parameters['aggregate_name']})
        try:
            self.cluster.invoke_successfully(volume_move,
                                             enable_tunneling=True)
            self.ems_log_event("volume-move")
        except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error moving volume %s: %s'
                                      % (self.parameters['name'], to_native(error)),
                                      exception=traceback.format_exc())
        
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
            self.server.invoke_successfully(volume_rename,
                                            enable_tunneling=True)
             self.ems_log_event("volume-rename")
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error renaming volume %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
    def expand_flexgroup(self):
        """
        Expand the flexgroup

        Note: 'is_infinite' needs to be set to True in order to rename an
        Infinite Volume.
        """
        flexgroup_expand = netapp_utils.zapi.NaElement.create_node_with_children(
            'volume-expand-async', **{'volume-name':      self.parameters['name'],
                                   'aggr-list-multiplier': '1',
                                     })

         zapi_aggr_list = netapp_utils.zapi.NaElement( 'aggr-list' )
         if self.parameters.get('aggregate_list') is not None:
           for aggr in self.parameters.get('aggregate_list'):
               zapi_aggr_list.add_new_child( 'aggr-name', aggr )
           flexgroup_expand.add_child_elem( zapi_aggr_list )
         else:
           self.module.fail_json(msg='No aggregate_list specified for expanding volume &s' % (self.parameters['name']),exception='ERROR' )
           
         try:
             self.server.invoke_successfully(flexgroup_expand,
                                             enable_tunneling=True)
             self.ems_log_event("volume-expand")
         except netapp_utils.zapi.NaApiError as error:
             self.module.fail_json(msg='Error expanding volume %s: %s'
                                   % (self.parameters['name'], to_native(error)),
                                   exception=traceback.format_exc())

         # self.module.fail_json(msg='Successfully expanded the volume %s' % (self.parameters['name']),exception='NOTICE' )


  
    def resize_volume(self):
        """
        Re-size the volume.

        Note: 'is_infinite' needs to be set to True in order to resize an
        Infinite Volume.
        """
        vol_size_zapi, vol_name_zapi = ['volume-size-async', 'volume-name'] if (self.parameters['is_infinite']\
            else ['volume-size', 'volume']
        volume_resize = netapp_utils.zapi.NaElement.create_node_with_children(
            vol_size_zapi, **{vol_name_zapi: self.parameters['name'],
                              'new-size': str(self.parameters['size'])})
        try:
            result = self.server.invoke_successfully(volume_resize, enable_tunneling=True)
            self.ems_log_event("volume-resize")
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error re-sizing volume %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def change_volume_state(self):
        """
        Change volume's state (offline/online).
        """
        if self.parameters['is_online'] # Desired state is online, setup zapi APIs respectively
            vol_state_zapi, vol_name_zapi, action = ['volume-online-async', 'volume-name'] if self.parameters['is_infinite']\
                else ['volume-online', 'name']
        else: # Desired state is offline, setup zapi APIs respectively
            vol_state_zapi, vol_name_zapi, action = ['volume-offline-async', 'volume-name'] if self.parameters['is_infinite']\
                else ['volume-offline', 'name']
          volume_unmount = netapp_utils.zapi.NaElement.create_node_with_children(
                'volume-unmount', **{'volume-name': self.parameters['name']})
        volume_change_state = netapp_utils.zapi.NaElement.create_node_with_children(
            vol_state_zapi, **{vol_name_zapi: self.parameters['name']})
        try:
            if not self.parameters['is_online']: # Unmount before offline
               self.server.invoke_successfully(volume_unmount, enable_tunneling=True)
           self.server.invoke_successfully(volume_change_state, enable_tunneling=True)
           self.ems_log_event("change-state")
        except netapp_utils.zapi.NaApiError as error:
            state = "online" if self.parameters['is_online'] else "offline"
            self.module.fail_json(msg='Error changing the state of volume %s to %s: %s'
                                  % (self.parameters['name'], state, to_native(errors)),
                                  exception=traceback.format_exc())

    def volume_modify_policy_space(self):
        """
        modify volume parameter 'policy' or 'space_gurantee'
        """
        #
        vol_mod_iter= netapp_utils.zapi.NaElement('volume-modify-iter')
        attributes = netapp_utils.zapi.NaElement('attributes')
        vol_mod_attributes = netapp_utils.zapi.NaElement('volume-attributes')f
        if self.parameters.get('policy'):
            vol_export_attributes = netapp_utils.zapi,NaElement(
                'volume-export-attibutes')
            vol_export_attributes.add_new_child('policy', self.parameters['policy'])
            vol_mod_attributes.add_child_elem(vol_export_attributes)
        if self.parameters.get('space_guarantee'):
            vol_space_attributes = netapp_utils.zapi.NaElement(
                'volume-space-attributes')
            vol_space_attributes.add_new_child(
                'space-gaurantee', self.parameters['space_guarantee'])
            vol_mod_attributes.add_child_elem(vol_space_attributes)
        if self.parameters.get('qos_policy_group_name'):
            vol_qos_attributes = netapp_utils.zapi.NaElement(
                'volume-qos-attributes')
            vol_qos_attributes.add_new_child(
                policy_group-name', self.parameters['qos_policy_group_name'])
            vol_mod_attributes.add_child_elem(vol_qos_attributes)
        attributes.add_child_elem(vol_mod_attributes)
        query = netapp_utils.zapi.NaElement('query')
        vol_query_attributes = netapp_utils.zapi.NaElement('volume-attributes')
        vol_id_attributes = netapp_utils.zapi.NaElement('volume-id-attributes')
        vol_id_attributes.add_new_child('name', self.parameters['name'])
        vol_query_attributes.add_child_elem(vol_id_attributes)
        query.add_child_elem(vol_query_attributes)
        vol_mod_iter.add_child_elem(attributes)
        vol_mod_iter.add_child_elem(query)
        try:
            result: self.server.invoke_successfully(vol_mod_iter, enable_tunneling=True)
            failure = result.get_child_by_name('failure-list')
            #
            if failure is not None and failures.get_child_by_name('volume-modify-iter-info') is not None:
                error_msg = failures.get_child_by_name('volume-modify-iter-info').get_child_content('error-message')
                self.module.fail_json(msg="Error modifying volume %s: %s"
                                      % (self.parameters['name'], error_msg),
                                      exception=traceback.format_exc())
            self.ems_log_event('volume-modify")
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying volume %s: %s'
                                  % (self.parameters['name'], to_native(error)),
                                  exception=traceback.foramt_exc())

    def modify_volume(self, modify):
        for attribute in modify.keys():
            if attribute == 'size':
                self.resize_volume()
            elif attrattribute == 'is_online':
                self.change_volume_state()
        elif attribute == 'aggregate_name':
            self.move_volume()
        else:
            self.volume_modify_policy_space()

    def apply(self):
        '''Call create/modify/delete operations'''
        current = self.get_volume()
        # expand, rename and create are mutually exclusive
        expand, rename, cd_action = None, None, None
        if self.parameters.get('from_name'):
            rename = self.na_helper.is_rename_action(self.get_volume(self.parameters['from_name']), current)
        else:
            if self.parameters.get('state') == 'expand':
              expand = 'True'
            else:
              cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify = self.na_helper.get_modified_attributes(current, self.paremeters)
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if rename:
                    self.rename_volume()
                if cd_action == 'create':
                    self.create_volume()
                elif cd_action == 'delete':
                    self.delete_volune()
                elif modify:
                    self.modify_volume(modify)
        else:
          if self.module.check_mode:
                pass
        else:
          if expand:
             self.expand_flexgroup()
             self.module.exit_json(changed='true')

        if cd_action == 'create':
            self.module.exit_json(changed=self.na_helper.changed,ansible_facts={'volume-create-faacts': self.volume_create_facts } )
        else:
             self.module_exit_json(changed=self.na_helper.changed)
                   
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
