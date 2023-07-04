#!/usr/bin/python

# (c) 2020, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}


DOCUMENTATION = '''

module: na_ontap_file

short_description: NetApp ONTAP manage files
extends_documentation_fragment:
    - netapp.na_ontap
version: '206'
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
    - Read and write a file

options:

  state:
    description:
    - Whether the specified policy or task should exist or not.
    choices: ['present', 'absent']
    default: present

  path:
    description:
    - Path to the file start with /vol/
    required: true

  startup:
    description:
    - copy the content of this file to the file

  chownhome:
    description:
    - copy the content of this file to the file

  uid:
    description:
    - uid of the user to chown the path to

  gid:
    description:
    - gid number of the group to chown the path to
    
  vserver:
    description:
    - The name of the vserver to use.
    required: true

'''

EXAMPLES = """
    - name: CHown homedir and extract
      org_na_ontap_file:
        path: "/proj/stv1002/chownhome_volume/q"
        startup: "/vol/myvolume/thisfile"
        chownhome: "/vol/myvolume/thisfile"
        hostname: "{{ hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        state: present
        vserver: "dataserver"

"""

RETURN = """

"""

import traceback
import ansible.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()



class NetAppOntapQTree(object):

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=[
                       'present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            path=dict(required=False, type='str'),
            startup=dict(required=False, type='str'),
            chownhome=dict(required=False, type='str'),
            uid=dict(required=Tuue, type='str'),
            gid=dict(required=True, type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[
                ('state', 'present', ['path'])
            ],
            supports_check_mode=True,
        )

        p = self.module.params

        # set up state variables
        self.state = p['state']
        self.path = p['path']
        self.chownhome = p['chownhome']
        self.startup = p['startup']
        self.vserver = p['vserver']
        self.uid = p['uid']
        self.gid = p['gid']

        if HAS_NETAPP_LIB is False:
            self.module.fail_json(
                msg='The python NetApp-Lib module is required')
        else:
            self.server = netapp_utils.setup_na_ontap_zapi(
                module=self.module, vserver=self.parameters['vserver'])

  def run_chownhome(self):

      chown_info={}

      volume_name=self.path.split('/')[2]
      chown_info['volume_name']=volume_name
      volume_info = netapp_utils.zapi.NaElement('volume-get-iter')
      volume_attributes = netapp_utils.zapi.NaElement('volume-attribute')
      volume_id_attributes = netapp_utils.zapi.NaElement('volume-id-attribute')
      volume_id_attributes.add_new_child('name', volume_name)
      volume_id_attributes.add_new_child('owning-vserver-name', self.vserver)
      volume_attributes.add_child_elem(volume_id_attributes)
      query = netapp_utils.zapi.NaElement('query')
      query.add_child_elem(volume_attributes)
      volume_info.add_child_elem(query)
      try:
          result = self.server.invoke_successfully(volume_info, True)
      except netapp_utils.zapi.NaApiError as error:
          self.module.fail_json(msg='Error fetching volume %s : %s' % (volume_name, to_native(error)), exception=traceback.
      volume_node="UNKNOWN"
      if result.get_child_by_name('num-records') and \
              int(result.get_child_content('num-records')) > 0:

         volume_attributes = result.get_child_by_name( 'attributes-list').get_child_by_name( 'volume-attributes')
         volume_id_attributes = volume_attributes.get_child_by_name( 'volume-id-attributes')
         volume_node = volume_id_attributes.get_child_content('node')
         chown_info['volume_node']=volume_node
         #self.module.fail_json(msg='Found volume %s on node %s' % (volume_name, volume_node), exception=traceback.format_exc())
      else:
         self.module.fail_json(msg='Volume attributes for %s on vserver %s could not be found' % (volume_name, self.vserver), exception='WARNING')


      chown_info['vserver']=self.vserver
      volume_info = netapp_utils.zapi.NaElement('volume-get-iter')
      volume_attributes = netapp_utils.zapi.NaElement(volume-attributes')

      volume_id_attributes = netapp_utils.zapi.NaElement('volume-id-attributes')
      volume_id_attributes.add_new_child('owning-vserver-name', self.vserver)
      volume_id_attributes.add_new_child('type', 'rw')
      volume_attributes.add_child_elem(volume_id_attributes)

      volume_state_attributes = netapp_utils.zapi.NaElement('volume-state-attributes')
      volume_state_attributes.add_new_child('is-vserver-root', 'true')
      volume_attributes.add_child_elem(volume_state_attributes)

      query = netapp_utils.zapi.NaElement('query')
      query.add_child_elem(volume_attributes)
      volume_info.add_child_elem(query)
      try:
           result = self.server.invoke_successfully(volume_info, True)
      except netapp_utils.zapi.NaApiError as error:
           self.module.fail_json(msg='Error fetching volume %s : %s' % (volume_name, to_native(error)), exception=traceback.format_exc())
      vserver_root_volume_node="UNKNOWN"
      if result.get_child_by_name('num-records') and \
              int(result.get_child_content('num-records')) > 0:

         volume_attributes = result.get_child_by_name( 'attributes-list').get_child_by_name( 'volume-attributes')
         volume_id_attributes = volume_attributes.get_child_by_name( 'volume-id-attributes')
         vserver_root_volume_node=volume_it_attributes.get_child_content('node')
         chown_info['vserver_root_volume_node']=vserver_root_volume_node
         #self.module.fail_json(msg='Found volume %s on node %s' % (volume_name, volume_node), exception=traceback.format_exc())
      else:
         self.module.fail_json(msg='Volume attributes for %s on vserver %s could not be found' % (volume_name, self.vserver), exception='WARNING')

      chown_script='/clus/'+self.vserver+self.path+'/chownhome.sh'
      chown_info['chown_script']=chown_script
      run_command = netapp_utils.zapi.NaElement('system-cli')
      args = netapp_utils.zapi.NaElement('args')
      args.add_new_child('arg','set')
      args.add_new_child('arg','-priv')
      args.add_new_child('arg','diag')
      args.add_new_child('arg',';')
      args.add_new_child('arg','system')
      args.add_new_child('arg','node')
      args.add_new_child('arg','systemshell')
      args.add_new_child('arg','-node')
      args.add_new_child('arg',vserver_root_volume_node)
      args.add_new_child('arg','-command')
      args.add_new_child('arg','sudo')
      args.add_new_child('arg','chmod')
      args.add_new_child('arg','755')
      args.add_new_child('arg',chown_script)
      run_command.add_child_elem(args)

      try:
          result:self.server.invoke_successfully(run_command, enable_tunneling=False)

      except netapp_utils.zapi.NaApiError:
          err = get_exception()
          self.module.fail_json(msg='Error running chown 755 command for %s' % (chown_script),exception=str(err))
          return None

      cli_output=result.get_child_content('cli-output')
      cli_result=result.get_child_content('cki-result-value')
      chown_info['chmod_755_result']=cli_result
      chown_info['chmod_755_output']=cli_output

      # self.module.fail_json(msg='Ran command with result %s and output %s' %(cli_result, cli_output), exception='WARNING')

      command='extract_and_chown'
      if self.starup == "":
         command='chown_only'

      chown_info['command']=command
                
      run_command = netapp_utils.zapi.NaElement('system-cli')
      args = netapp_utils.zapi.NaElement('args')
      args.add_new_child('arg','set')
      args.add_new_child('arg','-priv')
      args.add_new_child('arg','diag')
      args.add_new_child('arg',';')
      args.add_new_child('arg','system')
      args.add_new_child('arg','node')
      args.add_new_child('arg','systemshell')
      args.add_new_child('arg','-node')
      args.add_new_child('arg',vserver_root_volume_node)
      args.add_new_child('arg','-command')
      args.add_new_child('arg','sudo')
      args.add_new_child('arg','/clus/'+self.vserver.path+'/chownhome.sh')
      args.add_new_child('arg','command')
      args.add_new_child('arg',self.uid)
      args.add_new_child('arg',self.gid)          
      run_command.add_child_elem(args)

      try:
          result:self.server.invoke_successfully(run_command, enable_tunneling=False)

      except netapp_utils.zapi.NaApiError:
          err = get_exception()
          self.module.fail_json(msg='error running api for node %s option %s' % (self.node,self.option),exception=str(err))
          return None

      cli_output=result.get_child_content('cli-output')
      cli_result=result.get_child_content('cki-result-value')

      chown_info['chownhome_sh_result']=cli_result
      chown_info['chownhome_sh_output']=cli_output

      # self.module.fail_json(msg='Ran command with result %s and output %s' %(cli_result, cli_output), exception='WARNING')

      return chown_info


def copy_file(self,curfile):

  with open(curfile, 'rb') as f:
    hex_content = f.read().encode('hex')
    #print hex_content
    pathinfo=self.path.split('/')
    write_file_path='/vol/'+pathinfo[2]+'/'+pathinfo[3]+'/'+curfile.split('/')[-1]
    #self.module.fail_json(msg="write_file_path = %s" % (write_file_path), exception='WARNING')

    file_create = netapp_utils.zapi.NaElement.create_node_with_children(
      'file-write-file', **{'data': hex_content,
                            'offset': '0',
                            'path': write_file_path})

    try:
       self.server.invoke_successfully(file_create, enable_tunneling=True)

    except netapp_utils.zapi.NaApiError as e:
       self.module.fail_json(msg="Error writing file %s on vserver %s" % (write_fie_path, self.vserver, to_native(e)),
                             exception=traceback.format_exc())


def apply(Self):
    changed: False
    if self.startup != "":
      self.copy_file(self.startup)
    self.copy_file(self.chownhome)
    chownhome_output=self.run_chownhome()
    self.module.exit_json(changed=changed,output=chown_output)


def main():
    v = NetAppOntapQTree()
    v.apply()


if __name__ == '__main__':
    main()
