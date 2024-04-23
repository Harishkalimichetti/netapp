#!/usr/bin/python
#

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
module: cdot_trigger_lsm_update
short_description: Issue a LSM Snapmirror update of a root volume
extends_documentation_fragment:
    - netapp.ontap
version_added: '2.3'
author: Jeroen Kleijer (jeroen.keijer_2@nxp.com)
description:
- Since Ansible doesn't appear to have a snapmirror-ls-update command,
this module was created to have ONTAP update the snapmirror of the root volume
options:
  vserver:
    description:
    - Name of the vserver to use.
    required: true
    default: None
'''

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pycompat24 import get_exception
import ansible.moudle_utils.netapp as netapp_utils
import time

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()

class NetAppCDOTTriggerLSMUpdate(object):

  def __init__(self):

    self.argument_spec = netapp_utils.ontap_sf_host_argument_spec()
    self.argument_spec.update(dict(
        vserver=dict(required=True, type='str' ),
        volume=dict(required=True, type='str' ),
    ))

    self.module = AnsibleModule(
        argument_spec=self.argument_spec,
        supports_check_mode=False
    )

    p = self.module.params
    self.params = p

    # set up state variables
    self.vserver = p['vserver']
    self.volume = p['volume']

    self.state_vars_opt = []

    if HAS_NETAPP_LIB is False:
        self.module.fail_json(msg="the python NetApp-Lib module is required")
    else:
        self.server = netapp_utils.setup_ontap_zapi(module=self.module, vserver=self.vserver)

  def cleanse_name(self, name):
      cleansed_name = name.split('}')[1].replace('-','_')
      return cleansed_name

  def snapmirror_update_ls_set(self):
      facts = {}
      try:
          api_call = {}
          api_call.update( {'source-vserver': self.vserver } )
          api_call.update( {'source-volume': self.volume } )
          snapmirror_update_ls_set = netapp_utils.zapi.NaElement.create_node_with_children(
              'snapmirror-update-ls-set', **api_call )
          lsm_call = self.server.invoke_successfully( snapmirror_update_ls_set,
                                          enable_tunneling=True )

          success = True
      except netapp_utils.zapi.NaApiError:
          err=get_exception()
          if "Another snapmirror operation is currently in progress" in str(err):
              time.sleep(30)
              pass
          else:
              self.module.fail_json(msg='Error updating snapmirror on vserver %s' %self.vserver, exception=str( err ))

      self.jobid = lsm_call.get_child_by_name( 'result-jobid' ).get_content()

      retry_limit = 60
      retry = 0
      success = False
      while retry <= retry_limit and not success:
          retry+=1

          try:
              job_info = netapp_utils.zapi.NaElement('job-get-iter')
              query_details = netapp.utils.zapi.NaElement.create_node_with_children('job-info', **{'job-id': self.jobid})
              query = netapp_utils.zapi.NaElement('query')
              query.add_child_elem(query_details)
              job_info.add_child_elem(query)
              result = self.server.invoke_successfully( job_info, enable_tunneling=True )
              changed = True

          except netapp_utils.zapi.NaApiError:
              err=get_exception()
              self.module.fail_json(msg='Error gathering job info on jobs %s' %self.jobid, exception=str( err ))

          attr_list = result.get_child_by_name( 'attribute-list' )
          for job in attr_list.get_children():
              job_state = job.get_child_by_name('job-state').get_content()

          if job_state == "running"
              time.sleep(10)
          else:
              success = True

      facts.update( { 'jobid': self.jobid } )
      return facts
  
  def apply(self):
      changed = True
      output = self.snapmirror_update_ls_set()
      self.module.exit_json(changed=changed, result=output)

def main():
    v = NetAppCDOTTrigger_LSMUpdate()
    v.apply()

if __name__ == '__main__':
    main()
