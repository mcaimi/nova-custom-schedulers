# Copyright (c) 2016 Fastweb S.p.A.
#
# Nova filter that implements a way to isolate tenants to specific hypervisor technology
# for Fastweb's MultiHypervisor IaaS Cloud Use Case
#

from oslo_log import log as logging
from oslo_config import cfg

from nova.scheduler import filters
from nova.scheduler.filters import utils
from nova.objects import fields 

# client v2
from keystoneclient.v2_0 import client as keystone_client
from keystoneauth1.identity import v2 as auth_v2

# client v3
from keystoneclient import client as keystone_client_v3
from keystoneauth1.identity import v3 as auth_v3

# keystone exceptions
from keystoneclient.exceptions import AuthorizationFailure, Unauthorized

# keystone session support
from keystoneauth1 import session as keystone_session

# define custom entries in nova.conf, and add them to the option parser
hypervisor_type_scheduler_options = [
    cfg.StrOpt('keystone_username', default='admin', help="Username to use when authentication to keystone", required=True),
    cfg.StrOpt('keystone_password', default='P4ssw0rd', help="Password to use when authentication to keystone", required=True),
    cfg.StrOpt('keystone_url', default='http://192.168.1.10:5000', help="Keystone authentication URL endpoint", required=True),
    cfg.StrOpt('keystone_tenant_name', default='admin', help="Tenant ID of the user that attempts authentication", required=True),
    cfg.BoolOpt('keystone_unreachable_defaults_to_true', default=True, help="Specifies what to do if keystone is unreachable. True means that the filter will bypass private_iaas enforcement.", required=True),
    cfg.BoolOpt('debug', default=False, help="Turn debug logging on"),
    cfg.StrOpt('user_domain_name', default='Default', help="User domain to use for authentication", required=False),
    cfg.StrOpt('project_domain_name', default='Default', help="Project domain to use for authentication", required=False),
    cfg.BoolOpt('run_filter_once_per_request', default=True, help="Whether to run this filter once per every request"),
    cfg.IntOpt('keystone_version', default=3, help="Identity API version to be used by the filter", required=True),
]
hypervisor_type_scheduler_group = cfg.OptGroup('hypervisor_type_scheduler', "MultiHypervisor Scheduler options.")
cfg.CONF.register_group(hypervisor_type_scheduler_group)
cfg.CONF.register_opts(hypervisor_type_scheduler_options, group=hypervisor_type_scheduler_group)

# load nova configuration
CONF = cfg.CONF.hypervisor_type_scheduler
LOG = logging.getLogger(__name__)

ANY_LABEL = [ 'ANY', 'any', 'Any' ]

# nova scheduler filter implementation
class HypervisorTypeFilter(filters.BaseHostFilter):
    """Isolate tenants in specific aggregates based on keystone extra_specs and virtualization technology.."""

    # override constructor, add custom elements to filter class
    def __init__(self):
       # auth url
        if CONF.keystone_version == 2:
            LOG.info("HYPERVISOR_FILTER: Initializing v2.0 API session")
            self.auth_url = CONF.keystone_url + "/v2.0"
            # create an admin session object
            self.admin_auth = auth_v2.Password(username=CONF.keystone_username,
                                               password=CONF.keystone_password,
                                               tenant_name=CONF.keystone_tenant_name,
                                               auth_url=self.auth_url)
            self.admin_session = keystone_session.Session(auth=self.admin_auth)

        else:
            LOG.info("HYPERVISOR_FILTER: Initializing v3 API session")
            self.auth_url = CONF.keystone_url + "/v3"
            self.admin_auth = auth_v3.Password(username=CONF.keystone_username,
                                               password=CONF.keystone_password,
                                               project_name=CONF.keystone_tenant_name,
                                               user_domain_name=CONF.user_domain_name,
                                               project_domain_name=CONF.project_domain_name,
                                               auth_url=self.auth_url)
            self.admin_session = keystone_session.Session(auth=self.admin_auth)
        
        try:
            LOG.info("HYPERVISOR_FILTER: Spawning ADMIN CLIENT")
            # admin session
            if CONF.keystone_version == 2:
                self.keystoneclient = keystone_client.Client(session=self.admin_session)
            else:
                self.keystoneclient = keystone_client_v3.Client(session=self.admin_session)

        except AuthorizationFailure as user_failed_auth_step:
            LOG.info(user_failed_auth_step.message)
            raise user_failed_auth_step
        except Unauthorized as user_unauthorized:
            LOG.info(user_unauthorized.message)
            raise user_unauthorized

        # OK, object created
        # TODO: Preload keystone tenant list?
        if CONF.debug:
            LOG.info("[HYPERVISOR_FILTER]: Filter Object Created")
        
        # tenant manager reference
        if hasattr(self.keystoneclient, "projects"):
            self.tenant_manager = getattr(self.keystoneclient, "projects")
        else:
            self.tenant_manager = getattr(self.keystoneclient, "tenants")

    # Execute filter for every request, since we want to isolate instances
    run_filter_once_per_request = CONF.run_filter_once_per_request

    # filter host function, called by the filter scheduler
    def host_passes(self, host_state, spec_obj):
        """
            Search for the 'tenant_type' property in keystone. The tenant_type is an extra spec that determines 
            on which virtualization technology a tenant can deploy on.

            'tenant_type' can be 'QEMU', 'VMWARE' or 'any'

            Based on that extra_spec value, this filter builds a list of suitable compute nodes
        """
        # handle identity version differences
        current_project_id = getattr(spec_obj, 'project_id', None) or getattr(spec_obj, 'tenant_id', None)

        # ask keystone for tenant metadata
        try:
            resolved_project_spec = self.tenant_manager.get(current_project_id)
        except:
            if CONF.debug:
                LOG.info("[HYPERVISOR_FILTER]: Keystone connection broken, scheduler filter will default to %s" % CONF.keystone_unreachable_defaults_to_true)
            if CONF.keystone_unreachable_defaults_to_true:
                return True
            else:
                return False

        tenant_type = getattr(resolved_project_spec, 'tenant_type', 'any')
        if CONF.debug:
            LOG.info("[HYPERVISOR_FILTER]: ProjectID %s, Tenant Type: %s" % (current_project_id, tenant_type))

        # if tenant_type is 'any', any compute node can handle instances from this tenant.
        if tenant_type in ANY_LABEL:
            return True

        # canonicalize hypervisor type
        self.hv_type = fields.HVType()
        requested_hv_type = self.hv_type.canonicalize(tenant_type)
        # hv type is unknown. filter out everything
        if not self.hv_type.is_valid(requested_hv_type):
            return False

        # retrieve host hypervisor type
        compute_type = self.hv_type.canonicalize(host_state.hypervisor_type)

        # check hypervisor type
        if requested_hv_type == compute_type:
            if CONF.debug:
                LOG.info("HYPERVISOR_FILTER: HV TYPE: %s == TENANT TYPE: %s, Host Passes." % (requested_hv_type, compute_type))
            return True
        else:
            if CONF.debug:
                LOG.info("HYPERVISOR_FILTER: HV TYPE: %s != TENANT TYPE: %s, Host Filtered." % (requested_hv_type, compute_type))
            return False
#
