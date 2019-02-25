# Copyright (c) 2016 Fastweb S.p.A.
#
# Nova filter that implements a way to isolate tenants to specific host aggregates
#

from oslo_log import log as logging
from oslo_config import cfg

from nova.scheduler import filters
from nova.scheduler.filters import utils

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
private_iaas_scheduler_options = [
    cfg.IntOpt('keystone_version', default=3, help="Identity Service API verstion", required=True),
    cfg.StrOpt('keystone_username', default='nova', help="Username to use when authentication to keystone", required=True),
    cfg.StrOpt('keystone_password', default='P4ssw0rd', help="Password to use when authentication to keystone", required=True),
    cfg.StrOpt('keystone_url', default='http://192.168.0.100:5000', help="Keystone authentication URL endpoint", required=True),
    cfg.StrOpt('keystone_tenant_name', default='services', help="Tenant ID of the user that attempts authentication", required=True),
    cfg.StrOpt('user_domain_name', default='Default', help="User domain to use for authentication", required=False),
    cfg.StrOpt('project_domain_name', default='Default', help="Project domain to use for authentication", required=False),
    cfg.BoolOpt('keystone_unreachable_defaults_to_true', default=True, help="Specifies what to do if keystone is unreachable. True means that the filter will bypass private_iaas enforcement.", required=True),
    cfg.BoolOpt('debug', default=False, help="Turn debug logging on"),
    cfg.BoolOpt('run_filter_once_per_request', default=True, help="Whether to run this filter once per every request"),
]
private_iaas_scheduler_group = cfg.OptGroup('private_iaas_scheduler', "Private IAAS Scheduler options.")
cfg.CONF.register_group(private_iaas_scheduler_group)
cfg.CONF.register_opts(private_iaas_scheduler_options, group=private_iaas_scheduler_group)

# load nova configuration
CONF = cfg.CONF.private_iaas_scheduler
LOG = logging.getLogger(__name__)

# nova scheduler filter implementation
class PrivateIaasFilter(filters.BaseHostFilter):
    # Execute filter for every request, since we want to isolate instances
    run_filter_once_per_request = CONF.run_filter_once_per_request

    """Isolate tenants in specific aggregates based on keystone extra_specs."""
    # override constructor, add custom elements to filter class
    def __init__(self):
        """ Add keystone glue to resolve extra_specs for private iaas tenants """
        # auth url
        if CONF.keystone_version == 2:
            LOG.info("PRIVATEIAAS: Initializing v2.0 API session")
            self.auth_url = CONF.keystone_url + "/v2.0"
            # create an admin session object
            self.admin_auth = auth_v2.Password(username=CONF.keystone_username,
                                               password=CONF.keystone_password,
                                               tenant_name=CONF.keystone_tenant_name,
                                               auth_url=self.auth_url)
            self.admin_session = keystone_session.Session(auth=self.admin_auth)

        else:
            LOG.info("PRIVATEIAAS: Initializing v3 API session")
            self.auth_url = CONF.keystone_url + "/v3"
            self.admin_auth = auth_v3.Password(username=CONF.keystone_username,
                                               password=CONF.keystone_password,
                                               project_name=CONF.keystone_tenant_name,
                                               user_domain_name=CONF.user_domain_name,
                                               project_domain_name=CONF.project_domain_name,
                                               auth_url=self.auth_url)
            self.admin_session = keystone_session.Session(auth=self.admin_auth)

        try:
            LOG.info("PRIVATEIAAS: Spawning ADMIN CLIENT")
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
            LOG.info("[PRIVATEIAAS]: Filter Object Created")

        # tenant manager reference
        if hasattr(self.keystoneclient, "projects"):
            self.tenant_manager = getattr(self.keystoneclient, "projects")
        else:
            self.tenant_manager = getattr(self.keystoneclient, "tenants")

        # build callback table
        self.private_iaas_callbacks = { True: self.react_true, False: self.react_false }

    # take action in case tenant happens to be private
    def react_true(self, project_id, host_group, host_state):
        if host_group != {}:
            allowed_tenant_ids = host_group.get("private_iaas_project_id")
            if allowed_tenant_ids:
                if project_id not in allowed_tenant_ids:
                    if CONF.debug:
                        LOG.info("[PRIVATEIAAS]: %s fails private_iaas filter on aggregate. Rejecting Host.", host_state)
                    return False
                else:
                    if CONF.debug:
                        LOG.info("[PRIVATEIAAS]: Host %s matches %s tenant id" % (host_state, project_id))
                    return True
            else: # metadata key malformed.
                return False
        else:
            if CONF.debug:
                LOG.info("[PRIVATEIAAS]: No host available in private host group. Host filtered.")
            return False

    # act accordingly in case the tenant is not private
    def react_false(self, project_id, host_group, host_state):
        if host_group != {}:
            # filter out private hypervisors
            if CONF.debug:
                LOG.info("[PRIVATEIAAS]: Tenant is public, host is in private HG. Host filtered.")
            return False
        else:
            if CONF.debug:
                LOG.info("[PRIVATEIAAS]: Tenant is public, Host Passes.")
            return True

    # filter host function, called by the filter scheduler
    def host_passes(self, host_state, spec_obj):
        """ Search for host aggregates that have the 'private_iaas_project_id'
        metadata key. Hosts in these aggregates can accept instance only from the matching
        project id if the project id belongs to a tenant which has the private_iaas extra_spec 
        set to True, else they are filtered out.

        Hosts can belong to more than one aggregate, more than one project ids can be specified in
        the 'private_iaas_project_id' key.

        Hosts that are outside every aggregate, or in aggregates that do not match the metadata key
        are filtered out. (eg. can only accept instances from shared tenants)
        """

        # (mcaimi) Update call to request_object properties to accomodate changes in Newton
        # get project id from the request object
        #if isinstance(spec_obj, dict):
        #    request_object = spec_obj.get('request_spec', None)
        #    instance_properties = request_object.get('instance_properties', None)
        #    current_project_id = instance_properties.get('project_id', None)
        #else:
        #    current_project_id = spec_obj.get('project_id', None)
        # also, handle both v3 and v3 API versions
        current_project_id = getattr(spec_obj, 'project_id', None) or getattr(spec_obj, 'tenant_id', None)

        if current_project_id is None:
            LOG.error("[PRIVATEIAAS]: request is broken. Missing project UUID")
            return False

        # ask keystone for tenant metadata
        try:
            resolved_project_spec = self.tenant_manager.get(current_project_id)
        except Exception as e:
            if CONF.debug:
                LOG.info("[PRIVATEIAAS]: Keystone connection broken, scheduler filter will default to %s" % CONF.keystone_unreachable_defaults_to_true)
            if CONF.keystone_unreachable_defaults_to_true:
                return True
            else:
                return False

        tenant_is_private = getattr(resolved_project_spec, "private_iaas", False)
        tenant_is_private = bool(tenant_is_private)

        if CONF.debug:
            LOG.info("[PRIVATEIAAS]: ProjectID %s, is_private: %s" % (current_project_id, tenant_is_private))

        # retrieve host aggregate, filter by 'private_iaas_project_id' metadata key
        private_iaas_hg = utils.aggregate_metadata_get_by_host(host_state, key="private_iaas_project_id")

        # now computing scheduling decision...
        # we have some matching host groups, then select the matching callback
        return self.private_iaas_callbacks[tenant_is_private](current_project_id, private_iaas_hg, host_state)

#
