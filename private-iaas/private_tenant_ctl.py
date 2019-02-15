#!/usr/bin/env python
#
# CLI tool to enable/disable private tenants
#
# Marco Caimi <marco.caimi@fastweb.it>

import keystoneclient

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

import sys, os
from argparse import ArgumentParser
import requests
import json

MANDATORY_ENV_VARS = ['OS_IDENTITY_API_VERSION']

ENV_VARS_V2 = ['OS_USERNAME', 'OS_PASSWORD', 'OS_TENANT_NAME', 'OS_AUTH_URL']
ENV_VARS_V3 = ['OS_USERNAME', 'OS_PASSWORD', 'OS_PROJECT_NAME', 'OS_USER_DOMAIN_NAME', 'OS_PROJECT_DOMAIN_NAME', 'OS_AUTH_URL']

def assert_parameters(environment_variables):
    for entry in environment_variables:
        if not entry in os.environ.keys():
            print("Missing environment variable %s. Please load your OpenStack RC File" % entry)
            sys.exit(-1)

assert_parameters(MANDATORY_ENV_VARS)
api_version = int(os.environ['OS_IDENTITY_API_VERSION'])

if api_version == 3:
    assert_parameters(ENV_VARS_V3)
    username = os.environ['OS_USERNAME']
    password = os.environ['OS_PASSWORD']
    project_name = os.environ['OS_PROJECT_NAME']
    user_domain = os.environ['OS_USER_DOMAIN_NAME']
    project_domain = os.environ['OS_PROJECT_DOMAIN_NAME']
    auth_url = os.environ['OS_AUTH_URL']
    api_endpoint = "projects"
else:
    assert_parameters(ENV_VARS_V2)
    username = os.environ['OS_USERNAME']
    password = os.environ['OS_PASSWORD']
    project_name = os.environ['OS_TENANT_NAME']
    auth_url = os.environ['OS_AUTH_URL']
    api_endpoint = "tenants"

# get params

aparser = ArgumentParser(prog="private_tenant_ctl.py", usage="%(prog)s [options] TENANT_ID", description="Tool to enable/disable the private_iaas metadata key in keystone")
aparser.add_argument("-e", "--enable", action='store_true', help="Set the private_iaas key to True for specified tenant")
aparser.add_argument("-d", "--disable", action='store_true', help="Set the private_iaas key to False for specified tenant")
aparser.add_argument("-l", "--list", action='store_true', help="List tenant IDs.")
aparser.add_argument("tenantid", type=str)
opts = aparser.parse_args(args=sys.argv[1:])

try:
    # sanity check
    if (not (bool(opts.enable) ^ bool(opts.disable))) ^ opts.list:
        print("Syntax Error: You cannot specify both '--enable' and '--disable' switches at the same time.")
        sys.exit(-1)
except:
    aparser.print_help()
    sys.exit(-1)

try:
    if api_version == 2:
        print("PRIVATEIAAS: Initializing v2.0 API session")
        # create an admin session object
        admin_auth = auth_v2.Password(username=username,
                                      password=password,
                                      tenant_name=project_name,
                                      auth_url=auth_url)
        admin_session = keystone_session.Session(auth=admin_auth)

    else:
        print("PRIVATEIAAS: Initializing v3 API session")
        admin_auth = auth_v3.Password(username=username,
                                      password=password,
                                      project_name=project_name,
                                      user_domain_name=user_domain,
                                      project_domain_name=project_domain,
                                      auth_url=auth_url)
        admin_session = keystone_session.Session(auth=admin_auth)

    try:
        print("PRIVATEIAAS: Spawning ADMIN CLIENT")
        # admin session
        if api_version == 2:
            keystoneclient = keystone_client.Client(session=admin_session)
        else:
            keystoneclient = keystone_client_v3.Client(session=admin_session)

    except AuthorizationFailure as user_failed_auth_step:
        print(user_failed_auth_step.message)
        sys.exit(-1)
    except Unauthorized as user_unauthorized:
        print(user_unauthorized.message)
        sys.exit(-1)

except Exception as e: # Catch superclass, so we can intercept every kind of error.
    print("Exception caught while calling client.Client(): \n[%s]" % e)
    sys.exit(-1)

# tenant manager reference
if hasattr(keystoneclient, "projects"):
    tenant_manager = getattr(keystoneclient, "projects")
else:
    tenant_manager = getattr(keystoneclient, "tenants")

if (opts.list):
    print("Tenant IDs:")
    for tid in tenant_manager.list():
        print("ID: %s\t NAME: %s" % (tid.id, tid.name))
    sys.exit(0)

try:
    tid = tenant_manager.get(opts.tenantid)
    print("Starting operation on tenant id -> %s [%s]" % (getattr(tid, "name", "undef"), opts.tenantid))
except http.Forbidden as e:
    print("Keystone exception caught: \n[%s]" % e)
    sys.exit(-1)

# API request wrapper object
class APIRequest():
    def __init__(self, keystone_client_object=None, keystone_session_object=None, tenant=None):
        if keystone_client_object==None or keystone_session_object==None:
            raise Exception("Missing Parameter: keystone_client_object cannot be 'None'")

        if tenant == None:
            raise Exception("Missing Parameter: tenant object cannot be 'None'")

        self.keystone_client = keystone_client_object
        self.auth_token = keystone_session_object.get_token()
        self.tid = tenant

        self.request_body_template_v2 = { "tenant": 
                                        { "private_iaas": False,
                                          "enabled": True, 
                                          "description": "placeholder", 
                                          "id": "placeholder", 
                                          "name": "placeholder"
                                        }
                                     }
        
        self.request_body_template_v3 = { "project": 
                                        { "private_iaas": False,
                                          "enabled": True, 
                                          "description": "placeholder", 
                                          "project_id": "placeholder", 
                                          "name": "placeholder"
                                        }
                                     }


        if not self.assert_valid():
            raise Exception("Auth token invalid!!")

    # assert authentication token validity
    def assert_valid(self):
        return self.keystone_client.tokens.validate(self.auth_token)

    # build request header hash
    def build_request_header(self):
        return { 'Content-Type': 'application/json',
                 'User-Agent': 'python-keystoneclient',
                 'X-Auth-Token': self.auth_token,
                 'Accept': 'application/json' }
    
    # build request body hash
    def build_request_body(self, private_tenant=False):
        if api_version == 2:
            self.request_body_template_v2['tenant']['private_iaas'] = private_tenant
            self.request_body_template_v2['tenant']['description'] = self.tid.description
            self.request_body_template_v2['tenant']['id'] = self.tid.id
            self.request_body_template_v2['tenant']['name'] = self.tid.name
            self.request_body_template = self.request_body_template_v2
        else:
            self.request_body_template_v3['project']['private_iaas'] = private_tenant
            self.request_body_template_v3['project']['description'] = self.tid.description
            self.request_body_template_v3['project']['project_id'] = self.tid.id
            self.request_body_template_v3['project']['name'] = self.tid.name
            self.request_body_template = self.request_body_template_v3

        return self.request_body_template

# enable or disable private_iaas property.
# if key is False and switch --enable is true, switch key logical state
private_iaas_key_state = getattr(tid, "private_iaas", False)

# instantiate API Wrapper...
try:
    apiwrapper = APIRequest(keystone_client_object=keystoneclient, keystone_session_object=admin_session, tenant=tid)
except Exception as e:
    print(e)
    sys.exit(-1)

try: 
    if not(private_iaas_key_state) and opts.enable:
        # flip private_iaas key state to true
        print("Enabling private_iaas metadata property...")
        response_from_api = requests.patch("%s/%s/%s" % (os.environ["OS_AUTH_URL"], api_endpoint, tid.id), 
                                           headers=apiwrapper.build_request_header(), 
                                           data=json.dumps(apiwrapper.build_request_body(private_tenant=True)))

        response_from_api.raise_for_status()
        print(response_from_api.text)
        pass
    #otherwise, if private_iaas key is true and switch --disable is true, switch key state to false
    elif private_iaas_key_state and opts.disable:
        # flip private_iaas key state to false
        print("Disabling private_iaas metadata property...")
        response_from_api = requests.patch("%s/%s/%s" % (os.environ["OS_AUTH_URL"], api_endpoint, tid.id), 
                                           headers=apiwrapper.build_request_header(), 
                                           data=json.dumps(apiwrapper.build_request_body(private_tenant=False)))
        response_from_api.raise_for_status()
        print(response_from_api.text)
        pass
    else:
        print("Tenant left unchanged.\nTID: %s" % tid)
        sys.exit(0)
except Exception as e:
    print(e)
    sys.exit(-1)

#
