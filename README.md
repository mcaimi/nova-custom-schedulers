## CUSTOM OPENSTACK NOVA SCHEDULERS

These schedulers were developed in our in-house Openstack Environment to meet our custom use cases.

### NOVA Private Iaas 

This filter allows enabled tenants to only deploy on specific compute nodes.
These compute nodes are then dedicated to that tenant, so they are removed from the shared compute pool.

#### Prerequisites:

  - Highly Available Openstack Installation (We use the one from RedHat) version Mitaka or higher. Tested until Queens.
  - Root access on every controller node
  - Keystone Admin Access
  - An admin-enabled user on keystone (nova or admin).

#### Install the scheduler filter:

Just copy the scheduler python file in the site-packages library path:

```
root@controller-0 neutron-n-0:~# cp private_iaas_filter.py /usr/lib/python2.7/site-packages/nova/scheduler/filters/

```

Do that on every controller node.

#### Modify /etc/nova/nova.conf:

* Enable all scheduler filters for inclusion in the nova scheduler:
	
```
available_filters=nova.scheduler.filters.all_filters

enabled_filters=PrivateIaasFilter,RetryFilter,AvailabilityZoneFilter,RamFilter,ComputeFilter,ComputeCapabilitiesFilter,ImagePropertiesFilter,ServerGroupAntiAffinityFilter,ServerGroupAffinityFilter

```
* Configure the scheduler options by adding a config stanza in nova.conf:

```
[....]

[private_iaas_scheduler]
# keystone version
keystone_version=3
# if keystone is v3, set domains accordingly
user_domain_name="Default"
project_domain_name="Default"
# Nova user (must be admin in the project)
keystone_username="admin"
keystone_password="P4ssw0rd"
# Endpoint keystone INTERNAL
keystone_url="http://10.3.41.74:5000"
# project in which the user has the admin role
keystone_tenant_name="admin"
# debug logging
debug=True
# Set the default behaviour in case keystone is unreachable
# TRUE == deploy anyways and let the admin move instances afterwards
# FALSE == abort the deployment with a "No host available" error message
keystone_unreachable_defaults_to_true=True

[...]

```

* Restart the nova scheduler service on all controller nodes:

```
 root@controller-0 neutron-n-0:~# pcs resource |grep nova-scheduler
 Clone Set: openstack-nova-scheduler-clone [openstack-nova-scheduler]

 root@controller-0 neutron-n-0:~# pcs resource restart openstack-nova-scheduler-clone 
```

Check the logs for errors.


#### Configure a new private project

* Create an host group dedicated to that project:

```
[root@controller-0 ~(openstack_admin)]# nova aggregate-create private_iaas_test_hg
+----+----------------------+-------------------+-------+----------+
| Id | Name                 | Availability Zone | Hosts | Metadata |
+----+----------------------+-------------------+-------+----------+
| 1  | private_iaas_test_hg | -                 |       |          |
+----+----------------------+-------------------+-------+----------+
```

* Identify the project ID you want to associate with this host group:

```
[root@controller-0 ~(openstack_admin)]# keystone tenant-list
+----------------------------------+----------------------+---------+
|                id                |         name         | enabled |
+----------------------------------+----------------------+---------+
| 254ece3166264a8f899ae050db0a4baa |      VPDC_Demo       |   True  |
| b318bdbc48444f9281778316ebc83c84 |      VPDC_Test       |   True  |
| 605a0109a00b4be09074d43b9b7fe3dd |   VPDC_test_router   |   True  |
| ac8e28f8095242beb07e310eb65e2a61 |        admin         |   True  |
| 010926a1dc6b4c15bf4ec22b52e60939 |      dev_tenant      |   True  |
| f9dca225654e42a587a84c12dca45032 | reseller01_project01 |   True  |
| ee16c655c9074ff19e20dc5f9b715f58 | reseller01_project02 |   True  |
| 49d65df7639a4cf5b2f3c91cf5bc29e9 |       services       |   True  |
| 31451f4dd8644aa8aabc803da923073d |     test_tenant      |   True  |
+----------------------------------+----------------------+---------+
```

for example, let's use "dev_tenant".

* For this project, set an extra_spec named "private_iaas_project_id" and assign the project ID as its value:

```
[root@controller-0 ~(openstack_admin)]# nova aggregate-set-metadata 1 private_iaas_project_id=010926a1dc6b4c15bf4ec22b52e60939
Metadata has been successfully updated for aggregate 1.
+----+----------------------+-------------------+-------+------------------------------------------------------------+
| Id | Name                 | Availability Zone | Hosts | Metadata                                                   |
+----+----------------------+-------------------+-------+------------------------------------------------------------+
| 1  | private_iaas_test_hg | -                 |       | 'private_iaas_project_id=010926a1dc6b4c15bf4ec22b52e60939' |
+----+----------------------+-------------------+-------+------------------------------------------------------------+
```

* Get the hostnames of all compute nodes that must be part of this host group:

```
[root@controller-0 ~(openstack_admin)]# nova host-list|grep compute
| compute01.dev.openstack.lan    | compute     | nova     |
| compute02.dev.openstack.lan    | compute     | nova     |

```

For example, let's add "compute01" to the private group.

* Add the host to the host group:

```
[root@compute-0 ~(openstack_admin)]# nova aggregate-add-host 1 compute01.dev.openstack.lan
Host compute01.dev.openstack.lan has been successfully added for aggregate 1 
+----+----------------------+-------------------+---------------------------------------+------------------------------------------------------------+
| Id | Name                 | Availability Zone | Hosts                                 | Metadata                                                   |
+----+----------------------+-------------------+---------------------------------------+------------------------------------------------------------+
| 1  | private_iaas_test_hg | -                 | 'compute01.dev.openstack.lan'         | 'private_iaas_project_id=010926a1dc6b4c15bf4ec22b52e60939' |
+----+----------------------+-------------------+---------------------------------------+------------------------------------------------------------+
```

* Lastly, mark the project as private in keystone:

You can add the the following extra_spec with the keystone CLI or with the provided command:

```
[root@controller-0 ~(openstack_admin_dev)]$ python private_tenant_ctl.py -h
usage: private_tenant_ctl.py [options] TENANT_ID

Tool to enable/disable the private_iaas metadata key in keystone

positional arguments:
  tenantid

optional arguments:
  -h, --help     show this help message and exit
  -e, --enable   Set the private_iaas key to True for specified tenant
  -d, --disable  Set the private_iaas key to False for specified tenant
  -l, --list     List tenant IDs.

```

Use the "-e" option to set the project as private or the "-d" to mark the project as shared.

Get the ID of the project "dev_tenant":

```
[root@controller-0 ~(openstack_admin_dev)]$ python private_tenant_ctl.py -l all|grep dev_tenant
Tenant IDs:
ID: 010926a1dc6b4c15bf4ec22b52e60939   NAME: dev_tenant
```

Set the extra_spec flag "private_iaas" to True:

```
[root@controller-0 ~(openstack_admin_dev)]$ python private_tenant_ctl.py -e 010926a1dc6b4c15bf4ec22b52e60939
Starting operation on tenant id -> dev_tenant [010926a1dc6b4c15bf4ec22b52e60939]
Enabling private_iaas metadata property...
{"tenant": {"description": "development_tenant", "extra": {"testproperty": "test123", "private_iaas": true}, "testproperty": "test123", "enabled": true, "id": "010926a1dc6b4c15bf4ec22b52e60939", "private_iaas": true, "name": "dev_tenant"}}
```

