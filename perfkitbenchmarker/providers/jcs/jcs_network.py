# Copyright 2015 PerfKitBenchmarker Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Module containing classes related to JCS VM networking.

"""

import json
import logging
import threading
import uuid

from perfkitbenchmarker import flags
from perfkitbenchmarker import network
from perfkitbenchmarker import resource
from perfkitbenchmarker import vm_util
from perfkitbenchmarker.providers.jcs import util

FLAGS = flags.FLAGS
JCS = 'JCS'


class JcsFirewall(network.BaseFirewall):
  """An object representing the JCS Firewall."""

  CLOUD = JCS

  def __init__(self):
    self.firewall_set = set()
    self._lock = threading.Lock()

  def AllowPort(self, vm, port):
    """Opens a port on the firewall.

    Args:
      vm: The BaseVirtualMachine object to open the port for.
      port: The local port to open.
    """
    if vm.is_static:
      return
    entry = (port, vm.group_id)
    if entry in self.firewall_set:
      return
    with self._lock:
      if entry in self.firewall_set:
        return
      authorize_cmd = util.JCS_VPC_PREFIX + [
          'ec2',
          'authorize-security-group-ingress',
          '--group-id=%s' % vm.group_id,
          '--port=%s' % port,
          '--cidr=0.0.0.0/0']
      util.IssueRetryableCommand(
          authorize_cmd + ['--protocol=tcp'])
      util.IssueRetryableCommand(
          authorize_cmd + ['--protocol=udp'])
      self.firewall_set.add(entry)

  def DisallowAllPorts(self):
    """Closes all ports on the firewall."""
    pass

class JcsFloatingIp(resource.BaseResource):
  def __init__(self):
	super(JcsFloatingIp, self).__init__()
	self.id = None
	self.association_id = None
	self.publicIp = None
  def _Create(self):
	create_cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'allocate-address',
        '--domain=vpc']
   	stdout, stderr, retcode = vm_util.IssueCommand(create_cmd)
    	response = json.loads(stdout)
    	self.id = response['AllocationId']
	self.publicIp = response['PublicIp']
  def AssociateAddress(self, instance_id):
	cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'associate-address',
	'--instance-id=%s'%instance_id,
	'--allocation-id=%s'%self.id]
	stdout, stderr, retcode = vm_util.IssueCommand(cmd)
        response = json.loads(stdout)
	self.association_id = response['AssociationId']

  def DisassociateAddress(self):
	if(self.association_id != None):
           cmd = util.JCS_VPC_PREFIX + [
           'ec2',
           'disassociate-address',
           '--association-id=%s'%self.association_id]
   	   stdout, stderr, retcode = vm_util.IssueCommand(cmd)

  def _Delete(self):
	self._ReleaseAddress()

  def _ReleaseAddress(self):
        cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'release-address',
        '--allocation-id=%s'%self.id]
        stdout, stderr, retcode = vm_util.IssueCommand(cmd)
	#response = json.loads(stdout)

  def _Exists(self):
        cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'describe-addresses',
        '--filter=Name=allocation-id,Values=%s'%self.id]
        stdout, stderr, retcode = vm_util.IssueCommand(cmd)
        response = json.loads(stdout)
	addresses = response['Addresses']
	assert len(addresses) < 2, 'Too many addressess.'
    	return len(addresses) == 1



class JcsVpc(resource.BaseResource):
  """An object representing an Jcs VPC."""

  def __init__(self, region):
    super(JcsVpc, self).__init__()
    self.region = region
    self.id = None

    # Subnets are assigned per-AZ.
    # _subnet_index tracks the next unused 10.0.x.0/24 block.
    self._subnet_index = 0
    # Lock protecting _subnet_index
    self._subnet_index_lock = threading.Lock()

  def _Create(self):
    """Creates the VPC."""
    create_cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'create-vpc',
        '--cidr-block=10.0.0.0/16']
    stdout, stderr, retcode = vm_util.IssueCommand(create_cmd)
    response = json.loads(stdout)
    self.id = response['Vpc']['VpcId']
    #self._EnableDnsHostnames()
    #util.AddDefaultTags(self.id, self.region)

  def _Exists(self):
    """Returns true if the VPC exists."""
    describe_cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'describe-vpcs',
        '--filter=Name=vpc-id,Values=%s' % self.id]
    stdout, stderr = util.IssueRetryableCommand(describe_cmd)
    response = json.loads(stdout)
    vpcs = response['Vpcs']
    assert len(vpcs) < 2, 'Too many VPCs.'
    return len(vpcs) > 0

  def _EnableDnsHostnames(self):
    """Sets the enableDnsHostnames attribute of this VPC to True.

    By default, instances launched in non-default VPCs are assigned an
    unresolvable hostname. This breaks the hadoop benchmark.  Setting the
    enableDnsHostnames attribute to 'true' on the VPC resolves this. See:
    http://docs.jcs.amazon.com/AmazonVPC/latest/UserGuide/VPC_DHCP_Options.html
    """
    enable_hostnames_command = util.JCS_VPC_PREFIX + [
        'ec2',
        'modify-vpc-attribute',
        '--region=%s' % self.region,
        '--vpc-id', self.id,
        '--enable-dns-hostnames',
        '{ "Value": true }']

    util.IssueRetryableCommand(enable_hostnames_command)

  def _Delete(self):
    """Deletes the VPC."""
    delete_cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'delete-vpc',
        '--vpc-id=%s' % self.id]
    vm_util.IssueCommand(delete_cmd)

  def NextSubnetCidrBlock(self):
    """Returns the next available /24 CIDR block in this VPC.

    Each VPC has a 10.0.0.0/16 CIDR block.
    Each subnet is assigned a /24 within this allocation.
    Calls to this method return the next unused /24.

    Returns:
      A string representing the next available /24 block, in CIDR notation.
    Raises:
      ValueError: when no additional subnets can be created.
    """
    with self._subnet_index_lock:
      if self._subnet_index >= (1 << 8) - 1:
        raise ValueError('Exceeded subnet limit ({0}).'.format(
            self._subnet_index))
      cidr = '10.0.{0}.0/24'.format(self._subnet_index)
      self._subnet_index += 1
    return cidr


class JcsSubnet(resource.BaseResource):
  """An object representing an Jcs subnet."""

  def __init__(self, zone, vpc_id, cidr_block='10.0.0.0/24'):
    super(JcsSubnet, self).__init__()
    self.zone = zone
    self.region = util.GetRegionFromZone(zone)
    self.vpc_id = vpc_id
    self.id = None
    self.cidr_block = cidr_block

  def _Create(self):
    """Creates the subnet."""

    create_cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'create-subnet',
        '--vpc-id=%s' % self.vpc_id,
        '--cidr-block=%s' % self.cidr_block]
    #if not util.IsRegion(self.zone):
    #  create_cmd.append('--availability-zone=%s' % self.zone)

    stdout, _, _ = vm_util.IssueCommand(create_cmd)
    response = json.loads(stdout)
    self.id = response['Subnet']['SubnetId']
    #util.AddDefaultTags(self.id, self.region)

  def _Delete(self):
    """Deletes the subnet."""
    logging.info('Deleting subnet %s. This may fail if all instances in the '
                 'subnet have not completed termination, but will be retried.',
                 self.id)
    delete_cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'delete-subnet',
        '--subnet-id=%s' % self.id]
    vm_util.IssueCommand(delete_cmd)

  def _Exists(self):
    """Returns true if the subnet exists."""
    describe_cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'describe-subnets',
        '--filter=Name=subnet-id,Values=%s' % self.id]
    stdout, _ = util.IssueRetryableCommand(describe_cmd)
    response = json.loads(stdout)
    subnets = response['Subnets']
    assert len(subnets) < 2, 'Too many subnets.'
    return len(subnets) > 0

class JcsInternetGateway(resource.BaseResource):
  """An object representing an Jcs Internet Gateway."""

  def __init__(self, region):
    super(JcsInternetGateway, self).__init__()
    self.region = region
    self.vpc_id = None
    self.id = None
    self.attached = False

  def _Create(self):
    """Creates the internet gateway."""
    create_cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'create-internet-gateway']
    stdout, _, _ = vm_util.IssueCommand(create_cmd)
    response = json.loads(stdout)
    self.id = response['InternetGateway']['InternetGatewayId']
    util.AddDefaultTags(self.id, self.region)

  def _Delete(self):
    """Deletes the internet gateway."""
    delete_cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'delete-internet-gateway',
        '--internet-gateway-id=%s' % self.id]
    vm_util.IssueCommand(delete_cmd)

  def _Exists(self):
    """Returns true if the internet gateway exists."""
    describe_cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'describe-internet-gateways',
        '--filter=Name=internet-gateway-id,Values=%s' % self.id]
    stdout, _ = util.IssueRetryableCommand(describe_cmd)
    response = json.loads(stdout)
    internet_gateways = response['InternetGateways']
    assert len(internet_gateways) < 2, 'Too many internet gateways.'
    return len(internet_gateways) > 0

  def Attach(self, vpc_id):
    """Attaches the internetgateway to the VPC."""
    if not self.attached:
      self.vpc_id = vpc_id
      attach_cmd = util.JCS_VPC_PREFIX + [
          'ec2',
          'attach-internet-gateway',
          '--internet-gateway-id=%s' % self.id,
          '--vpc-id=%s' % self.vpc_id]
      util.IssueRetryableCommand(attach_cmd)
      self.attached = True

  def Detach(self):
    """Detaches the internetgateway from the VPC."""
    if self.attached:
      detach_cmd = util.JCS_VPC_PREFIX + [
          'ec2',
          'detach-internet-gateway',
          '--internet-gateway-id=%s' % self.id,
          '--vpc-id=%s' % self.vpc_id]
      util.IssueRetryableCommand(detach_cmd)
      self.attached = False

class JcsRouteTable(resource.BaseResource):
  """An object representing a route table."""

  def __init__(self, region, vpc_id):
    super(JcsRouteTable, self).__init__()
    self.region = region
    self.vpc_id = vpc_id

  def _Create(self):
    """Creates the route table.

    This is a no-op since every VPC has a default route table.
    """
    pass

  def _Delete(self):
    """Deletes the route table.

    This is a no-op since the default route table gets deleted with the VPC.
    """
    pass

  @vm_util.Retry()
  def _PostCreate(self):
    """Gets data about the route table."""
    describe_cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'describe-route-tables',
        '--filters=Name=vpc-id,Values=%s' % self.vpc_id]
    stdout, _ = util.IssueRetryableCommand(describe_cmd)
    response = json.loads(stdout)
    self.id = response['RouteTables'][0]['RouteTableId']

  def CreateRoute(self, internet_gateway_id):
    """Adds a route to the internet gateway."""
    create_cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'create-route',
        '--route-table-id=%s' % self.id,
        '--gateway-id=%s' % internet_gateway_id,
        '--destination-cidr-block=0.0.0.0/0']
    util.IssueRetryableCommand(create_cmd)


class JcsPlacementGroup(resource.BaseResource):
  """Object representing an JCS Placement Group.

  Attributes:
    region: The JCS region the Placement Group is in.
    name: The name of the Placement Group.
  """

  def __init__(self, region):
    """Init method for JcsPlacementGroup.

    Args:
      region: A string containing the JCS region of the Placement Group.
    """
    super(JcsPlacementGroup, self).__init__()
    self.name = (
        'perfkit-%s-%s' % (FLAGS.run_uri, str(uuid.uuid4())[-12:]))
    self.region = region

  def _Create(self):
    """Creates the Placement Group."""
    create_cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'create-placement-group',
        '--group-name=%s' % self.name,
        '--strategy=cluster']
    vm_util.IssueCommand(create_cmd)

  def _Delete(self):
    """Deletes the Placement Group."""
    delete_cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'delete-placement-group',
        '--group-name=%s' % self.name]
    vm_util.IssueCommand(delete_cmd)

  def _Exists(self):
    """Returns true if the Placement Group exists."""
    describe_cmd = util.JCS_VPC_PREFIX + [
        'ec2',
        'describe-placement-groups',
        '--filter=Name=group-name,Values=%s' % self.name]
    stdout, _ = util.IssueRetryableCommand(describe_cmd)
    response = json.loads(stdout)
    placement_groups = response['PlacementGroups']
    assert len(placement_groups) < 2, 'Too many placement groups.'
    return len(placement_groups) > 0


class JcsRegionalNetwork(network.BaseNetwork):
  """Object representing regional components of an JCS network.

  This class maintains a singleton-per-region; acquire instances via
  JcsRegionalNetwork.GetForRegion.

  Attributes:
    region: string. The JCS region.
    vpc: an JcsVpc instance.
    internet_gateway: an JcsInternetGateway instance.
    route_table: an JcsRouteTable instance. The default route table.
    placement_group: An JcsPlacementGroup instance.
  """
  # Map from region to JcsRegionalNetwork
  _network_pool = {}
  # Lock protecting _network_pool
  _network_pool_lock = threading.Lock()

  def __init__(self, region):
    self.region = region
    self.vpc = JcsVpc(self.region)
    self.internet_gateway = JcsInternetGateway(region)
    self.route_table = None
    self.placement_group = JcsPlacementGroup(self.region)
    self.created = False

    # Locks to ensure that a single thread creates / deletes the instance.
    self._create_lock = threading.Lock()

    # Tracks the number of JcsNetworks using this JcsRegionalNetwork.
    # Incremented by Create(); decremented by Delete();
    # When a Delete() call decrements _reference_count to 0, the RegionalNetwork
    # is destroyed.
    self._reference_count = 0
    self._reference_count_lock = threading.Lock()

  @classmethod
  def GetForRegion(cls, region):
    """Gets the JcsRegionalNetwork for a given JCS region.

    Args:
      region: str. A Region name.
    Returns:
      The JcsRegionalNetwork for 'region'.
    """
    with cls._network_pool_lock:
      return cls._network_pool.setdefault(region, cls(region))

  def Create(self):
    """Creates the network."""
    with self._reference_count_lock:
      assert self._reference_count >= 0, self._reference_count
      self._reference_count += 1

    # Access here must be synchronized. The first time the block is executed,
    # the network will be created. Subsequent attempts to create the
    # network block until the initial attempt completes, then return.
    with self._create_lock:
      if self.created:
        return

      self.vpc.Create()

      """
      self.internet_gateway.Create()
      self.internet_gateway.Attach(self.vpc.id)

      if self.route_table is None:
        self.route_table = JcsRouteTable(self.region, self.vpc.id)
      self.route_table.Create()
      self.route_table.CreateRoute(self.internet_gateway.id)

      self.placement_group.Create()
      """
      self.created = True

  def Delete(self):
    """Deletes the network."""
    # Only actually delete if there are no more references.
    with self._reference_count_lock:
      assert self._reference_count >= 1, self._reference_count
      self._reference_count -= 1
      if self._reference_count:
        return

    #self.placement_group.Delete()
    #self.internet_gateway.Detach()
    #self.internet_gateway.Delete()
    self.vpc.Delete()


class JcsNetwork(network.BaseNetwork):
  """Object representing an JCS Network.

  Attributes:
    region: The JCS region the Network is in.
    regional_network: The JcsRegionalNetwor for 'region'.
    subnet: the JcsSubnet for this zone.
  """

  CLOUD = JCS

  def __init__(self, spec):
    """Initializes JcsNetwork instances.

    Args:
      spec: A BaseNetworkSpec object.
    """
    super(JcsNetwork, self).__init__(spec)
    self.region = util.GetRegionFromZone(spec.zone)
    self.regional_network = JcsRegionalNetwork.GetForRegion(self.region)
    self.subnet = None

  def Create(self):
    """Creates the network."""
    self.regional_network.Create()

    if self.subnet is None:
      cidr = self.regional_network.vpc.NextSubnetCidrBlock()
      self.subnet = JcsSubnet(self.zone, self.regional_network.vpc.id,
                              cidr_block=cidr)
      self.subnet.Create()

  def Delete(self):
    """Deletes the network."""
    if self.subnet:
      self.subnet.Delete()
    self.regional_network.Delete()
