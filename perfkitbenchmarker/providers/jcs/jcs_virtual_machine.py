# Copyright 2014 PerfKitBenchmarker Authors. All rights reserved.
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

"""Class to represent an JCS Virtual Machine object.

All VM specifics are self-contained and the class provides methods to
operate on the VM: boot, shutdown, etc.
"""

import base64
import json
import logging
import threading

from perfkitbenchmarker import disk
from perfkitbenchmarker import errors
from perfkitbenchmarker import flags
from perfkitbenchmarker import linux_virtual_machine
from perfkitbenchmarker import virtual_machine
from perfkitbenchmarker import vm_util
from perfkitbenchmarker import windows_virtual_machine
from perfkitbenchmarker.providers.jcs import jcs_disk
from perfkitbenchmarker.providers.jcs import jcs_network
from perfkitbenchmarker.providers.jcs import util
from perfkitbenchmarker import data

FLAGS = flags.FLAGS

HVM = 'HVM'
PV = 'PV'
NON_HVM_PREFIXES = ['m1', 'c1', 't1', 'm2']
US_EAST_1 = 'us-east-1'
US_WEST_1 = 'us-west-1'
US_WEST_2 = 'us-west-2'
EU_WEST_1 = 'eu-west-1'
AP_NORTHEAST_1 = 'ap-northeast-1'
AP_SOUTHEAST_1 = 'ap-southeast-1'
AP_SOUTHEAST_2 = 'ap-southeast-2'
SA_EAST_1 = 'sa-east-1'
PLACEMENT_GROUP_PREFIXES = frozenset(
    ['c3', 'c4', 'cc2', 'cg1', 'g2', 'cr1', 'r3', 'hi1', 'i2'])
NUM_LOCAL_VOLUMES = {
    'c1.small': 0, 'c1.medium': 0, 'c1.large': 0,
    'c1.xlarge': 0,
}
DRIVE_START_LETTER = 'b'
INSTANCE_EXISTS_STATUSES = frozenset(
    ['pending', 'running', 'stopping', 'stopped'])
INSTANCE_DELETED_STATUSES = frozenset(['shutting-down', 'terminated'])
INSTANCE_KNOWN_STATUSES = INSTANCE_EXISTS_STATUSES | INSTANCE_DELETED_STATUSES


def GetBlockDeviceMap(machine_type):
  """Returns the block device map to expose all devices for a given machine.

  Args:
    machine_type: The machine type to create a block device map for.

  Returns:
    The json representation of the block device map for a machine compatible
    with the JCS CLI, or if the machine type has no local disks, it will
    return None.
  """
  if machine_type in NUM_LOCAL_VOLUMES:
    mappings = [{'VirtualName': 'ephemeral%s' % i,
                 'DeviceName': '/dev/vd%s' % chr(ord(DRIVE_START_LETTER) + i)}
                for i in xrange(NUM_LOCAL_VOLUMES[machine_type])]
    return json.dumps(mappings)
  else:
    return None


def IsPlacementGroupCompatible(machine_type):
  """Returns True if VMs of 'machine_type' can be put in a placement group."""
  prefix = machine_type.split('.')[0]
  return prefix in PLACEMENT_GROUP_PREFIXES


class JcsVirtualMachine(virtual_machine.BaseVirtualMachine):
  """Object representing an JCS Virtual Machine."""

  CLOUD = 'JCS'
  IMAGE_NAME_FILTER = None
  DEFAULT_ROOT_DISK_TYPE = 'standard'

  _lock = threading.Lock()
  imported_keyfile_set = set()
  deleted_keyfile_set = set()

  def __init__(self, vm_spec):
    """Initialize a JCS virtual machine.

    Args:
      vm_spec: virtual_machine.BaseVirtualMachineSpec object of the vm.
    """
    super(JcsVirtualMachine, self).__init__(vm_spec)
    self.region = util.GetRegionFromZone(self.zone)
    self.user_name = FLAGS.jcs_user_name
    if self.machine_type in NUM_LOCAL_VOLUMES:
      self.max_local_disks = NUM_LOCAL_VOLUMES[self.machine_type]
    self.user_data = None
    self.network = jcs_network.JcsNetwork.GetNetwork(self)
    self.firewall = jcs_network.JcsFirewall.GetFirewall()
    self.fip = None

  @classmethod
  def _GetDefaultImage(cls, machine_type, region):
    """Returns the default image given the machine type and region.

    If no default is configured, this will return None.
    """
    if cls.IMAGE_NAME_FILTER is None:
      return None

    prefix = machine_type.split('.')[0]
    virt_type = 'paravirtual' if prefix in NON_HVM_PREFIXES else 'hvm'

    describe_cmd = util.JCS_EC2_PREFIX + [
        'ec2',
        'describe-images',
        '--query', 'Images[*].{Name:Name,ImageId:ImageId}',
        '--filters',
        'Name=name,Values=%s' % cls.IMAGE_NAME_FILTER,
        'Name=block-device-mapping.volume-type,Values=%s' %
        cls.DEFAULT_ROOT_DISK_TYPE,
        'Name=virtualization-type,Values=%s' % virt_type]
    stdout, _ = util.IssueRetryableCommand(describe_cmd)

    if not stdout:
      return None

    images = json.loads(stdout)
    # We want to return the latest version of the image, and since the wildcard
    # portion of the image name is the image's creation date, we can just take
    # the image with the 'largest' name.
    return max(images, key=lambda image: image['Name'])['ImageId']

  def ImportKeyfile(self):
    """Imports the public keyfile to JCS."""
    with self._lock:
      if self.region in self.imported_keyfile_set:
        return
      cat_cmd = ['cat',
                 vm_util.GetPublicKeyPath()]
      keyfile, _ = vm_util.IssueRetryableCommand(cat_cmd)
      import_cmd = util.JCS_EC2_PREFIX + [
          'ec2',
          'import-key-pair',
          '--key-name=%s' % 'perfkit-key-%s' % FLAGS.run_uri,
          '--public-key-material="%s"' % keyfile.strip()]
      full_cmd = ' '.join(import_cmd)
      util.IssueRetryableCommand(full_cmd, is_shell=True)
      self.imported_keyfile_set.add(self.region)
      if self.region in self.deleted_keyfile_set:
        self.deleted_keyfile_set.remove(self.region)

  def DeleteKeyfile(self):
    """Deletes the imported keyfile for a region."""
    with self._lock:
      if self.region in self.deleted_keyfile_set:
        return
      delete_cmd = util.JCS_EC2_PREFIX + [
          'ec2',
          'delete-key-pair',
          '--key-name=%s' % 'perfkit-key-%s' % FLAGS.run_uri]
      util.IssueRetryableCommand(delete_cmd)
      self.deleted_keyfile_set.add(self.region)
      if self.region in self.imported_keyfile_set:
        self.imported_keyfile_set.remove(self.region)

  @vm_util.Retry()
  def _PostCreate(self):
    """Get the instance's data and tag it."""
    self.fip = jcs_network.JcsFloatingIp()
    self.fip.Create()
    self.fip.AssociateAddress(self.id)
    
    describe_cmd = util.JCS_EC2_PREFIX + [
        'ec2',
        'describe-instances',
        '--instance-ids=%s' % self.id]
    logging.info('Getting instance %s public IP. This will fail until '
                 'a public IP is available, but will be retried.', self.id)
    stdout, _ = util.IssueRetryableCommand(describe_cmd)
    response = json.loads(stdout)
    instance = response['Reservations'][0]
    self.ip_address = instance['PublicIpAddress']
    self.internal_ip = instance['PrivateIpAddress']
    self.group_id = instance['SecurityGroups'][0]['GroupId']
    #if util.IsRegion(self.zone):
    #  self.zone = str(instance['Placement']['AvailabilityZone'])
    #util.AddDefaultTags(self.id, self.region)

  def _CreateDependencies(self):
    """Create VM dependencies."""
    self.ImportKeyfile()
    # _GetDefaultImage calls the JCS CLI.
    self.image = self.image or self._GetDefaultImage(self.machine_type,
                                                     self.region)

  def DeleteFip(self):
    self.fip.DisassociateAddress()
    self.fip.Delete()

  def _DeleteDependencies(self):
    """Delete VM dependencies."""
    self.DeleteKeyfile()
    self.DeleteFip()

  def _Create(self):
    """Create a VM instance."""
    """
    placement = []
    if not util.IsRegion(self.zone):
      placement.append('AvailabilityZone=%s' % self.zone)
    if IsPlacementGroupCompatible(self.machine_type):
      placement.append('GroupName=%s' % self.network.placement_group.name)
    placement = ','.join(placement)
    """
    #block_device_map = GetBlockDeviceMap(self.machine_type)

    #block_device_map = [{'DeviceName':'/dev/vda', 'DeleteOnTermination':True}] 
    BDM_FILE = "bdm.json"
    block_device_map = data.ResourcePath(BDM_FILE)
    create_cmd = util.JCS_EC2_PREFIX + [
        'ec2',
        'run-instances',
        '--subnet-id=%s' % self.network.subnet.id,
        #'--associate-public-ip-address',
        '--image-id=%s' % self.image,
        '--instance-type-id=%s' % self.machine_type,
        '--instance-count=%s' % "1",
        '--key-name=%s' % 'perfkit-key-%s' % FLAGS.run_uri]
    if block_device_map:
      create_cmd.append('--block-device-mappings=file://%s' % block_device_map)
    """
    if placement:
      create_cmd.append('--placement=%s' % placement)
    if self.user_data:
      create_cmd.append('--user-data=%s' % self.user_data)
    """
    stdout, _, _ = vm_util.IssueCommand(create_cmd)
    response = json.loads(stdout)
    self.id = response['Reservations'][0]['InstanceId']

  def _Delete(self):
    """Delete a VM instance."""
    delete_cmd = util.JCS_EC2_PREFIX + [
        'ec2',
        'terminate-instances',
        '--instance-ids=%s' % self.id]
    vm_util.IssueCommand(delete_cmd)

  def _Exists(self):
    """Returns true if the VM exists."""
    describe_cmd = util.JCS_EC2_PREFIX + [
        'ec2',
        'describe-instances',
        '--filter=Name=instance-id,Values=%s' % self.id]
    stdout, _ = util.IssueRetryableCommand(describe_cmd)
    response = json.loads(stdout)
    """
    reservations = response['Reservations']
    assert len(reservations) < 2, 'Too many reservations.'
    if not reservations:
      return False
    """
    instances =  response['Reservations']
    assert len(instances) == 1, 'Wrong number of instances.'
    status = instances[0]['State']
    assert status in INSTANCE_KNOWN_STATUSES, status
    return status in INSTANCE_EXISTS_STATUSES

  def CreateScratchDisk(self, disk_spec):
    """Create a VM's scratch disk.

    Args:
      disk_spec: virtual_machine.BaseDiskSpec object of the disk.
    """
    # Instantiate the disk(s) that we want to create.
    disks = []
    for _ in range(disk_spec.num_striped_disks):
      data_disk = jcs_disk.JcsDisk(disk_spec, self.zone, self.machine_type)
      if disk_spec.disk_type == disk.LOCAL:
        data_disk.device_letter = chr(ord(DRIVE_START_LETTER) +
                                      self.local_disk_counter)
        # Local disk numbers start at 1 (0 is the system disk).
        data_disk.disk_number = self.local_disk_counter + 1
        self.local_disk_counter += 1
        if self.local_disk_counter > self.max_local_disks:
          raise errors.Error('Not enough local disks.')
      else:
        # Remote disk numbers start at 1 + max_local disks (0 is the system disk
        # and local disks occupy [1, max_local_disks]).
        data_disk.disk_number = (self.remote_disk_counter +
                                 1 + self.max_local_disks)
        self.remote_disk_counter += 1
      disks.append(data_disk)

    self._CreateScratchDiskFromDisks(disk_spec, disks)

  def GetLocalDisks(self):
    """Returns a list of local disks on the VM.

    Returns:
      A list of strings, where each string is the absolute path to the local
          disks on the VM (e.g. '/dev/sdb').
    """
    return ['/dev/xvd%s' % chr(ord(DRIVE_START_LETTER) + i)
            for i in xrange(NUM_LOCAL_VOLUMES[self.machine_type])]

  def AddMetadata(self, **kwargs):
    """Adds metadata to the VM."""
    #util.AddTags(self.id, self.region, **kwargs) #TBD Vishnu
    pass


class DebianBasedJcsVirtualMachine(JcsVirtualMachine,
                                   linux_virtual_machine.DebianMixin):
  IMAGE_NAME_FILTER = 'ubuntu/images/*/ubuntu-trusty-14.04-amd64-*'


class RhelBasedJcsVirtualMachine(JcsVirtualMachine,
                                 linux_virtual_machine.RhelMixin):
  pass


class WindowsJcsVirtualMachine(JcsVirtualMachine,
                               windows_virtual_machine.WindowsMixin):

  IMAGE_NAME_FILTER = 'Windows_Server-2012-R2_RTM-English-64Bit-Core-*'
  DEFAULT_ROOT_DISK_TYPE = 'gp2'

  def __init__(self, vm_spec):
    super(WindowsJcsVirtualMachine, self).__init__(vm_spec)
    self.user_name = 'Administrator'
    self.user_data = ('<powershell>%s</powershell>' %
                      windows_virtual_machine.STARTUP_SCRIPT)

  @vm_util.Retry()
  def _GetDecodedPasswordData(self):
    # Retreive a base64 encoded, encrypted password for the VM.
    get_password_cmd = util.JCS_EC2_PREFIX + [
        'ec2',
        'get-password-data',
        '--instance-id=%s' % self.id]
    stdout, _ = util.IssueRetryableCommand(get_password_cmd)
    response = json.loads(stdout)
    password_data = response['PasswordData']

    # JCS may not populate the password data until some time after
    # the VM shows as running. Simply retry until the data shows up.
    if not password_data:
      raise ValueError('No PasswordData in response.')

    # Decode the password data.
    return base64.b64decode(password_data)


  def _PostCreate(self):
    """Retrieve generic VM info and then retrieve the VM's password."""
    super(WindowsJcsVirtualMachine, self)._PostCreate()

    # Get the decoded password data.
    decoded_password_data = self._GetDecodedPasswordData()

    # Write the encrypted data to a file, and use openssl to
    # decrypt the password.
    with vm_util.NamedTemporaryFile() as tf:
      tf.write(decoded_password_data)
      tf.close()
      decrypt_cmd = ['openssl',
                     'rsautl',
                     '-decrypt',
                     '-in',
                     tf.name,
                     '-inkey',
                     vm_util.GetPrivateKeyPath()]
      password, _ = vm_util.IssueRetryableCommand(decrypt_cmd)
      self.password = password
