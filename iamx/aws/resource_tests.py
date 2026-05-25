"""
EC2 DryRun permission checks.

AWS returns DryRunOperation  → caller HAS the permission.
AWS returns UnauthorizedOperation → caller does NOT have the permission.
"""

from typing import Any


# EC2 operations that support DryRun=True.
# Values are the minimal required params beyond DryRun.
# Placeholder instance/group IDs are intentionally invalid — AWS validates
# permission before resource existence when DryRun=True.
DRYRUN_TESTS: dict[str, dict[str, Any]] = {
    "run_instances": {
        "ImageId": "ami-00000000",
        "MinCount": 1,
        "MaxCount": 1,
        "DryRun": True,
    },
    "terminate_instances": {
        "InstanceIds": ["i-00000000"],
        "DryRun": True,
    },
    "stop_instances": {
        "InstanceIds": ["i-00000000"],
        "DryRun": True,
    },
    "start_instances": {
        "InstanceIds": ["i-00000000"],
        "DryRun": True,
    },
    "modify_instance_attribute": {
        "InstanceId": "i-00000000",
        "Attribute": "instanceType",
        "DryRun": True,
    },
    "create_security_group": {
        "GroupName": "iamx-dryrun-test",
        "Description": "iamx dryrun test",
        "DryRun": True,
    },
    "delete_security_group": {
        "GroupId": "sg-00000000",
        "DryRun": True,
    },
    "authorize_security_group_ingress": {
        "GroupId": "sg-00000000",
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        "DryRun": True,
    },
    "create_key_pair": {
        "KeyName": "iamx-dryrun-test",
        "DryRun": True,
    },
    "request_spot_instances": {
        "InstanceCount": 1,
        "LaunchSpecification": {"ImageId": "ami-00000000", "InstanceType": "t2.micro"},
        "DryRun": True,
    },
    "create_image": {
        "InstanceId": "i-00000000",
        "Name": "iamx-dryrun-test",
        "DryRun": True,
    },
    "create_tags": {
        "Resources": ["i-00000000"],
        "Tags": [{"Key": "iamx", "Value": "dryrun"}],
        "DryRun": True,
    },
    "delete_tags": {
        "Resources": ["i-00000000"],
        "Tags": [{"Key": "iamx"}],
        "DryRun": True,
    },
    # Snapshots / volumes
    "create_snapshot": {
        "VolumeId": "vol-00000000",
        "DryRun": True,
    },
    "delete_snapshot": {
        "SnapshotId": "snap-00000000",
        "DryRun": True,
    },
    "create_volume": {
        "AvailabilityZone": "us-east-1a",
        "Size": 1,
        "DryRun": True,
    },
    "delete_volume": {
        "VolumeId": "vol-00000000",
        "DryRun": True,
    },
    "attach_volume": {
        "VolumeId": "vol-00000000",
        "InstanceId": "i-00000000",
        "Device": "/dev/sdf",
        "DryRun": True,
    },
    "detach_volume": {
        "VolumeId": "vol-00000000",
        "DryRun": True,
    },
    # AMIs
    "deregister_image": {
        "ImageId": "ami-00000000",
        "DryRun": True,
    },
    "copy_image": {
        "Name": "iamx-dryrun-test",
        "SourceImageId": "ami-00000000",
        "SourceRegion": "us-east-1",
        "DryRun": True,
    },
    # Network
    "create_vpc": {
        "CidrBlock": "10.0.0.0/16",
        "DryRun": True,
    },
    "delete_vpc": {
        "VpcId": "vpc-00000000",
        "DryRun": True,
    },
    "create_subnet": {
        "VpcId": "vpc-00000000",
        "CidrBlock": "10.0.1.0/24",
        "DryRun": True,
    },
    "delete_subnet": {
        "SubnetId": "subnet-00000000",
        "DryRun": True,
    },
    "create_internet_gateway": {
        "DryRun": True,
    },
    "delete_internet_gateway": {
        "InternetGatewayId": "igw-00000000",
        "DryRun": True,
    },
    "attach_internet_gateway": {
        "InternetGatewayId": "igw-00000000",
        "VpcId": "vpc-00000000",
        "DryRun": True,
    },
    "create_route_table": {
        "VpcId": "vpc-00000000",
        "DryRun": True,
    },
    "delete_route_table": {
        "RouteTableId": "rtb-00000000",
        "DryRun": True,
    },
    "create_route": {
        "RouteTableId": "rtb-00000000",
        "DestinationCidrBlock": "0.0.0.0/0",
        "GatewayId": "igw-00000000",
        "DryRun": True,
    },
    "create_network_interface": {
        "SubnetId": "subnet-00000000",
        "DryRun": True,
    },
    "delete_network_interface": {
        "NetworkInterfaceId": "eni-00000000",
        "DryRun": True,
    },
    "allocate_address": {
        "Domain": "vpc",
        "DryRun": True,
    },
    "release_address": {
        "AllocationId": "eipalloc-00000000",
        "DryRun": True,
    },
    "associate_address": {
        "AllocationId": "eipalloc-00000000",
        "InstanceId": "i-00000000",
        "DryRun": True,
    },
    # Security groups
    "revoke_security_group_ingress": {
        "GroupId": "sg-00000000",
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        "DryRun": True,
    },
    "authorize_security_group_egress": {
        "GroupId": "sg-00000000",
        "DryRun": True,
    },
    "revoke_security_group_egress": {
        "GroupId": "sg-00000000",
        "DryRun": True,
    },
    # Key pairs
    "delete_key_pair": {
        "KeyName": "iamx-dryrun-test",
        "DryRun": True,
    },
    "import_key_pair": {
        "KeyName": "iamx-dryrun-test",
        "PublicKeyMaterial": b"ssh-rsa AAAA",
        "DryRun": True,
    },
    # Launch templates
    "create_launch_template": {
        "LaunchTemplateName": "iamx-dryrun-test",
        "LaunchTemplateData": {"ImageId": "ami-00000000"},
        "DryRun": True,
    },
    "delete_launch_template": {
        "LaunchTemplateId": "lt-00000000",
        "DryRun": True,
    },
    "create_launch_template_version": {
        "LaunchTemplateId": "lt-00000000",
        "LaunchTemplateData": {"ImageId": "ami-00000000"},
        "DryRun": True,
    },
    # VPC peering / endpoints
    "create_vpc_peering_connection": {
        "VpcId": "vpc-00000000",
        "PeerVpcId": "vpc-11111111",
        "DryRun": True,
    },
    "delete_vpc_peering_connection": {
        "VpcPeeringConnectionId": "pcx-00000000",
        "DryRun": True,
    },
}
