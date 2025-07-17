import os
import boto3
import urllib.request
import json

def get_github_ip_list():
    url = 'https://api.github.com/meta'
    with urllib.request.urlopen(url) as response:
        if response.status != 200:
            raise ConnectionError("Failed to fetch GitHub IPs")
        data = json.loads(response.read().decode())
        return data.get("hooks", [])

def get_aws_security_group(group_id):
    """Retrieve the EC2 Security Group"""
    ec2 = boto3.resource('ec2')
    return ec2.SecurityGroup(group_id)

def check_rule_exists(rules, address, port):
    """Check if IP + port already allowed"""
    if "." in address:
        rule_key = 'IpRanges'
        range_key = 'CidrIp'
    else:
        rule_key = 'Ipv6Ranges'
        range_key = 'CidrIpv6'
        
    for rule in rules:
        if rule.get('FromPort') != port:
            continue
        for ip_range in rule.get(rule_key, []):
            if ip_range.get(range_key) == address:
                return True
    return False

def add_ingress_rule(group, address, port, description):
    """Add a new ingress rule to the SG"""
    if "." in address:
        permissions = [{
            'IpProtocol': 'tcp',
            'FromPort': port,
            'ToPort': port,
            'IpRanges': [{'CidrIp': address, 'Description': description}]
        }]
    else:
        permissions = [{
            'IpProtocol': 'tcp',
            'FromPort': port,
            'ToPort': port,
            'Ipv6Ranges': [{'CidrIpv6': address, 'Description': description}]
        }]
    
    try:
        group.authorize_ingress(IpPermissions=permissions)
        print(f"Added ingress rule: {address}:{port}")
    except Exception as e:
        print(f"Failed to add rule for {address}:{port} - {str(e)}")

def clear_security_group_ingress_rules(group):
    """Optional: Clear all existing ingress rules"""
    try:
        if group.ip_permissions:
            group.revoke_ingress(IpPermissions=group.ip_permissions)
            print("Cleared existing ingress rules")
    except Exception as e:
        print(f"Failed to clear ingress rules: {str(e)}")

def lambda_handler(event, context):
    # Load ports
    ingress_ports = [int(port.strip()) for port in os.environ.get("INGRESS_PORTS_LIST", "443").split(",")]

    # Load Security Group
    security_group_id = os.environ["SECURITY_GROUP_ID"]
    security_group = get_aws_security_group("sg-02458291c7a58ee8d")

    # Get GitHub IPs
    github_ips = get_github_ip_list()

    # Optional: clear existing rules first
    # Uncomment if you want to clean first
    # clear_security_group_ingress_rules(security_group)

    description = "GitHub Webhook"

    # Add missing rules
    for ip in github_ips:
        for port in ingress_ports:
            if not check_rule_exists(security_group.ip_permissions, ip, port):
                add_ingress_rule(security_group, ip, port, description)
            else:
                print(f"Rule exists: {ip}:{port}")
