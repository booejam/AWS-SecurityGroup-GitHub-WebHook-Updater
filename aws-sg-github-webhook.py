import os
import boto3
import urllib.request
import json

def fetch_github_hook_ips():
    """Fetch GitHub webhook IP ranges"""
    url = "https://api.github.com/meta"
    with urllib.request.urlopen(url) as response:
        data = json.loads(response.read())
        return set(data.get("hooks", []))  # ensure it's a set for comparison

def get_security_group(sg_id):
    ec2 = boto3.resource('ec2')
    return ec2.SecurityGroup(sg_id)

def build_permission(ip, port, description):
    """Build a permission object for IPv4 or IPv6"""
    if ":" in ip:
        return {
            'IpProtocol': 'tcp',
            'FromPort': port,
            'ToPort': port,
            'Ipv6Ranges': [{'CidrIpv6': ip, 'Description': description}]
        }
    else:
        return {
            'IpProtocol': 'tcp',
            'FromPort': port,
            'ToPort': port,
            'IpRanges': [{'CidrIp': ip, 'Description': description}]
        }

def lambda_handler(event, context):
    # Config
    SG_ID = os.environ["SECURITY_GROUP_ID"]
    PORT = int(os.environ.get("INGRESS_PORT", "443"))
    DESCRIPTION = "GitHub Webhook"

    # Fetch
    github_ips = fetch_github_hook_ips()
    sg = get_security_group(SG_ID)

    existing_permissions = sg.ip_permissions
    current_ips = set()

    # Loop: Track existing SG IPs (both valid + invalid or old rules)
    for perm in existing_permissions:
        if perm.get("IpProtocol") != "tcp" or perm.get("FromPort") != PORT:
            continue

        # IPv4
        for ip_range in perm.get("IpRanges", []):
            ip = ip_range.get("CidrIp")
            desc = ip_range.get("Description")

            if desc == DESCRIPTION:
                if ip in github_ips:
                    current_ips.add(ip)  # valid
                else:
                    # Description is "GitHub Webhook" but not in GitHub list — revoke it
                    print(f"Removing stale GitHub IPv4 {ip}")
                    sg.revoke_ingress(IpPermissions=[{
                        'IpProtocol': 'tcp',
                        'FromPort': PORT,
                        'ToPort': PORT,
                        'IpRanges': [ip_range]
                    }])
            elif ip:
                print(f"Removing unrelated IPv4 {ip}")
                sg.revoke_ingress(IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': PORT,
                    'ToPort': PORT,
                    'IpRanges': [ip_range]
                }])

        # IPv6
        for ip_range in perm.get("Ipv6Ranges", []):
            ip = ip_range.get("CidrIpv6")
            desc = ip_range.get("Description")

            if desc == DESCRIPTION:
                if ip in github_ips:
                    current_ips.add(ip)
                else:
                    print(f"Removing stale GitHub IPv6 {ip}")
                    sg.revoke_ingress(IpPermissions=[{
                        'IpProtocol': 'tcp',
                        'FromPort': PORT,
                        'ToPort': PORT,
                        'Ipv6Ranges': [ip_range]
                    }])
            elif ip:
                print(f"Removing unrelated IPv6 {ip}")
                sg.revoke_ingress(IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': PORT,
                    'ToPort': PORT,
                    'Ipv6Ranges': [ip_range]
                }])

    # Add missing GitHub IPs
    to_add = github_ips - current_ips
    for ip in to_add:
        try:
            perm = build_permission(ip, PORT, DESCRIPTION)
            sg.authorize_ingress(IpPermissions=[perm])
            print(f"Added: {ip}")
        except Exception as e:
            if "already exists" in str(e):
                print(f"Rule already exists: {ip}")
            else:
                print(f"Error adding {ip}: {str(e)}")

    print("Sync complete. Security Group now matches GitHub hook IPs exactly.")
