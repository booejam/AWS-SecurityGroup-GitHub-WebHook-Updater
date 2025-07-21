"""
===================================================================================
Script: GitHub Webhook IP Sync to AWS Security Group
Last Updated: July 2025

Purpose:
--------
This AWS Lambda function synchronizes a specified EC2 Security Group with GitHub’s
official webhook IP address ranges (both IPv4 and IPv6), ensuring only valid GitHub
webhook sources are permitted on a defined port.

Functionality:
--------------
1. Retrieves the current list of GitHub webhook IPs from GitHub’s metadata API.
2. Compares them with existing ingress rules in the Security Group.
3. Removes stale or unrelated IPs that are not part of the current GitHub list.
4. Adds any missing GitHub IPs to the Security Group with a defined description.

Environment Variables:
----------------------
- SECURITY_GROUP_ID : The target AWS EC2 Security Group ID.
- INGRESS_PORT      : (Optional) TCP port number for ingress (defaults to 443).

Key Components:
---------------
- `fetch_github_hook_ips()`:
    Fetches and returns the list of GitHub webhook IPs from GitHub’s metadata API.

- `get_security_group(sg_id)`:
    Initializes and returns a SecurityGroup object using boto3.

- `build_permission(ip, port, description)`:
    Constructs a properly formatted ingress permission entry for IPv4 or IPv6.

- `lambda_handler(event, context)`:
    The main function executed by AWS Lambda. It:
        - Loads environment variables.
        - Fetches GitHub IPs and current Security Group rules.
        - Revokes any stale or unrelated rules.
        - Adds any new GitHub IPs not already present.

Logging:
--------
The script outputs information about added or removed IPs and potential errors using
`print()` statements, which are viewable in AWS CloudWatch Logs.

Security Group Permissions Required:
------------------------------------
Lambda must be granted the following EC2 permissions:
- `ec2:DescribeSecurityGroups`
- `ec2:AuthorizeSecurityGroupIngress`
- `ec2:RevokeSecurityGroupIngress`

Use Case:
---------
Typically scheduled using Amazon EventBridge to run daily or weekly, keeping the
Security Group always in sync with the current GitHub IP list for webhook delivery.

Reference:
----------
GitHub Metadata API: https://api.github.com/meta
"""
