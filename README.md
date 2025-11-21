# Cloud VPC Simulator (vpcctl.py)

This project simulates core Virtual Private Cloud (VPC) functionalities, including isolated subnets, Network Address Translation (NAT) Gateway, VPC Peering, and Security Groups, using Linux networking primitives (network namespaces, bridges, and iptables).

Prerequisites

This simulator requires a Linux environment with root access (sudo) and Python 3.

Operating System: Linux (Ubuntu 20.04+ or similar distributions are recommended).

Permissions: sudo access is required for all networking commands (ip, iptables, sysctl).

Software: Python 3 (for the controller script and simple HTTP servers).

📁 Project Structure
cloud-vpc-simulator/
 ├── vpcctl.py
 ├── cleanup.sh
 ├── README.md
 ├── index.html
 ├── internet_index.html
 ├── vpcctl.log
 └── .git

Setup and Environment Preparation

Follow these steps to set up the clean, working environment needed to run the main demonstration script.

1. Initial Cleanup

Before running any creation commands, ensure no lingering network artifacts from previous sessions interfere.

# Stop any running Python HTTP servers
killall python3 2>/dev/null

# Execute the project cleanup script
sudo ./cleanup.sh

# Manually ensure lingering peering VETHs are removed
sudo ip link del pr1-test-prod 2>/dev/null
sudo ip link del pr2-dev-vpc 2>/dev/null


2. Create VPCs and Inject DNS

Create the two independent VPCs and set up the necessary DNS resolution for external access.

# Create the first VPC (test-prod)
sudo ./vpcctl.py create --name test-prod --cidr 10.10.0.0/16 --iface ens5

# Create the second VPC (dev-vpc)
sudo ./vpcctl.py create --name dev-vpc --cidr 10.20.0.0/16 --iface ens5

# Inject static DNS (Google's 8.8.8.8) into the public namespaces for hostname resolution
sudo mkdir -p /etc/netns/test-prod-public; sudo sh -c 'echo "nameserver 8.8.8.8" > /etc/netns/test-prod-public/resolv.conf'


3. Deploy Test Servers

Deploy two simple Python HTTP servers in different VPCs and subnets to act as test targets.

# Server 1: Intra-VPC target (Runs in test-prod private subnet, hosts simple directory listing)
sudo ip netns exec test-prod-private python3 -m http.server 80 &

# Create custom content for the peering target
sudo mkdir -p /tmp/dev-vpc-public-app
echo '<h1>VPC PEERING SUCCESS!</h1>' | sudo tee /tmp/dev-vpc-public-app/index.html > /dev/null

# Server 2: Peering target (Runs in dev-vpc public subnet, hosts custom success message)
sudo ip netns exec dev-vpc-public python3 -m http.server 80 --directory /tmp/dev-vpc-public-app &


Complete Demonstration Run Sequence

The following commands represent the full, verified demonstration script, organized by the policy being tested. Execute these commands sequentially.

A. Isolation and NAT Access Validation

Step

Command

Expected Result

1. Intra-VPC Comm.

sudo ip netns exec test-prod-public curl 10.10.1.2:80 -m 3

Directory Listing (200 OK)

2. Public NAT Access

sudo ip netns exec test-prod-public curl google.com -m 5

HTML/Redirect (Success)

3. Private Isolation

sudo ip netns exec test-prod-private curl google.com -m 5

Timeout (Failure)

B. VPC Peering and Security Group Enforcement

Step

Command

Expected Result

4. Setup Peering

sudo ./vpcctl.py peer --vpc1-name test-prod --vpc1-cidr 10.10.0.0/16 --vpc2-name dev-vpc --vpc2-cidr 10.20.0.0/16

VPC Peering established successfully!

5. Peering Test

sudo ip netns exec test-prod-public curl 10.20.0.2:80 -m 3

<h1>VPC PEERING SUCCESS!</h1>

6. Apply Security Group

sudo ./vpcctl.py apply-sg --vpc-name dev-vpc --subnet public --rules icmp:any tcp:22

Security Group applied successfully.

7. SG Test (Allowed)

sudo ip netns exec test-prod-public ping -c 1 10.20.0.2

0% packet loss (Success)

8. SG Test (Blocked)

sudo ip netns exec test-prod-public curl 10.20.0.2:80 -m 3

Timeout (Failure)

C. Teardown

Clean up all network resources created by the tool.

# Delete the test-prod VPC
sudo ./vpcctl.py delete --name test-prod --cidr 10.10.0.0/16

# Delete the dev-vpc VPC
sudo ./vpcctl.py delete --name dev-vpc --cidr 10.20.0.0/16

# Stop all running HTTP servers
killall python3 2>/dev/null
