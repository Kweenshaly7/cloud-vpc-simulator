#!/usr/bin/env python3
import os
import sys
import subprocess
import logging
import argparse
import ipaddress 

# ------------------ Logging Setup ------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "vpcctl.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.info("\n\n========== VPCCTL RUN STARTED ==========")

# ------------------ Helpers ------------------
def run(cmd):
    """Run shell command with logging."""
    print(f"➡️  {cmd}")
    logging.info(f"RUN: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, text=True, check=True, capture_output=True)
        if result.stdout.strip():
            logging.info(result.stdout.strip())
        if result.stderr.strip():
            # Log stderr but allow graceful failure for expected cleanups (|| true)
            logging.warning(result.stderr.strip()) 
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed: {cmd}")
        logging.error(f"Command failed: {cmd}")
        logging.error(e.stderr.strip() if e.stderr else str(e))
        # Note: We do NOT sys.exit(1) on failure for peer/unpeer/cleanup commands
        # because the failure might be an expected cleanup case (e.g., link doesn't exist).
        # We only exit for critical failures in VPC creation.
        if "create" in cmd or "addr add" in cmd or "route add" in cmd:
             sys.exit(1)

def detect_inet_iface():
    """Detect default internet interface."""
    try:
        out = subprocess.check_output("ip route | awk '/default/ {print $5; exit}'", shell=True).decode().strip()
        return out or "eth0"
    except Exception:
        return "eth0"

def exists_bridge(name):
    return subprocess.call(f"ip link show {name}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

# ------------------ IP Management ------------------
def get_subnet_ips(vpc_cidr_str):
    """Calculates non-overlapping CIDRs for the public and private subnets."""
    try:
        vpc_net = ipaddress.ip_network(vpc_cidr_str)
        
        # 1. Assign the central bridge IP (GW for all namespaces)
        bridge_ip_address = str(list(vpc_net.hosts())[0])
        bridge_ip = bridge_ip_address + "/" + str(vpc_net.prefixlen)
        central_gw_ip = bridge_ip_address 

        # 2. Subnet the VPC block into smaller, non-overlapping /24 networks
        subnets = list(vpc_net.subnets(new_prefix=24))

        if len(subnets) < 2: 
            logging.error(f"VPC CIDR {vpc_cidr_str} is too small to create 2 separate /24 subnets.")
            sys.exit(1)

        public_net = subnets[0]
        private_net = subnets[1]

        # Namespace IPs: Use the second usable IP for the namespace interface
        public_ns_ip = str(list(public_net.hosts())[1]) + "/24" 
        private_ns_ip = str(list(private_net.hosts())[1]) + "/24"
        
        return {
            "vpc_cidr": vpc_cidr_str,
            "bridge_cidr": vpc_cidr_str,
            "bridge_ip": bridge_ip,
            "central_gw_ip": central_gw_ip,
            "public_net_cidr": str(public_net.with_prefixlen), 
            "public_ns_ip": public_ns_ip,
            "private_net_cidr": str(private_net.with_prefixlen), 
            "private_ns_ip": private_ns_ip,
        }

    except ValueError as e:
        logging.error(f"Invalid CIDR format or network error: {e}")
        sys.exit(1)
    except IndexError:
        logging.error("Failed to allocate necessary IPs. Check the VPC CIDR size.")
        sys.exit(1)

# ------------------ VPC Core ------------------
def create_bridge(bridge, bridge_ip):
    if not exists_bridge(bridge):
        run(f"ip link add name {bridge} type bridge")
    run(f"ip addr add {bridge_ip} dev {bridge} || true") 
    run(f"ip link set {bridge} up")

def create_namespace(ns):
    run(f"ip netns add {ns}")
    run(f"ip netns exec {ns} ip link set lo up")

def connect_namespace_to_bridge(ns, veth_ns, veth_br, bridge, ns_ip, gw_ip, vpc_cidr):
    """Connects a namespace to the bridge and configures internal routing."""
    # Note: veth_ns and veth_br must be unique strings (15 chars max).
    run(f"ip link add {veth_ns} type veth peer name {veth_br}")
    run(f"ip link set {veth_ns} netns {ns}")
    run(f"ip link set {veth_br} master {bridge}")
    run(f"ip link set {veth_br} up")
    run(f"ip netns exec {ns} ip addr add {ns_ip} dev {veth_ns}")
    run(f"ip netns exec {ns} ip link set {veth_ns} up")
    
    # Add a direct route to the VPC CIDR via the local link to make the gateway resolvable.
    run(f"ip netns exec {ns} ip route add {vpc_cidr} dev {veth_ns}")
    
    # Set the default route to the central bridge IP.
    run(f"ip netns exec {ns} ip route add default via {gw_ip}") 

def setup_nat_and_isolation(public_cidr, iface):
    run("sysctl -w net.ipv4.ip_forward=1")
    
    print(f"Configuring NAT for public subnet {public_cidr} via {iface}")
    run(f"iptables -t nat -A POSTROUTING -s {public_cidr} -o {iface} -j MASQUERADE")

# ------------------ Peering Core (Part 3) ------------------

def peer_vpcs(vpc1_name, vpc1_cidr, vpc2_name, vpc2_cidr):
    print(f"\n🔗 Setting up peering between {vpc1_name} ({vpc1_cidr}) and {vpc2_name} ({vpc2_cidr})")

    bridge1 = f"br-{vpc1_name}"
    bridge2 = f"br-{vpc2_name}"

    # 1. Create a VETH pair to connect the two bridges (Ensure short, unique names)
    veth_name1 = f"pr1-{vpc1_name}"[:14] # Max 15 chars
    veth_name2 = f"pr2-{vpc2_name}"[:14]

    run(f"ip link add {veth_name1} type veth peer name {veth_name2}")

    # 2. Attach VETH interfaces to their respective bridges
    run(f"ip link set {veth_name1} master {bridge1}")
    run(f"ip link set {veth_name2} master {bridge2}")

    # 3. Bring the interfaces up
    run(f"ip link set {veth_name1} up")
    run(f"ip link set {veth_name2} up")

    # 4. Add static routes on the host (using dev instead of via, as they're directly connected)
    print(f"Adding route: {vpc2_cidr} dev {veth_name1}")
    run(f"ip route add {vpc2_cidr} dev {veth_name1} || true")

    print(f"Adding route: {vpc1_cidr} dev {veth_name2}")
    run(f"ip route add {vpc1_cidr} dev {veth_name2} || true")

    print("✅ VPC Peering established successfully!")

def unpeer_vpcs(vpc1_name, vpc1_cidr, vpc2_name, vpc2_cidr):
    print(f"\n🗑️ Removing peering between {vpc1_name} and {vpc2_name}")
    
    veth_name1 = f"pr1-{vpc1_name}"[:14]
    veth_name2 = f"pr2-{vpc2_name}"[:14]

    # 1. Delete static routes
    run(f"ip route del {vpc2_cidr} dev {veth_name1} || true")
    run(f"ip route del {vpc1_cidr} dev {veth_name2} || true")
    
    # 2. Delete the veth pair 
    run(f"ip link del {veth_name1} || true")

    print("✅ VPC Peering removed.")

# ------------------ Security Group Core (Part 4) ------------------

def apply_security_group(vpc_name, subnet_type, rules):
    print(f"\n🛡️ Applying Security Group rules to {vpc_name}-{subnet_type}")

    ns_name = f"{vpc_name}-{subnet_type}"
    chain_name = f"SG-{vpc_name.upper()}-{subnet_type[0].upper()}" # Unique chain name

    # 1. Cleanup previous SG chain before creating a new one (important for testing)
    run(f"ip netns exec {ns_name} iptables -D INPUT -j {chain_name} || true")
    run(f"ip netns exec {ns_name} iptables -F {chain_name} || true")
    run(f"ip netns exec {ns_name} iptables -X {chain_name} || true")
    
    # 2. Create a new iptables chain inside the namespace
    run(f"ip netns exec {ns_name} iptables -N {chain_name}")
    
    # 3. Insert a jump rule at the start of the INPUT chain to hit our SG chain
    run(f"ip netns exec {ns_name} iptables -I INPUT 1 -j {chain_name}")

    # 4. Apply the rules to the new chain
    for rule in rules:
        try:
            protocol, port = rule.split(":")
            protocol = protocol.lower()

            # Handle ICMP
            if protocol == "icmp":
                run(f"ip netns exec {ns_name} iptables -A {chain_name} -p icmp -j ACCEPT")
                print(f"   -> Added Rule: ICMP ACCEPT")
            
            # Handle TCP/UDP
            elif protocol in ("tcp", "udp"):
                if port.lower() == "any":
                    run(f"ip netns exec {ns_name} iptables -A {chain_name} -p {protocol} -j ACCEPT")
                    print(f"   -> Added Rule: {protocol.upper()} ANY PORT ACCEPT")
                else:
                    run(f"ip netns exec {ns_name} iptables -A {chain_name} -p {protocol} --dport {port} -j ACCEPT")
                    print(f"   -> Added Rule: {protocol.upper()} Port {port} ACCEPT")
            
            # Catch all others
            else:
                 print(f"   -> SKIPPING unsupported protocol: {protocol}")
                 logging.warning(f"Skipped unsupported SG protocol: {protocol}")

        except ValueError:
            print(f"   -> SKIPPING invalid rule format: {rule}. Must be PROTO:PORT.")
            logging.warning(f"Skipped invalid SG rule: {rule}")
            continue

    # 5. Default Policy: Drop traffic that doesn't match the ACCEPT rules
    run(f"ip netns exec {ns_name} iptables -A {chain_name} -j DROP")
    print("   -> Default Rule: DROP all unmatched traffic.")
    
    print("✅ Security Group applied successfully.")

def remove_security_group(vpc_name, subnet_type):
    ns_name = f"{vpc_name}-{subnet_type}"
    chain_name = f"SG-{vpc_name.upper()}-{subnet_type[0].upper()}"

    print(f"\n🧹 Removing Security Group from {ns_name}")

    run(f"ip netns exec {ns_name} iptables -D INPUT -j {chain_name} || true")
    run(f"ip netns exec {ns_name} iptables -F {chain_name} || true")
    run(f"ip netns exec {ns_name} iptables -X {chain_name} || true")
    print("✅ Security Group removed.")

# ------------------ Lifecycle ------------------
def create_vpc(vpc_name, cidr, public, private, iface):
    print(f"\n🚀 Creating VPC: {vpc_name} (Base CIDR: {cidr})")
    
    try:
        ip_config = get_subnet_ips(cidr)
    except SystemExit:
        return 

    bridge = f"br-{vpc_name}"
    
    # Extract details
    vpc_cidr = ip_config["vpc_cidr"]
    bridge_ip = ip_config["bridge_ip"]
    central_gw_ip = ip_config["central_gw_ip"]
    
    # Public Subnet details
    ns_public = f"{vpc_name}-public"
    public_ns_ip = ip_config["public_ns_ip"]
    public_net_cidr = ip_config["public_net_cidr"]

    # Private Subnet details
    ns_private = f"{vpc_name}-private"
    private_ns_ip = ip_config["private_ns_ip"]
    private_net_cidr = ip_config["private_net_cidr"] # <-- FIX: Added missing variable
    
    # --- FIX: Unique VETH NAMES ---
    # Using vpc_name in the interface name prevents collisions
    pub_veth_ns = f"pns-{vpc_name}"[:14] 
    pub_veth_br = f"pbr-{vpc_name}"[:14]
    priv_veth_ns = f"vns-{vpc_name}"[:14]
    priv_veth_br = f"vbr-{vpc_name}"[:14]
    
    # 2. VPC Setup
    create_bridge(bridge, bridge_ip) 
    create_namespace(ns_public)
    create_namespace(ns_private)

    # Connect public subnet to bridge 
    connect_namespace_to_bridge(
        ns_public, pub_veth_ns, pub_veth_br, bridge, public_ns_ip, central_gw_ip, vpc_cidr
    )
    
    # Connect private subnet to bridge 
    connect_namespace_to_bridge(
        ns_private, priv_veth_ns, priv_veth_br, bridge, private_ns_ip, central_gw_ip, vpc_cidr
    )

    # 3. NAT Gateway & Isolation Setup (Part 2)
    setup_nat_and_isolation(public_net_cidr, iface)

    print("✅ VPC created successfully!")
    print(f"   Bridge GW: {bridge_ip}")
    print(f"   Public Subnet: {public_net_cidr}")
    print(f"   Private Subnet: {private_net_cidr}\n")

def delete_vpc(vpc_name, cidr):
    print(f"\n🧹 Cleaning up VPC: {vpc_name}")
    bridge = f"br-{vpc_name}"
    
    # 1. Determine the public subnet CIDR to clean up the specific NAT rule
    try:
        ip_config = get_subnet_ips(cidr)
        public_net_cidr = ip_config["public_net_cidr"]
    except SystemExit:
        public_net_cidr = None
        
    if public_net_cidr:
        iface = detect_inet_iface() 
        print(f"Removing NAT rule for {public_net_cidr} on {iface}...")
        run(f"iptables -t nat -D POSTROUTING -s {public_net_cidr} -o {iface} -j MASQUERADE || true")

    # 2. Delete Namespaces and Bridge
    for ns in [f"{vpc_name}-public", f"{vpc_name}-private"]:
        # Also clean up any potential SGs before deleting the namespace
        remove_security_group(vpc_name, "public")
        remove_security_group(vpc_name, "private")
        run(f"ip netns del {ns} || true")

    run(f"ip link del {bridge} || true")
    
    print("✅ All resources removed.\n")

def list_vpc():
    run("ip netns list")
    run("ip link show type bridge")
    run("ip route show") # Show host routes, including peering routes
    run("iptables -t nat -L POSTROUTING") # Show NAT rules

# ------------------ CLI ------------------
def main():
    parser = argparse.ArgumentParser(description="Simple VPC controller using Linux namespaces & bridges")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 'create' command
    create_p = subparsers.add_parser("create", help="Create a new VPC")
    create_p.add_argument("--name", required=True, help="Unique name for the VPC (e.g., prod-vpc)")
    create_p.add_argument("--cidr", required=True, help="Base IP range (e.g., 10.10.0.0/16)")
    create_p.add_argument("--public", required=False, default="/24", help="Public subnet CIDR size (default: /24).")
    create_p.add_argument("--private", required=False, default="/24", help="Private subnet CIDR size (default: /24).")
    create_p.add_argument("--iface", required=False, help="Host's outbound network interface (e.g., eth0).")

    # 'delete' command
    delete_p = subparsers.add_parser("delete", help="Delete an existing VPC")
    delete_p.add_argument("--name", required=True, help="Name of the VPC to delete.")
    delete_p.add_argument("--cidr", required=True, help="Original base CIDR, needed to find and delete the NAT rule.")

    # 'list' command
    subparsers.add_parser("list", help="List all VPC resources")

    # 'peer' command
    peer_p = subparsers.add_parser("peer", help="Establishes peering between two VPCs.")
    peer_p.add_argument("--vpc1-name", required=True, help="Name of the first VPC.")
    peer_p.add_argument("--vpc1-cidr", required=True, help="CIDR of the first VPC.")
    peer_p.add_argument("--vpc2-name", required=True, help="Name of the second VPC.")
    peer_p.add_argument("--vpc2-cidr", required=True, help="CIDR of the second VPC.")
    
    # 'unpeer' command
    unpeer_p = subparsers.add_parser("unpeer", help="Removes a peering connection between two VPCs.")
    unpeer_p.add_argument("--vpc1-name", required=True, help="Name of the first VPC.")
    unpeer_p.add_argument("--vpc1-cidr", required=True, help="CIDR of the first VPC.")
    unpeer_p.add_argument("--vpc2-name", required=True, help="Name of the second VPC.")
    unpeer_p.add_argument("--vpc2-cidr", required=True, help="CIDR of the second VPC.")

    # 'apply-sg' command (NEW - Part 4)
    sg_p = subparsers.add_parser("apply-sg", help="Applies security group rules to a namespace.")
    sg_p.add_argument("--vpc-name", required=True, help="Name of the VPC (e.g., prod-vpc).")
    sg_p.add_argument("--subnet", required=True, choices=["public", "private"], help="Subnet (public or private) to apply the SG to.")
    sg_p.add_argument("--rules", required=True, nargs='+', help="List of rules: PROTOCOL:PORT (e.g., tcp:22, icmp:any).")
    
    # 'remove-sg' command (NEW - Part 4 cleanup)
    remove_sg_p = subparsers.add_parser("remove-sg", help="Removes a security group from a namespace.")
    remove_sg_p.add_argument("--vpc-name", required=True, help="Name of the VPC.")
    remove_sg_p.add_argument("--subnet", required=True, choices=["public", "private"], help="Subnet to remove the SG from.")


    args = parser.parse_args()

    if args.command == "create":
        iface = args.iface or detect_inet_iface()
        create_vpc(args.name, args.cidr, args.public, args.private, iface) 
    elif args.command == "delete":
        delete_vpc(args.name, args.cidr) 
    elif args.command == "list":
        list_vpc()
    elif args.command == "peer":
        peer_vpcs(args.vpc1_name, args.vpc1_cidr, args.vpc2_name, args.vpc2_cidr)
    elif args.command == "unpeer":
        unpeer_vpcs(args.vpc1_name, args.vpc1_cidr, args.vpc2_name, args.vpc2_cidr)
    elif args.command == "apply-sg":
        apply_security_group(args.vpc_name, args.subnet, args.rules)
    elif args.command == "remove-sg":
        remove_security_group(args.vpc_name, args.subnet)

if __name__ == "__main__":
    main()
