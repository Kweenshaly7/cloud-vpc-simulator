#!/bin/bash

echo "Stopping all background Python servers..."
killall python3 2>/dev/null

echo "Removing all VPCs..."
sudo python3 ./vpcctl.py delete --name test-prod --cidr 10.10.0.0/16 || true
sudo python3 ./vpcctl.py delete --name dev-vpc --cidr 10.20.0.0/16 || true

echo "Removing temporary directories and resolv.conf links..."
sudo rm -rf /tmp/dev-vpc-public-app
sudo rm -rf /etc/netns/test-prod-public
sudo rm -rf /etc/netns/test-prod-private
sudo rm -rf /etc/netns/dev-vpc-public
sudo rm -rf /etc/netns/dev-vpc-private

echo "Cleanup complete."
