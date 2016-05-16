#!/bin/bash

# Remove potentially existing "sdon" OVS switch
sudo ovs-vsctl del-br sdon
sudo ip link del veth1 type veth peer name veth2

# Add and "sdon" ovs switch
sudo ovs-vsctl add-br sdon

# Set "sdon" OF version to 1.3 so it can talk to Ryu
sudo ovs-vsctl set bridge sdon protocols=OpenFlow13

# Create an interface pair
sudo ip link add veth1 type veth peer name veth2

# Add veth1 to sdon
sudo ovs-vsctl add-port sdon veth1

# Set veth1 up
sudo ifconfig veth1 up

# Set ipv4 forwarding to Enabled
sudo sysctl -w net.ipv4.ip_forward=1

# Set ip for veth2
sudo ifconfig veth2 192.168.111.1/24

# Add tunnels to "sdon"
sudo ovs-vsctl add-port sdon gre1 -- set interface gre1 type=gre options:remote_ip=10.0.0.101 
sudo ovs-vsctl add-port sdon gre2 -- set interface gre2 type=gre options:remote_ip=10.0.0.102 

# Set controller for "sdon"
sudo ovs-vsctl set-controller sdon tcp:10.0.0.1:6633

# DONE!
