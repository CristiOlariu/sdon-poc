#!/usr/bin/env python

import os
from scapy.all import *
import time
import random
import string
# import fileTransfer

CTRL_IP    = "10.0.0.1"
CTRL_PORT  = "6633"
CTRL_INTF  = "veth2"
APP_INTF   = "veth4"

# f = os.popen('ifconfig eth0 | grep "inet\ addr" | cut -d: -f2 | cut -d" " -f1')
MY_PUB_IP = ""

MY_IP = ""
MY_ROLE = ""
MY_ID = ""

print "Hello, this is the sdonManager app."

def mainMenu():
    while True:
        os.system("clear")
        print "=== Sdon Main menu ==="
        print MY_IP, MY_ID
        print "Options"
        print "--- Step by step ---"
        print "1. Create OVS switch and send Hello message to controller"
        print "2. Get  IP  my FT sdon application"
        print "3. Get role my FT sdon application"
        print "4. Setup my tunnels to neighbours"
        print "5. Setup my OF rules"
        print ""
        print "A. Do steps 1, 2, 3, 4, 5 sequentially"
        print "S. Start file transfer SDoN app"
        # print "9. Send test packet"
        print "0. Exit"
        choice = raw_input("Your choice: ")
        execOption(choice)

def execOption(choice):
    print "Your choice is: " ,choice
    if choice == "1":
        createOvsSwitch()
    elif choice == "2":
        getMyIp()
    elif choice == "3":
        getMyRole()
    elif choice == "4":
        getMyTunnels()
    elif choice == "5":
        getMyOfRules()
    elif choice == "9":
        sendTestPacket()
    # elif choice == "l":
    #     waitingForInstructions()
    elif choice == "A":
        createOvsSwitch()
        time.sleep(1.1)

        getMyIp()
        time.sleep(1.1)

        getMyRole()
        time.sleep(1.1)

        getMyTunnels()
        time.sleep(1.1)

        getMyOfRules()
        time.sleep(1.1)

    elif choice == "S":
        getGo()
    elif choice == "0":
        exit()
    raw_input("Press any key to continue...")
    return

def handleSdonSignalingPkt(pkt):
    packet = pkt[0]
    if packet == None:
        print "Timeout occured before server replied."
        return False
    ctrlReply = packet[IP].payload
    print ctrlReply
    handleControllerReply(str(ctrlReply))

    return True


def createOvsSwitch():
    print "Creating OVS switch."
    # Remove potentially existing "sdon" OVS switch
    os.system("sudo ovs-vsctl del-br sdon")
    os.system("sudo ovs-vsctl del-br mgm")
    os.system("sudo ip link del veth1 type veth peer name veth2")
    os.system("sudo ip link del veth3 type veth peer name veth4")

    # Add and "sdon" ovs switch
    os.system("sudo ovs-vsctl add-br sdon")
    os.system("sudo ovs-vsctl add-br mgm")

    # Set eth0 to have no IP address
    os.system("sudo ifconfig eth0 0")

    # Add eth0 to this bridge
    os.system("sudo ovs-vsctl add-port mgm eth0")

    # Get an IP address for sdon using dhclient
    os.system("sudo dhclient mgm -v")

    f = os.popen('ifconfig mgm | grep "inet\ addr" | cut -d: -f2 | cut -d" " -f1')
    global MY_PUB_IP
    MY_PUB_IP = f.read().__str__().strip()
    print "My public IP is:" + MY_PUB_IP

    # Set "sdon" OF version to 1.3 so it can talk to Ryu
    os.system("sudo ovs-vsctl set bridge sdon protocols=OpenFlow13")

    # Create an interface pair for SdonManager
    os.system("sudo ip link add veth1 type veth peer name veth2")

    # Add veth1 to sdon
    os.system("sudo ovs-vsctl add-port sdon veth1")

    # Set veth1 and veth2 up
    os.system("sudo ifconfig veth1 up")
    os.system("sudo ifconfig veth2 up")

    # Set ipv4 forwarding to Enabled
    os.system("sudo sysctl -w net.ipv4.ip_forward=1")

    # Set remote controller
    os.system("sudo ovs-vsctl set-controller sdon tcp:" + CTRL_IP + ":" + CTRL_PORT)
    time.sleep(1)

    # Prepare and send an hello message to the controller
    data = MY_PUB_IP + ",hello"
    sendp(Ether()/IP(dst="1.2.3.4")/data, iface=CTRL_INTF)

    # Wait for the controller to acknowledge the packet (should happen in 3 seconds)
    pkt = sniff(count=1, filter="host 1.2.3.4", timeout=1, iface=CTRL_INTF)
    assert handleSdonSignalingPkt(pkt)


def getMyIp():
    print MY_PUB_IP
    pkt = Ether()/IP(src=str(MY_PUB_IP), dst="1.2.3.4")/UDP()/(MY_PUB_IP + ",getIp")
    print pkt
    sendp(pkt, iface=CTRL_INTF)
    pkt = sniff(count=1, filter="host 1.2.3.4", timeout=1, iface=CTRL_INTF)
    print pkt
    assert handleSdonSignalingPkt(pkt)


def getMyRole():
    sendp(Ether()/IP(src=MY_PUB_IP, dst="1.2.3.4")/UDP()/(MY_PUB_IP + ",getRole"), iface=CTRL_INTF)
    pkt = sniff(count=1, filter="host 1.2.3.4", timeout=1, iface=CTRL_INTF)
    assert handleSdonSignalingPkt(pkt)


def sendTestPacket():
    sendp(Ether()/IP(src=MY_PUB_IP, dst="1.2.3.4")/UDP()/(MY_PUB_IP + "TEST_TEST_TEST_TEST"), iface=CTRL_INTF)


def getMyTunnels():
    sendp(Ether()/IP(src=MY_PUB_IP, dst="1.2.3.4")/UDP()/(MY_PUB_IP + ",getTunnels"), iface=CTRL_INTF)
    pkt = sniff(count=1, filter="host 1.2.3.4", timeout=1, iface=CTRL_INTF)
    assert handleSdonSignalingPkt(pkt)

def getMyOfRules():
    sendp(Ether()/IP(src=MY_PUB_IP, dst="1.2.3.4")/UDP()/(MY_PUB_IP + ",getRules"), iface=CTRL_INTF)
    pkt = sniff(count=1, filter="host 1.2.3.4", timeout=1, iface=CTRL_INTF)
    assert handleSdonSignalingPkt(pkt)

# def waitingForInstructions():
#     pkt = sniff(count=1, filter="host 1.2.3.4", timeout=600, iface=CTRL_INTF)
#     assert handleSdonSignalingPkt(pkt)

def getGo():
    sendp(Ether()/IP(src=MY_PUB_IP, dst="1.2.3.4")/UDP()/(MY_PUB_IP + ",getGo"), iface=CTRL_INTF)
    pkt = sniff(count=1, filter="host 1.2.3.4", timeout=300, iface=CTRL_INTF)
    assert handleSdonSignalingPkt(pkt)


# Actions to be done after the Controller has responded
def setupMyIp(ip):
    # Create an interface pair for our File Transfer app
    os.system("sudo ip link add veth3 type veth peer name veth4")

    # Add veth3 to sdon
    os.system("sudo ovs-vsctl add-port sdon veth3")

    # Set veth3 and veth4 up
    os.system("sudo ifconfig veth3 up")
    os.system("sudo ifconfig veth4 up")
    time.sleep(1)
    print "sudo ifconfig veth4 " + str(ip)
    os.system(str("sudo ifconfig veth4 " + str(ip)))

    global MY_IP
    global MY_ID
    ip,mask = ip.split("/")
    MY_IP = ip
    id = ip.split(".")[-1]
    MY_ID = id
    print "My ID is: ", MY_ID

def setupMyTunnels(tunnels):
    greId = 0
    for neighIp in tunnels:
        print "Setting up gre tunnel for: " + neighIp
        # The convention to name the tunnels is >>> my tep IP = 10.lowerId.higherId.MyID/24 <<<
        # and the tunnel destination is >> gre remote IP = 10.lowerId.hirherID.neighID <<
        # if int(MY_ID) < int(neighID):
        #     a = MY_ID
        #     b = neighID
        # else:
        #     a = neighID
        #     b = MY_ID

        # tepIP = "10." + a + "." + b + "." + MY_ID + "/24"
        # neighIp =  "10." + a + "." + b + "." + neighID

        print "Tunnel settings: neighbour Ip=", neighIp

        # os.system("sudo ovs-vsctl add-port mgm tep" + str(greId) + " -- set interface tep" + str(greId) + " type=internal")
        # os.system("sudo ifconfig tep" + str(greId) + " " + tepIP)
        os.system("sudo ovs-vsctl add-port sdon gre" + str(greId) + " -- set interface gre" + str(greId) + " type=gre options:remote_ip=" + str(neighIp))

        greId += 1

def startMyFtApp():
    print "Starting the FT app!"
    print MY_ROLE
    if MY_ROLE == "S":
        print "I'm a sender and will start sending."

        sentMsg = ""

        if MY_IP == "192.168.101.1":
            recIp = "192.168.101.4"
        if MY_IP == "192.168.101.2":
            recIp = "192.168.101.6"

        for i in range(1,4):
            time.sleep(5)
            # Construct packet
            SRC = MY_IP
            DST = recIp
            seqNo = str(i)
            state = "ORG" # this is an original packet, the adder will change it to ADD
            isLast = "F"
            if i == 3:
                isLast = "T"

            data = "".join( [random.choice(string.letters[:26]) for i in xrange(8)] )
            sentMsg += data
            # data = "DumyData" * (16/8) # 8 bytes * 512/8 = 512 bytes in each packet
            payload = "/".join([SRC,DST,seqNo,state,isLast,data])
            pkt = Ether(dst="aa:1d:15:6f:14:cf")/IP(src=MY_IP, dst=recIp)/payload
            print "Sending packet: "
            print payload
            sendp(pkt, iface=APP_INTF)

        print "I've send: ", sentMsg

    if MY_ROLE == "D":
        # packets = []
        orgMsg = ""
        addMsg = ""
        lastFlagCount = 0
        last = False
        while not last:
            filter = "host 192.168.101.4 or host 192.168.101.6"
            pkt = sniff(count=1, filter=filter, iface=APP_INTF)
            # pkt = sniff(count=1, filter=("host " + MY_IP), iface=APP_INTF)
            print "I'm a Destination and got this packet: "
            pkt = pkt[0] # sniff outputs packets as list
            # print pkt
            pl = str(pkt[IP].payload)
            print "Payload is: ", pl
            # print "Type of pl is: ", type(pl)

            SRC, DST, seqNo, state, isLast, data = pl.split("/")

            if state == "ORG":
                orgMsg += data
            if state == "ADD":
                addMsg += data

            if isLast == "T":
                lastFlagCount += 1
            if lastFlagCount == 2:
                last= True

            # packets.append(pkt)

        print "Original message is:", orgMsg
        print "Coded    message is:", addMsg
        print "     ===XOR===      "
        print "Other    message is:", sxor(orgMsg,addMsg)

    if MY_ROLE == "F":
        # All I have to do is echo packets on the network
        lastFlagCount = 0
        last = False
        while not last:
            filter = "host 192.168.101.4 or host 192.168.101.6"
            pkt = sniff(count=1, filter=filter, iface=APP_INTF)
            print "I'm a forwarder, and am bouncing this packet:"
            pkt = pkt[0] # sniff outputs packets as list
            # print pkt
            payload = str(pkt[IP].payload)
            print payload

            SRC, DST, seqNo, state, isLast, data = payload.split("/")

            sendp(pkt, iface=APP_INTF)

            if isLast == "T":
                lastFlagCount += 1
            if lastFlagCount == 1:
                last= True


    if MY_ROLE == "A":
        # My role is more complicated:
        # I receive packets, get their seqNo, and if I have a matching one, I'll
        packets = {"192.168.101.1": {}, # this is for A
                   "192.168.101.2": {}} # this is for B
        last = False
        lastFlagCount = 0
        while not last:
            filter = "host 192.168.101.4 or host 192.168.101.6"
            pkt = sniff(count=1, filter=filter, iface=APP_INTF)
            print "I'm an adding and bouncing this packet:"
            pkt = pkt[0] # sniff outputs packets as list
            # print pkt
            payload = str(pkt[IP].payload)
            print "Payload is: ", payload
            # print "Type of payload is: ", type(payload)
            SRC, DST, seqNo, state, isLast, data = payload.split("/")

            # add packet details to dictionary
            packets[SRC][seqNo]=[SRC, DST, state, isLast, data]

            # check if this was the last packet of the session
            if isLast == "T":
                lastFlagCount += 1
            if lastFlagCount == 2:
                last= True

            # check if the current seqNo is already in the list of the other sender;
            pairIp = ""
            for i in packets.keys(): # Get the pair's IP address
                if SRC != i:
                    pairIp = i
                    print pairIp

            try: # if there is an entry for the pair of this packet
                pSRC, pDST, pState, pIsLast, pData = packets[pairIp][seqNo]

                # commonData = data + pData # here I have to do it with the actual XOR function
                commonData = sxor(data, pData)

                payload = "/".join([SRC,DST,seqNo,"ADD",isLast,commonData])
                # pairPayload = "/".join([pSRC,pDST,seqNo,"ADD",pIsLast,commonData])

                pkt = Ether(dst="aa:1d:15:6f:14:cf")/IP(src=SRC, dst=DST)/payload
                print pkt
                # pairPkt = Ether(dst="aa:1d:15:6f:14:cf")/IP(src=pSRC, dst=pDST)/pairPayload
                # print pairPkt

                # Now send the packets
                sendp(pkt, iface=APP_INTF)
                # time.sleep(2)
                # sendp(pairPkt, iface=APP_INTF)

            except KeyError:
                print "Yet, there is no pair entry for this seqNo: ", seqNo


def handleControllerReply(msg):
    action, context = msg.split(",")
    if action == "hello":
        print "Controller acknowledged my hello message."

    if action == "setIp":
        print "Controller wants me to start FT at: " + context
        ip = context
        setupMyIp(ip)

    if action == "setRoles":
        print "Controller wants me to start FT as: " + context
        roles = context.strip("[]")
        roles = roles.split(";")
        global MY_ROLE
        MY_ROLE = roles[0]
        print MY_ROLE

    if action == "setTunnels":
        print "Controller wants me create tunnels for: " + context
        tunnels = context.strip("[]")
        tunnels = tunnels.split(";")
        setupMyTunnels(tunnels)

    if action == "setRules":
        print "Controller acknowledged my getRules message."

    if action == "setGo":
        print "Controller confirmed I can start my FT app."
        startMyFtApp()

def sxor(s1,s2):
    # convert strings to a list of character pair tuples
    # go through each tuple, converting them to ASCII code (ord)
    # perform exclusive or on the ASCII code
    # then convert the result back to ASCII (chr)
    # merge the resulting array of characters as a string
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

mainMenu()
