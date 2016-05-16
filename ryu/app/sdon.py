# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import udp
from ryu.lib.packet import ipv4
from ryu.lib import addrconv
# from ryu.app import rest_router as rr
import struct

class Sdon(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Sdon, self).__init__(*args, **kwargs)

        # keeps and ip to datapath, parser, OFport ID --  dictionary
        self.sdonID_to_OF = {}

        # A node's public IP address is also their SDoN node id
        self.sdonID_to_apps = {}

        # set static roles for the FT app
        self.sdonID_to_FTrole = {
            # S = srouce, F = forwarder, A = adder, D = destination
            "10.0.0.101": "[S]", # node A
            "10.0.0.102": "[S]", # node B
            "10.0.0.103": "[A]", # node C
            "10.0.0.104": "[D]", # node D
            "10.0.0.105": "[F]", # node E
            "10.0.0.106": "[D]"  # node F
        }

        self.sdonID_to_FTappIP = {
            "10.0.0.101": "192.168.101.1/24",
            "10.0.0.102": "192.168.101.2/24",
            "10.0.0.103": "192.168.101.3/24",
            "10.0.0.104": "192.168.101.4/24",
            "10.0.0.105": "192.168.101.5/24",
            "10.0.0.106": "192.168.101.6/24"
        }

        self.sdonID_to_tunnels = {
            "10.0.0.101": "[10.0.0.103;10.0.0.104]",
            "10.0.0.102": "[10.0.0.103;10.0.0.106]",
            "10.0.0.103": "[10.0.0.101;10.0.0.102;10.0.0.105]",
            "10.0.0.104": "[10.0.0.101;10.0.0.105]",
            "10.0.0.105": "[10.0.0.103;10.0.0.104;10.0.0.106]",
            "10.0.0.106": "[10.0.0.102;10.0.0.105]"
        }

        self.sdonID_to_getGo = {
            "10.0.0.101": None,
            "10.0.0.102": None,
            "10.0.0.103": None,
            "10.0.0.104": None,
            "10.0.0.105": None,
            "10.0.0.106": None
        }

        self.sdonID_to_rules = {
            "10.0.0.101": {2: [3,4]},

            "10.0.0.102": {2: [3,4]},

            "10.0.0.103": {2: [5],
                           3: [2],
                           4: [2]},

            "10.0.0.104": {3: [2],
                           4: [2]},

            "10.0.0.105": {3: [2],
                           2: [4,5]},

            "10.0.0.106": {3: [2],
                           4: [2]}
        }

        # This should be done in negotiation with the SDoN database in a server
        self.subnets_to_apps = {
            "FT": "192.168.101.0/24"
        }
    #
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        print "PACKET IN!!!"
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        print datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        print "In port: " + str(in_port)

        pkt = packet.Packet(msg.data)
        print pkt
        # self.logger.info("packet-in %s" % (pkt,))
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            pkt_ip = pkt.get_protocol(ipv4.ipv4)
            if pkt_ip.dst == "1.2.3.4":
                print "Received SDoN signalling packet."
                data = str(pkt.protocols[-1])
                # sdonID = str(pkt_ip.src)
                print "Data: " + data
                self.handleSdonPacket(data, msg)


    def handleSdonPacket(self, data, msg):
        sdonID, action = data.split(",")
        sdonID = sdonID.strip()
        if action == "hello":
            self.handleSdonHello(sdonID, msg)
        if action == "getIp":
            self.handleGetIp(sdonID, msg)
        if action == "getRole":
            self.handleGetRole(sdonID, msg)
        if action == "getTunnels":
            self.handleGetTunnels(sdonID, msg)
        if action == "getRules":
            self.handleGetRules(sdonID, msg)
        if action == "getGo":
            self.handleGetGo(sdonID, msg)

    def handleSdonHello(self, sdonID, msg):
        print "SDoN node with pub IP: " + sdonID + " was added."
        self.sendReply(sdonID, msg, "hello,", "ack")
        print "Hello, ack sent back!"


    def handleGetIp(self, sdonID, msg):
        print "Got FT get IP request from:" + sdonID
        ip = self.sdonID_to_FTappIP[sdonID]
        self.sendReply(sdonID, msg, "setIp,", str(ip))

    def handleGetRole(self, sdonID, msg):
        print "Got FT get role request from:" + sdonID
        role = self.sdonID_to_FTrole[sdonID]
        self.sendReply(sdonID, msg, "setRoles,", str(role))

    def handleGetTunnels(self, sdonID, msg):
        print "Got getTunnels request from:" + sdonID
        tunnels = self.sdonID_to_tunnels[sdonID]
        self.sendReply(sdonID, msg, "setTunnels,", str(tunnels))

    def handleGetRules(self, sdonID, msg):
        print "Got getRules request from:" + sdonID
        self.sendReply(sdonID, msg, "setRules,", "ACK")
        self.setupRulesOnSdonNode(sdonID)

    def handleGetGo(self, sdonID, msg):
        print "Got getGo from: " + sdonID

        # This node is ready, set its flag to True
        self.sdonID_to_getGo[sdonID] = msg

        # Check if there is any other node left to ask to start,
        # if there is a node not chekced in, then don't give the go-ahead just yet
        for nId, origMgs in self.sdonID_to_getGo.items():
            if origMgs == None:
                return

        # if the function reached this point, it means the last node just checked in,
        # let the other know thay have to start trhei FT app
        for nId, origMgs in self.sdonID_to_getGo.items():
            self.sendReply(nId, origMgs, "setGo,", "ACK")

    def sendReply(self, sdonID, origMsg, action, reply):
        datapath = origMsg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = origMsg.match['in_port']
        if (action == "hello,"):
            # save this SdonManager in the dictionary so we can contact that switch when we want
            print "Saving " + str(sdonID) + "'s OF details."
            self.sdonID_to_OF[sdonID] = [datapath, parser, in_port]

            # Initialize the dictionary of Apps available for an SdonNode
            # self.sdonID_to_apps[pubIp] = []

        # Reply to the action message
        pkt = packet.Packet()
        e = ethernet.ethernet()
        i = ipv4.ipv4(src="10.0.0.1", dst = "1.2.3.4")
        # u = udp.udp()
        pkt= e/i/(str(action) + str(reply))
        pkt.serialize()

        data = pkt.data
        actions=[parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def setupRulesOnSdonNode(self, sdonID):
        print self.sdonID_to_OF
        datapath = self.sdonID_to_OF[sdonID][0]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Reply to the action message
        for inPort, outPorts in self.sdonID_to_rules[sdonID].items():
            print "In: ", inPort, "Outsputs: ", outPorts
            match = parser.OFPMatch(in_port=inPort)
            actions = []
            for outPort in outPorts:
                actions.append(parser.OFPActionOutput(outPort))

            self.add_flow(datapath, 1, match, actions)

        ## if out_port != ofproto.OFPP_FLOOD:
        ## match = parser.OFPMatch(ipv4_dst=ipv4_text_to_int(sdonID))
        # match = parser.OFPMatch(in_port=2) # this is the port of the FT app
        ## actions=[parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        # actions=[parser.OFPActionOutput(3), parser.OFPActionOutput(4)]
        # self.add_flow(datapath, 1, match, actions)


    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


def ipv4_text_to_int(ip_text):
    if ip_text == 0:
        return ip_text
    assert isinstance(ip_text, str)
    return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]
