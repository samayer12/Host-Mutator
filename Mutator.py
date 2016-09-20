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
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types
from threading import Timer
from random import randint

class Mutator(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Mutator, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.RIP_VIP = {}
        self.VIP_RIP = {}
        
        # Setup default for IP translation
        # self.RIP_VIP.setdefault(dpid, {})
        # self.VIP_RIP.setdefault(dpid, {})
        self.mutate()

        t = Timer(300, self.mutate)
        t.start()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        timeout = 30

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=timeout, hard_timeout=timeout, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def mutate(self):
        for address in range(1,10):
            VIP = '10.131.2.'+str(randint(11,100))
            while(VIP_used(VIP)):
                VIP = '10.131.2.'+str(randint(11,100))
            self.RIP_VIP['10.131.2.'+str(address)] = VIP
            self.VIP_RIP[VIP] = '10.131.2.'+str(address)
            
            self.logger.info(VIP)
       
    def VIP_used(self, VIP):
        if VIP in RIP_VIP:
            return true
        else:
            return false    

    def address_translation(self, RIP, VIP):
        if RIP not in RIP_VIP:
            return false
        elif VIP not in VIP_RIP:
            return false
        else:
            return true
        
        # self.RIP_VIP['10.131.1.2'] = '10.131.1.7'
        # del self.VIP_RIP['10.131.1.5']
        # self.VIP_RIP['10.131.1.7'] = '10.131.1.2'
        #
        # self.logger.info('changed address')
        # # Lookup virtual address
        # if rip in self.RIP_VIP[dpid]:
        #     return self.RIP_VIP[dpid][rip]
        # # Create virtual address for src if it doesn't have one yet
        # else:
        #     for address in self.ipPool:
        #         if address not in self.RIP_VIP[dpid]:
        #             self.RIP_VIP[dpid][rip] = address
        #             return address

    def packet_out(self, msg, ofproto, parser, datapath, in_port, actions):
        data = None

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def arpTranslation(self, arpPkt, dpid, parser, out_port, ofproto, msg, datapath, in_port):
        arpPkt = arpPkt[0]
        src_rip = arpPkt.src_ip
        dst_vip = arpPkt.dst_ip
        
        # Catch if there exists a translation
        if not self.address_translation(src_rip, dst_vip):
            return
            
        src_vip = self.RIP_VIP[src_rip]
        dst_rip = self.VIP_RIP[dst_vip]

        self.logger.info('src_RIP: %s, src_VIP: %s', src_rip, src_vip)
        self.logger.info('dst_RIP: %s, dst_VIP: %s', dst_rip, dst_vip)

        actions = [parser.OFPActionSetField(arp_tpa=dst_rip), parser.OFPActionSetField(arp_spa=src_vip),
                   parser.OFPActionOutput(out_port)]

        # install a flow to avoid the controller having to decide
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_type=0x806, arp_tpa=dst_vip)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        self.packet_out(msg, ofproto, parser, datapath, in_port, actions)

    def icmpTranslation(self, ipv4Pkt, dpid, parser, out_port, ofproto, msg, datapath, in_port):
        ipv4Pkt = ipv4Pkt[0]
        src_rip = ipv4Pkt.src
        dst_vip = ipv4Pkt.dst
        
        # Catch if there exists a translation
        if !self.address_translation(src_rip, dst_vip):
            return
        
        src_vip = self.RIP_VIP[src_rip]
        dst_rip = self.VIP_RIP[dst_vip]

        self.logger.info('src_RIP: %s, src_VIP: %s', src_rip, src_vip)
        self.logger.info('dst_RIP: %s, dst_VIP: %s', dst_rip, dst_vip)

        actions = [parser.OFPActionSetField(ipv4_dst=dst_rip), parser.OFPActionSetField(ipv4_src=src_vip),
                   parser.OFPActionOutput(out_port)]

        # install a flow to avoid the controller having to decide
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_type=0x800, ipv4_dst=dst_vip)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        self.packet_out(msg, ofproto, parser, datapath, in_port, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        ''' General Setup'''
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        # Setup the packet
        pkt = packet.Packet(msg.data)

        # Get the different protocols, if the exist
        eth = pkt.get_protocols(ethernet.ethernet)[0] # We know that there will be an ethernet component, so we can get the first element
        icmpPkt = pkt.get_protocols(icmp.icmp)
        ipv4Pkt = pkt.get_protocols(ipv4.ipv4)
        arpPkt = pkt.get_protocols(arp.arp)

        # TODO: Create random virtualization (to include random ttl)
        timout = 30

        '''Basic Switch Functionality'''
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        '''Functionality for mac to port mappings'''
        # Default behavior for mac to port mappings
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        '''Translation Rules'''
        if arpPkt:
            self.arpTranslation(arpPkt, dpid, parser, out_port, ofproto, msg, datapath, in_port)
        elif icmpPkt:
            self.icmpTranslation(ipv4Pkt, dpid, parser, out_port, ofproto, msg, datapath, in_port)
        else:
            actions = [parser.OFPActionOutput(out_port)]
            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
            self.packet_out(msg, ofproto, parser, datapath, in_port, actions)
