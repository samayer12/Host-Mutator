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


class Mutator(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Mutator, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ipTranslation = {}

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
        # self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        

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
        self.logger.info(msg.buffer_id)

        # Setup the packet
        pkt = packet.Packet(msg.data)
        
        # Get the different protocols, if the exist
        eth = pkt.get_protocols(ethernet.ethernet)[0] # We know that there will be an ethernet component, so we can get the first element
        icmpPkt = pkt.get_protocols(icmp.icmp)
        ipv4Pkt = pkt.get_protocols(ipv4.ipv4)
        arpPkt = pkt.get_protocols(arp.arp)        
        
        ''' Basic Switch Functionality'''
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        '''ARP Translation'''
        if arpPkt !=[]:
            arpPkt = arpPkt[0]
            dst_ip = arpPkt.dst_ip
            src_ip = arpPkt.src_ip

            # Lookup virtual address
            # Create virtual address for src if it doesn't have one yet

            if dst_ip == '10.131.1.5':
                actions = [parser.OFPActionSetField(arp_tpa='10.131.1.2'), parser.OFPActionOutput(out_port)]

                # install a flow to avoid packet_in next time
                # if out_port != ofproto.OFPP_FLOOD:
                    # match = parser.OFPMatch(in_port=in_port, eth_type=0x806, arp_tpa='10.131.1.2')
                    # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    # if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    #     self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    #     return
                    # else:
                    #     self.add_flow(datapath, 1, match, actions)
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                self.logger.info("You hit the controller 1")
            elif src_ip == '10.131.1.2':
                actions = [parser.OFPActionSetField(arp_spa='10.131.1.5'), parser.OFPActionOutput(out_port)]

                # install a flow to avoid packet_in next time
                # if out_port != ofproto.OFPP_FLOOD:
                #     match = parser.OFPMatch(in_port=in_port, eth_type=0x806, arp_spa = '10.131.1.2')
                    # TODO: for some reason the buffer is not showing up as empty, so I'm getting an error about an empty buffer. Maybe fix later
                    #verify if we have a valid buffer_id, if yes avoid to send both
                    #flow_mod & packet_out
                    # if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    #     self.add_flow(datapath, 1, match, actions)
                    #
                    #     # self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    #     return
                    # else:
                    #     self.add_flow(datapath, 1, match, actions)
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                self.logger.info("You hit the controller 2")
            else:
                actions = [parser.OFPActionOutput(out_port)]
                # install a flow to avoid packet_in next time
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                    # TODO: for some reason the buffer is not showing up as empty, so I'm getting an error about an empty buffer. Maybe fix later
                    #verify if we have a valid buffer_id, if yes avoid to send both
                    #flow_mod & packet_out
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions)

                        # self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions)
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                self.logger.info("You hit the controller 3")
        elif icmpPkt !=[]:
            ipv4Pkt = ipv4Pkt[0]
            dst_ip = ipv4Pkt.dst
            src_ip = ipv4Pkt.src

            if dst_ip == '10.131.1.5':
                actions = [parser.OFPActionSetField(ipv4_dst='10.131.1.2'),parser.OFPActionOutput(out_port)]
                # install a flow to avoid packet_in next time
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(in_port=in_port, eth_type=0x800, ipv4_dst=dst_ip)
                    # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    # if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    #     self.add_flow(datapath, 1, match, actions)
                    #
                    #     # self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    #     return
                    # else:
                    #     self.add_flow(datapath, 1, match, actions)
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                self.logger.info("You hit the controller 4")

            elif src_ip == '10.131.1.2':
                actions = [parser.OFPActionSetField(ipv4_src='10.131.1.5'),parser.OFPActionOutput(out_port)]
                # install a flow to avoid packet_in next time
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(in_port=in_port, eth_type=0x800, ipv4_src=src_ip)

                    # TODO: for some reason the buffer is not showing up as empty, so I'm getting an error about an empty buffer. Maybe fix later
                    #verify if we have a valid buffer_id, if yes avoid to send both
                    #flow_mod & packet_out
                    # if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    #     self.add_flow(datapath, 1, match, actions)
                    #
                    #     # self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    #     return
                    # else:
                    #     self.add_flow(datapath, 1, match, actions)
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                self.logger.info("You hit the controller 5")

            else:
                actions = [parser.OFPActionOutput(out_port)]
                # install a flow to avoid packet_in next time
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)

                    # TODO: for some reason the buffer is not showing up as empty, so I'm getting an error about an empty buffer. Maybe fix later
                    #verify if we have a valid buffer_id, if yes avoid to send both
                    #flow_mod & packet_out
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions)
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                self.logger.info("You hit the controller 6")
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
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
            self.logger.info("You hit the controller 7")
