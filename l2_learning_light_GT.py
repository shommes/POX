# Copyright 2011 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
This is an L2 learning switch written directly against the OpenFlow library.
It is derived from one written live for an SDN crash course.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
import time

import redis #GT 
import datetime, inspect #GT 
import logging #GT 
import config #GT 

'''Import for logging module''' #GT 
logger = logging.getLogger("DBHandler_logger")#GT 
hdlr = logging.FileHandler("/var/tmp/dbHandler.log")#GT 
formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")#GT 
hdlr.setFormatter(formatter)#GT 
logger.addHandler(hdlr)#GT 
logger.setLevel(logging.DEBUG)#GT 
current_cookie = 0 #GT 
log = core.getLogger()

# We don't want to flood immediately when a switch connects.
FLOOD_DELAY = 5


class LearningSwitch (EventMixin):
    """
    The learning switch "brain" associated with a single OpenFlow switch.
    
    When we see a packet, we'd like to output it on a port which will
    eventually lead to the destination.  To accomplish this, we build a
    table that maps addresses to ports.
    
    We populate the table by observing traffic.  When we see a packet
    from some source coming from some port, we know that source is out
    that port.
    
    When we want to forward traffic, we look up the desintation in our
    table.  If we don't know the port, we simply send the message out
    all ports except the one it came in on.  (In the presence of loops,
    this is bad!).
    
    In short, our algorithm looks like this:
    
    For each new flow:
    1) Use source address and port to update address/port table
    2) Is destination address a Bridge Filtered address, or is Ethertpe LLDP?
    * This step is ignored if transparent = True *
    Yes:
    2a) Drop packet to avoid forwarding link-local traffic (LLDP, 802.1x)
    DONE
    3) Is destination multicast?
    Yes:
    3a) Flood the packet
    DONE
    4) Port for destination address in our address/port table?
    No:
    4a) Flood the packet
    DONE
    5) Is output port the same as input port?
    Yes:
    5a) Drop packet and similar ones for a while
    6) Install flow table entry in the switch so that this
    flow goes out the appopriate port
    6a) Send buffered packet out appopriate port
    """
    def _handle_ConnectionUp(self, event): #GT 
        logger.info("Connection %s" %(event.connection))#GT 
        #Create database handler #GT  
        self.dbHandler = DBHandler()#GT 
        #Add switch entry to the data base --> Key: switchID | Field | Value #GT  
        self.dbHandler.addSwich(event.dpid)#GT 
    def __init__ (self, connection, transparent):
        # Switch we'll be adding L2 learning switch capabilities to
        self.connection = connection
        self.transparent = transparent
        
        # Our table
        self.macToPort = {}
        
        # We want to hear PacketIn messages, so we listen
        self.listenTo(connection)
    
    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))
    
    def _handle_PacketIn (self, event):
        """
        Handles packet in messages from the switch to implement above algorithm.
        """
        
        global current_cookie #GT 
        packet = event.parse()
        
        def flood ():
            """ Floods the packet """
            if event.ofp.buffer_id == -1:
                log.warning("Not flooding unbuffered packet on %s",
                dpidToStr(event.dpid))
                return
            msg = of.ofp_packet_out()
            if time.time() - self.connection.connect_time > FLOOD_DELAY:
                # Only flood if we've been connected for a little while...
                #log.debug("%i: flood %s -> %s", event.dpid, packet.src, packet.dst)
                msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            else:
                pass
            #log.info("Holding down flood for %s", dpidToStr(event.dpid))
            msg.buffer_id = event.ofp.buffer_id
            msg.in_port = event.port
            self.connection.send(msg)
        
        def drop (duration = None):
            """
            Drops this packet and optionally installs a flow to continue
            dropping similar ones for a while
            """
            if duration is not None:
                if not isinstance(duration, tuple):
                    duration = (duration,duration)
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet)
                msg.idle_timeout = duration[0]
                msg.hard_timeout = duration[1]
                msg.actions.append(of.ofp_action_output(port = port))
                msg.buffer_id = event.ofp.buffer_id
                msg.cookie = current_cookie #Set the flow identifier  #GT 
                #Sent flow to switch #GT 
                self.connection.send(msg)
                l_scriptName = inspect.getfile(inspect.currentframe())# Script name  #GT 
                l_lineNumber = inspect.currentframe().f_back.f_lineno # Get line number #GT 
                l_timestamp = datetime.datetime.now()# Timestamp #GT 
                
                #Add flow entry to switch ---> key: FlowID | Field | Value #GT 
                header = of.ofp_header()#GT 
                self.dbHandler.addFlowEntry(msg, header, event.dpid, l_scriptName, l_lineNumber, l_timestamp)#GT 
                
                #Set flow active --> SwitchID | FlowId | Value = 1 #GT 
                self.dbHandler.modifySwichEntry(event.dpid, msg.cookie)#GT 
                
                #Increase the flow identifier (cookie) #GT 
                current_cookie = current_cookie + 1 #GT 
            elif event.ofp.buffer_id != -1:
                msg = of.ofp_packet_out()
                msg.buffer_id = event.ofp.buffer_id
                msg.in_port = event.port
                self.connection.send(msg)
        
        self.macToPort[packet.src] = event.port # 1
        
        if not self.transparent:
            if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered(): # 2
                drop()
                return
        
        if packet.dst.isMulticast():
            flood() # 3a
        else:
            if packet.dst not in self.macToPort: # 4
                log.debug("Port for %s unknown -- flooding" % (packet.dst,))
                flood() # 4a
            else:
                port = self.macToPort[packet.dst]
                if port == event.port: # 5
                    # 5a
                    log.warning("Same port for packet from %s -> %s on %s.  Drop." %
                    (packet.src, packet.dst, port), dpidToStr(event.dpid))
                    drop(10)
                    return
                # 6
                log.debug("installing flow for %s.%i -> %s.%i" %
                (packet.src, event.port, packet.dst, port))
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet)
                msg.idle_timeout = 10
                msg.hard_timeout = 30
                msg.actions.append(of.ofp_action_output(port = port))
                msg.buffer_id = event.ofp.buffer_id # 6a
                msg.cookie = current_cookie #Set the flow identifier  #GT 
                #Sent flow to switch #GT 
                self.connection.send(msg)
                l_scriptName = inspect.getfile(inspect.currentframe())# Script name  #GT 
                l_lineNumber = inspect.currentframe().f_back.f_lineno # Get line number #GT 
                l_timestamp = datetime.datetime.now()# Timestamp #GT 
                
                #Add flow entry to switch ---> key: FlowID | Field | Value #GT 
                header = of.ofp_header()#GT 
                self.dbHandler.addFlowEntry(msg, header, event.dpid, l_scriptName, l_lineNumber, l_timestamp)#GT 
                
                #Set flow active --> SwitchID | FlowId | Value = 1 #GT 
                self.dbHandler.modifySwichEntry(event.dpid, msg.cookie)#GT 
                
                #Increase the flow identifier (cookie) #GT 
                current_cookie = current_cookie + 1 #GT 

class l2_learning (EventMixin):
    """
    Waits for OpenFlow switches to connect and makes them learning switches.
    """
    def __init__ (self, transparent):
        self.listenTo(core.openflow)
        self.transparent = transparent
    
    def _handle_ConnectionUp (self, event):
        log.debug("Connection %s" % (event.connection,))
        LearningSwitch(event.connection, self.transparent)


def launch (transparent=False):
    """
    Starts an L2 learning switch.
    """
    core.registerNew(l2_learning, str_to_bool(transparent))
class DBHandler: #GT
    def __init__(self):
        logger.info(' DBHandler created, writting in db = %s ',config.DB_STR)
        self.r_server = redis.Redis(host="localhost", port=6379, db=config.DB_STR)
    
    '''Add entry in db for each switch that joined
    key: switch dpid, maped to ip'''
    def addSwich(self, dpid):
        logger.info(' Added switch with IP: 10.92.0.%s',config.m[dpid])
        swStr="sw"+config.m[dpid]
        c=self.r_server.hget(swStr,"total")
        if (c==None):
            self.r_server.hmset(swStr,{"total":0})
        else:
            self.r_server.hmset(swStr,{"total":c})
    
    '''Modify entry for switch when new flow is installed'''
    def modifySwichEntry(self, dpid, flowId):
        swStr="sw"+config.m[dpid]
        self.r_server.hincrby(swStr, "total")
        self.r_server.hset(swStr,flowId, "-")
        logger.info(' Mark active flow cookie = %s ', flowId)
    
    ''' Add flow entry in db
    key: switch + flow cookie, value flow fields '''
    def addFlowEntry(self, flow, header, dpid, l_scriptName, l_lineNumber, l_timestamp):
        flowId=flow.cookie
        logger.info(' Add flow information for flow cookie = %s', flowId)
        
        actions=flow.actions.pop()
        
        self.r_server.hmset(flowId, {"prog":l_scriptName,
        "sid":config.m[dpid],
        "lic":l_lineNumber, 
        "time":l_timestamp,                                    
        "h_type":header.header_type,                                     
        "dl_src":flow.match.dl_src, 
        "dl_dst":flow.match.dl_dst,
        "nw_proto":flow.match.nw_proto, 
        "nw_src":flow.match.nw_src, 
        "nw_dst":flow.match.nw_dst, 
        "tp_src":flow.match.tp_src, 
        "tp_dst":flow.match.tp_dst,  
        "command":flow.command, 
        "idle_timeout":flow.idle_timeout, 
        "hard_timeout":flow.hard_timeout, 
        "a_type":actions.type, 
        "a_port":actions.port})

