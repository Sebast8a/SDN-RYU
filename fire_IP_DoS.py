# ip_blocker.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_5
from ryu.lib.packet import ether_types


class IPBlocker(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]

	#Asignamos un nombre para que el analizador lo busque y lo utilice
	_SERVICE_NAME = "ip_blocker"

	def __init__(self, *args, **kwargs):
		super(IPBlocker, self).__init__(*args, **kwargs)

		self.datapaths = {}
		self.blocked_ips = set()
		self.BLOCK_PRIORITY = 50000

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		self.datapaths[datapath.id] = datapath

		self.logger.info("IPBlocker conectado al switch dpid=%s", datapath.id)

	@set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
	def state_change_handler(self, ev):
		datapath = ev.datapath

		if ev.state == MAIN_DISPATCHER:
			self.datapaths[datapath.id] = datapath
			self.logger.info("IPBlocker registró switch dpid=%s", datapath.id)

		elif ev.state == DEAD_DISPATCHER:
			if datapath.id in self.datapaths:
				del self.datapaths[datapath.id]
				self.logger.info("IPBlocker eliminó switch dpid=%s", datapath.id)

	def block_ip(self, ip):
		if ip in self.blocked_ips:
			#self.logger.info("La IP %s ya estaba bloqueada", ip)
			return

		for datapath in self.datapaths.values():
			self.add_drop_rule(datapath, ip)

		self.blocked_ips.add(ip)
		self.logger.warning("IP BLOQUEADA: %s", ip)

	def add_drop_rule(self, datapath, ip):
		parser = datapath.ofproto_parser

		match = parser.OFPMatch(
			eth_type=ether_types.ETH_TYPE_IP,
			ipv4_src=ip
		)

		instructions = []

		mod = parser.OFPFlowMod(
			datapath=datapath,
			priority=self.BLOCK_PRIORITY,
			match=match,
			instructions=instructions,
			idle_timeout=0,
			hard_timeout=0
		)

		datapath.send_msg(mod)
