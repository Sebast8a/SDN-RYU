from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_5
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

import time


class MacRateBlocker(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MacRateBlocker, self).__init__(*args, **kwargs)

        #Lista de switches conectados al controlador
        self.datapath = {}

        # Registro de paquetes por MAC origen
        self.mac_activity = {}

        # MACs bloqueadas
        self.blocked_macs = set()

        # Parámetros del detector
        self.TIME_WINDOW = 5        # segundos para considerar
        self.MAX_PACKETS = 20      # X paquetes permitidos por ventana

        #self.MAX_BYTES_PER_SECOND = 5000

        # Prioridad alta para que el DROP tenga más peso que reglas normales del switch
        self.BLOCK_PRIORITY = 50000


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Se ejecuta cuando el switch se conecta al controlador.
        Instala la regla table-miss para enviar paquetes desconocidos al controlador.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapath[datapath.id] = datapath

        self.logger.info("Switch conectado: %s", datapath.id)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        """
        Instala una regla OpenFlow.
        Si actions está vacío, la regla descarta el tráfico.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if actions:
            instructions = [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions
                )
            ]
        else:
            instructions = []

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )

        datapath.send_msg(mod)

    def block_mac(self, datapath, src_mac):
        """
        Instala una regla para bloquear todo tráfico con eth_src = src_mac.
        """
        if src_mac in self.blocked_macs:
            return

        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_src=src_mac)

        # Lista vacía de acciones = DROP
        actions = []

        self.add_flow(
            datapath=datapath,
            priority=BLOCK_PRIORITY,
            match=match,
            actions=actions
        )

        self.blocked_macs.add(src_mac)

        self.logger.warning("MAC BLOQUEADA: %s", src_mac)

    def is_mac_abusive(self, src_mac):
        """
        Verifica si una MAC supera el umbral de tráfico.
        """
        current_time = time.time()

        if src_mac not in self.mac_activity:
            self.mac_activity[src_mac] = []

        # Agregar timestamp del paquete actual
        self.mac_activity[src_mac].append(current_time)

        # Mantener solo los paquetes dentro de la ventana de tiempo
        window_start = current_time - self.TIME_WINDOW

        self.mac_activity[src_mac] = [
            timestamp for timestamp in self.mac_activity[src_mac]
            if timestamp >= window_start
        ]

        packet_count = len(self.mac_activity[src_mac])

        self.logger.info(
            "MAC %s ha enviado %s paquetes en los últimos %s segundos",
            src_mac,
            packet_count,
            self.TIME_WINDOW
        )

        return packet_count > self.MAX_PACKETS

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Maneja los paquetes enviados desde el switch al controlador.
        """
        msg = ev.msg
        datapath = msg.datapath

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        # Ignorar LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src = eth.src

        # Si ya está bloqueada, no hacemos nada
        if src in self.blocked_macs:
            return

        # Detectar abuso por MAC origen
        if self.is_mac_abusive(src):
            for dp in self.datapath.values():
                self.block_mac(datapath, src)
                return
