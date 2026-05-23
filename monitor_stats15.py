# Monitor de estadísticas
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_5
from ryu.lib import hub


class MonitorStats15(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(MonitorStats15, self).__init__(*args, **kwargs)
        self.datapaths = {}
        # Crea hilo que ejecuta _monitor()
        self.monitor_thread = hub.spawn(self._monitor)

    # Ejecuta esta función cuando cambia el estado de un switch
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])

    def _state_change_handler(self, ev):
        # datapath representa al switch
        datapath = ev.datapath

        # Si el switch se conectó
        if ev.state == MAIN_DISPATCHER:
            # Verifica que no esté registrado
            if datapath.id not in self.datapaths:
                # Muestra el ID del switch
                self.logger.debug('Registrando el Switch: %s',datapath.id)
                # Guarda el switch conectado
                self.datapaths[datapath.id] = datapath

        # Si el switch se desconectó
        elif ev.state == DEAD_DISPATCHER:
            # Verifica que exista en el diccionario
            if datapath.id in self.datapaths:
                # Log de desconexión
                self.logger.debug('Eliminando switch: %s',datapath.id)
                # Elimina el switch
                del self.datapaths[datapath.id]

    def _monitor(self):
        # Bucle infinito de monitoreo
        while True:
            # Recorre todos los switches conectados
            for dp in self.datapaths.values():
                # Solicita estadísticas al switch
                self._request_stats(dp)
            # Espera 10 segundos
            hub.sleep(10)

    def _request_stats(self, datapath):
     parser = datapath.ofproto_parser
     ofproto = datapath.ofproto

     self.logger.info("Solicitando estadisticas al switch %s", datapath.id)

     match = parser.OFPMatch()

     req = parser.OFPFlowStatsRequest(
        datapath=datapath,
        flags=0,
        table_id=ofproto.OFPTT_ALL,
        out_port=ofproto.OFPP_ANY,
        out_group=ofproto.OFPG_ANY,
        cookie=0,
        cookie_mask=0,
        match=match
     )
     datapath.send_msg(req)

     req = parser.OFPPortStatsRequest(
        datapath=datapath,
        flags=0,
        port_no=ofproto.OFPP_ANY
     )
     datapath.send_msg(req)


    def _flow_stats_reply_handler(self, ev):

        # Lista de flujos devuelta por el switch
        body = ev.msg.body
        # Encabezado de la tabla
        self.logger.info(
            'datapath         '
            'in-port  eth-dst           '
            'out-port packets  bytes'
        )

        self.logger.info(
            '---------------- '
            '-------- ----------------- '
            '-------- -------- --------'
        )

        # Filtra solo flujos prioridad 1
        # (flujos aprendidos por el switch)
        for stat in sorted(
            [flow for flow in body if flow.priority == 1],

            # Ordena por puerto entrada y MAC destino
            key=lambda flow: (
                flow.match['in_port'],
                flow.match['eth_dst']
            )
        ):

            # Imprime:
            # switch
            # puerto entrada
            # MAC destino
            # puerto salida
            # paquetes
            # bytes
            self.logger.info(
                '%016x %8x %17s %8x %8d %8d',
                # ID del switch
                ev.msg.datapath.id,
                # Puerto de entrada del flujo
                stat.match['in_port'],
                # MAC destino del flujo
                stat.match['eth_dst'],
                # Puerto de salida configurado
                stat.instructions[0].actions[0].port,
                # Paquetes coincidentes
                stat.packet_count,
                # Bytes coincidentes
                stat.byte_count
            )

    # Maneja respuestas de estadísticas de puertos
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):

        # Lista de estadísticas de puertos
        body = ev.msg.body
        # Encabezado de la tabla
        self.logger.info(
            'datapath         port     '
            'rx-pkts  rx-bytes rx-error '
            'tx-pkts  tx-bytes tx-error'
        )
        self.logger.info(
            '---------------- -------- '
            '-------- -------- -------- '
            '-------- -------- --------'
        )

        # Ordena por número de puerto
        for stat in sorted(
            body,
            key=attrgetter('port_no')
        ):
            # Imprime estadísticas del puerto
            self.logger.info(
                '%016x %8x %8d %8d %8d %8d %8d %8d',
                # ID del switch
                ev.msg.datapath.id,
                # Número de puerto
                stat.port_no,
                # Paquetes recibidos
                stat.rx_packets,
                # Bytes recibidos
                stat.rx_bytes,
                # Errores de recepción
                stat.rx_errors,
                # Paquetes transmitidos
                stat.tx_packets,
                # Bytes transmitidos
                stat.tx_bytes,
                # Errores de transmisión
                stat.tx_errors
            )
