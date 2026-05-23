# monitor_of15.py

from operator import attrgetter

from ryu.base import app_manager

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.ofproto import ofproto_v1_5

from ryu.lib import hub


class MonitorStats15(app_manager.RyuApp):
    """
    Monitor de estadisticas usando OpenFlow 1.5.

    Esta version pide SOLO estadisticas de puertos.
    Se elimina temporalmente OFPFlowStatsRequest porque en tu caso
    Open vSwitch lo esta rechazando con:

    OFPET_BAD_REQUEST / OFPBRC_BAD_MULTIPART
    """

    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MonitorStats15, self).__init__(*args, **kwargs)

        # Diccionario de switches conectados.
        # self.datapaths[dpid] = datapath
        self.datapaths = {}

        # Hilo paralelo que ejecuta el monitor cada cierto tiempo.
        self.monitor_thread = hub.spawn(self.monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange,
               [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        """
        Registra o elimina switches segun su estado.

        MAIN_DISPATCHER:
            El switch esta conectado y listo.

        DEAD_DISPATCHER:
            El switch se desconecto.
        """

        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info("Registrando switch: %s", datapath.id)
                self.datapaths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info("Eliminando switch: %s", datapath.id)
                del self.datapaths[datapath.id]

    def monitor(self):
        """
        Bucle principal del monitor.

        Cada 5 segundos solicita estadisticas a cada switch conectado.
        """

        while True:
            for datapath in self.datapaths.values():
                self.request_stats(datapath)

            hub.sleep(5)

    def request_stats(self, datapath):
        """
        Solicita estadisticas de puertos.

        IMPORTANTE:
        Aqui NO se solicita OFPFlowStatsRequest.
        Esa era la parte que estaba generando el error BAD_MULTIPART.
        """

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        self.logger.info(
            "Solicitando estadisticas de puertos al switch %s",
            datapath.id
        )

        # OFPP_ANY significa: solicitar estadisticas de todos los puertos.
        req = parser.OFPPortStatsRequest(
            datapath=datapath,
            flags=0,
            port_no=ofproto.OFPP_ANY
        )

        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """
        Procesa la respuesta de estadisticas de puertos.

        Muestra por cada puerto:
        - paquetes recibidos
        - bytes recibidos
        - errores de recepcion
        - paquetes transmitidos
        - bytes transmitidos
        - errores de transmision
        """

        datapath_id = ev.msg.datapath.id
        body = ev.msg.body

        self.logger.info("---- Estadisticas de puertos ----")

        print("")
        print("datapath          port     rx-pkts  rx-bytes rx-error tx-pkts  tx-bytes tx-error")
        print("---------------- -------- -------- -------- -------- -------- -------- --------")

        for stat in sorted(body, key=attrgetter('port_no')):
            print(
                "%016x %8x %8d %8d %8d %8d %8d %8d" %
                (
                    datapath_id,
                    stat.port_no,
                    stat.rx_packets,
                    stat.rx_bytes,
                    stat.rx_errors,
                    stat.tx_packets,
                    stat.tx_bytes,
                    stat.tx_errors
                )
            )
