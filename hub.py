from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class BasicHub10(app_manager.RyuApp): #BasicHub10 es una aplicación heredada de RyuApp

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs): #Método constructor
        super(BasicHub10, self).__init__(*args, **kwargs) #nicializa correctamente la parte interna de Ryu
        self.packet_in_count = 0 #Crea un contador de paquetes recibidos

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) #cuando ocurra un EventOFPPacketIn, llama a la función de abajo
    def packet_in_handler(self, ev): #Recibe el evento ev
        msg = ev.msg #Mensaje del evento OpenFlow PacketIn
        datapath = msg.datapath #datapath representa al SW que envió el paquete
        ofproto = datapath.ofproto #Acceder a las acciones OpenFlow
        parser = datapath.ofproto_parser #Sirve para construir mensajes OpenFlow
	#msg.data contiene el paquete recibido
        pkt = packet.Packet(msg.data) #Con esto ryu interpreta los bytyes como un paquete
        eth = pkt.get_protocol(ethernet.ethernet) #Pedimos exclusivamente la cabecera ethernet

        if eth is None: #VAlidación por costumbre o buena práctica
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:  #Ignorar tráfico normal entre hosts
            return

        src = eth.src #MAC origen
        dst = eth.dst #MAC destino
        in_port = msg.in_port #Puerto por donde entró el paquete

        self.packet_in_count += 1

        self.logger.info(
            "PacketIn #%d | dpid=%s | in_port=%s | src=%s | dst=%s | eth_type=0x%04x",
            self.packet_in_count,
            datapath.id,
            in_port,
            src,
            dst,
            eth.ethertype
        ) #Impresión de la información de interés

        actions = [
            parser.OFPActionOutput(ofproto.OFPP_FLOOD) #Decisión del hub (inundar)
        ]

        data = None #No necesitamos reenviar los datos completos del paquete

        if msg.buffer_id == ofproto.OFP_NO_BUFFER: #El controlador debe enviar el paquete completo
            data = msg.data

        out = parser.OFPPacketOut( #Mensaje que el controlador envía al SW
            datapath=datapath, #A qué SW lo enviará
            buffer_id=msg.buffer_id, #Referencia al paquete guardado en el buffer del SW
            in_port=in_port, #Puerto donde entró originalmente
            actions=actions, #Qué hacer con el paquete (FLOOD)
            data=data #Datos del paquete
        )

        datapath.send_msg(out)
