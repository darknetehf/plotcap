import logging
import os
import sys
import tempfile
from collections import Counter, namedtuple

from pyvis.network import Network
from scapy.layers.inet import IP, Ether
from scapy.utils import PcapReader

from plotcap.mac_address import get_manufacturer_name

logger = logging.getLogger(__name__)


def plot_network(
    pcap_file: str, layer: str = "layer2", resolve_oui: bool = True
):
    """
    Build a summary of conversations:
    source MAC/IP address, destination/IP MAC address, number of packets
    """
    if layer == "layer2":
        ip_layer = Ether
    elif layer == "layer3":
        ip_layer = IP
    conversations = Counter()
    ConversationPair = namedtuple("ConversationPair", ["src", "dst"])
    bytes_read: int = 0
    with PcapReader(pcap_file) as pcap_reader:
        for packet_counter, packet in enumerate(pcap_reader, start=1):
            bytes_read += packet.wirelen
            if ip_layer in packet:
                logger.debug(
                    f"Packet {packet_counter} - Source: {packet[ip_layer].src}, Destination: {packet[ip_layer].dst} - Frame length: {packet[ip_layer].wirelen}"
                )
                # count conversations as tuples! (trailing comma is required)
                if (
                    packet[ip_layer].src != "ff:ff:ff:ff:ff:ff"
                    and packet[ip_layer].dst != "ff:ff:ff:ff:ff:ff"
                ):
                    conversations.update(
                        (
                            ConversationPair(
                                src=packet[ip_layer].src,
                                dst=packet[ip_layer].dst,
                            ),
                        )
                    )
    logger.info(f"Number of packets read: {packet_counter}")
    logger.info(f"Number of bytes read: {bytes_read}")

    nt = Network(height="750px", width="100%", directed=True, filter_menu=True)

    # get unique list of nodes
    nodes = set(
        [conversation.src for conversation, _ in conversations.items()]
        + [conversation.dst for conversation, _ in conversations.items()]
    )
    logger.info(f"Number of nodes: {len(nodes)}")
    if len(nodes) > 0:
        packet_average = packet_counter / len(nodes)
        logger.info(f"Average number of packets: {packet_average}")
    else:
        logger.warning(
            "No nodes found in capture file for the chosen layer => exit"
        )
        sys.exit(1)

    for node in nodes:
        # look up manufacturer
        if resolve_oui:
            node_label = f"{node}\n{get_manufacturer_name(node) or ''}"
        else:
            node_label = node
        nt.add_node(
            node,
            label=node_label,
            shape="dot",
            color="#97c2fc",
            title=node,
            borderWidth=2,
        )

    # add edges between nodes, both ways
    for conversation, packet_count in conversations.items():
        packet_ratio = (packet_count / packet_counter) * 100
        logger.debug(
            f"{conversation.src} to {conversation.dst}  - packet_count: {packet_count} - ratio = {packet_ratio}"
        )

        nt.add_edge(
            source=conversation.src,
            to=conversation.dst,
            title=f"{packet_count} packets"
            # weight=edge_width, value=edge_width
        )

        # double node size for nodes that sent more packets than average
        if packet_count > packet_average:
            node_size = 50
        else:
            node_size = 25
        logger.debug(
            f"Source: {conversation.src} => set node size: {node_size}"
        )
        nt.node_map[conversation.src]["size"] = node_size

    # because PyVis will output a HTML page and additional directories in the current directory,
    # we explicitly switch to the temp directory
    os.chdir(tempfile.gettempdir())

    # generate temp file name for HTML page
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmpfile:
        temp_file_name = tmpfile.name
    logger.debug(f"Create temp file for HTML page: {temp_file_name}")

    # open page in browser
    nt.show(temp_file_name, notebook=False)


def plot_layer2(pcap_file: str, resolve_oui: bool = True):
    return plot_network(
        pcap_file=pcap_file, layer="layer2", resolve_oui=resolve_oui
    )


def plot_layer3(pcap_file: str, resolve_oui: bool = True):
    return plot_network(
        pcap_file=pcap_file, layer="layer3", resolve_oui=resolve_oui
    )
