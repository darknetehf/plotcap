import logging
import os
import sys
import tempfile

from pyvis.network import Network

from plotcap.api import parse_file
from plotcap.mac_address import get_manufacturer_name

logger = logging.getLogger(__name__)

NODE_MIN_SIZE = 10
NODE_MAX_SIZE = 50


def plot_network(pcap_file: str, layer: int = 2, resolve_oui: bool = True):
    """
    Build a summary of conversations:
    source MAC/IP address, destination/IP MAC address, number of packets
    """

    conversations = parse_file(pcap_file=pcap_file, layer=layer)
    packet_counter = sum(conversations.values())
    logger.debug(f"Number of packets: {packet_counter}")

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
            packets=0,  # this property will be updated in a second stage
            shape="dot",
            color="#97c2fc",
            title=node,
            borderWidth=2,
            physics=False,  # freeze node position after manual rearrangement
        )

    # add edges between nodes, both ways
    for conversation, packet_count in conversations.items():
        logger.debug(
            f"{conversation.src} to {conversation.dst}  - packet_count: {packet_count}"
        )

        nt.add_edge(
            source=conversation.src,
            to=conversation.dst,
            title=f"{packet_count} packets",
        )
        # sum of emitted packets
        nt.node_map[conversation.src]["packets"] += packet_count

    # resize nodes in second pass
    for node in nt.nodes:

        # compute packet ratio for node, based on emitted traffic
        packet_percentage = node["packets"] / packet_counter

        # set node size in proportion to emitted traffic, with a minimum size
        node["size"] = max(NODE_MIN_SIZE, (NODE_MAX_SIZE * packet_percentage))

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
    return plot_network(pcap_file=pcap_file, layer=2, resolve_oui=resolve_oui)


def plot_layer3(pcap_file: str, resolve_oui: bool = True):
    return plot_network(pcap_file=pcap_file, layer=3, resolve_oui=resolve_oui)
