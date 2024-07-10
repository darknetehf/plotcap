import logging
from collections import Counter, namedtuple

from scapy.layers.inet import IP, Ether
from scapy.utils import PcapReader

logger = logging.getLogger(__name__)


def parse_file(pcap_file: str, layer: int = 2) -> Counter:
    """
    Build a summary of conversations:
    source MAC/IP address, destination/IP MAC address, number of packets
    """
    if layer == 2:
        ip_layer = Ether
    elif layer == 3:
        ip_layer = IP

    conversations = Counter()
    ConversationPair = namedtuple("ConversationPair", ["src", "dst"])
    bytes_read: int = 0

    with PcapReader(pcap_file) as pcap_reader:
        for packet_counter, packet in enumerate(pcap_reader, start=1):
            bytes_read += packet.wirelen
            if ip_layer in packet:
                logger.debug(
                    f"Packet {packet_counter} - Source: {packet[ip_layer].src}, Destination: {
                        packet[ip_layer].dst} - Frame length: {packet[ip_layer].wirelen}"
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
    return conversations
