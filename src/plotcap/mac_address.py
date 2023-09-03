import logging
from typing import Union

import netaddr

logger = logging.getLogger(__name__)


def get_manufacturer_name(mac_address: str) -> Union[str, None]:
    """
    Attempt to get manufacturer name from MAC address
    """
    try:
        mac = netaddr.EUI(mac_address)
        oui = mac.oui
        manufacturer = oui.registration().org
        logger.debug(
            f"Found manufacturer for MAC address: {mac_address} => {manufacturer}"
        )
        return manufacturer
    except netaddr.core.NotRegisteredError:
        logger.warning(f"No manufacturer found for MAC address: {mac_address}")
        return None
