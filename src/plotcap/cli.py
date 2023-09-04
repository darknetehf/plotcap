import argparse
import logging
import logging.config
import logging.handlers
import os
import sys
from pathlib import Path

import yaml

from plotcap import __version__
from plotcap.plotting import plot_layer2, plot_layer3

# constants
LOGGING_CONFIG_FILE = "logging.yml"
resolve_oui = True  # attempt to get manufacturer from MAC address


def setup_logging(yaml_file):
    logger = logging.getLogger(__name__)

    if not Path.exists(yaml_file):
        logging.basicConfig(
            stream=sys.stdout,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )
        logging.warning(
            f"File {yaml_file} not found, using default configuration for logging"
        )
    else:
        with open(yaml_file, "r") as f:
            yaml_config = yaml.safe_load(f.read())
            logging.config.dictConfig(yaml_config)

    return logger


def is_valid_file(file):
    if os.path.isfile(file):
        return file
    else:
        raise argparse.ArgumentTypeError("Invalid capture file")


def parse_arguments():
    parser = argparse.ArgumentParser(allow_abbrev=False)

    parser.add_argument(
        "--file",
        "-f",
        type=is_valid_file,
        dest="capture_file",
        required=True,
        help="Capture file name",
    )

    # resolve MAC addresses by default
    resolve_oui_group = parser.add_mutually_exclusive_group()
    resolve_oui_group.add_argument(
        "--resolve-oui", action="store_true", dest="resolve_oui"
    )
    resolve_oui_group.add_argument(
        "--no-resolve-oui", action="store_false", dest="resolve_oui"
    )
    parser.set_defaults(resolve_oui=True)

    # choose either layer 2 or 3
    layer_group = parser.add_mutually_exclusive_group()
    layer_group.add_argument(
        "-l2",
        "--layer2",
        action="store_const",
        dest="layer",
        const="l2",
        default="l2",
        help="visualize at layer 2 (MAC addresses)",
    )
    layer_group.add_argument(
        "-l3",
        "--layer3",
        action="store_const",
        dest="layer",
        const="l3",
        help="visualize at layer 3 (IP addresses)",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="%(prog)s {version}".format(version=__version__),
    )

    args = parser.parse_args()

    return args


def main():
    try:
        # do not set up logger yet in case CLI option -v/--version is set
        logger = logging.getLogger(__name__)

        # check command line arguments
        args = parse_arguments()

        # get current application dir and set up logger from YAML config
        current_dir = os.path.dirname(os.path.realpath(__file__))

        logger = setup_logging(Path(current_dir) / LOGGING_CONFIG_FILE)

        logger.info("Application starting")

        if args.layer == "l2":
            plot_layer2(
                pcap_file=args.capture_file, resolve_oui=args.resolve_oui
            )
        elif args.layer == "l3":
            plot_layer3(
                pcap_file=args.capture_file, resolve_oui=args.resolve_oui
            )

    except Exception as ex:
        exception_type = ex.__class__.__name__
        logger.exception(f"Unhandled exception: {exception_type}")
        sys.exit(1)
    finally:
        logger.info("Application terminating")


if __name__ == "__main__":
    main()
