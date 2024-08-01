==========
PlotCap
==========

PlotCap - a simple network visualization tool.

.. image:: preview.png
  :align: center
  :alt: Sample

.. contents:: Table of Contents

Introduction
============

PlotCap is a simple command line tool written in Python and based on PyVis, that parses network capture files (produced by tools such as tcpdump or Wireshark) to render a graph of the network topology in a web page.

PlotCap was designed for red team engagements, with the aim of quickly mapping out relationships between devices ("nodes") in a network.
Target groups are: network administrators, penetration testers and curious people.

Visualization can be performed at layer 2 (MAC addresses) and layer 3 (IP addresses).
Layer 2 is the default. The tool attempts to resolve MAC addresses unless directed otherwise.

Install
=======

You can install plotcap on your system by using pipx:

.. code-block:: bash

   pipx install git+https://github.com/darknetehf/plotcap.git

And optionally:

.. code-block:: bash

   pipx ensurepath

This will add '~/.local/bin' to your PATH environment variable.

Usage
=====

.. code-block:: bash

    plotcap  -f capture.cap

This is equivalent to:

.. code-block:: bash

    plotcap  -f capture.cap --layer2

or:

.. code-block:: bash

    plotcap  -f capture.cap --layer2 --resolve-oui

Do not resolve MAC addresses:

.. code-block:: bash

    plotcap  -f capture.cap --layer2 --no-resolve-oui

Show IP addresses:

.. code-block:: bash

    plotcap  -f capture.cap --layer3

To increase **verbosity** add ``-v`` or ``-vv`` for debugging.

API
===

A convenience API is available if you just want to parse the .pcap file and reuse the results, but don't want a graphical representation.

.. code-block:: python

   from plotcap.api import parse_file

   pcap_file = "/tmp/test.pcap"
   conversations = parse_file(pcap_file=pcap_file, layer=2)
   for conversation, packet_count in conversations.items():
      print(f"src: {conversation.src} - dst: {conversation.dst} - packets: {packet_count}")

Limitations
===========

- Although this is a command line tool, it requires a graphical environment and a web browser to render network maps. On headless systems we suggest using Xvfb to set up virtual sessions.
- PlotCap was tested on Linux only
- MAC addresses may not always be resolved to manufacturer names, especially if address randomization comes into play
- See the TODO file for more missing features