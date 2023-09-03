==========
PlotCap
==========

PlotCap - a simple network visualization tool.

Introduction
============

PlotCap is a simple command line tool written in Python and based on PyVis, that parses network capture files to render
PlotCap was designed for red team engagements, with the aim of quickly mapping out relationships between devices ("nodes") in a network.

Target groups are: network administrators, penetration testers and curious people.

Visualization can be performed at layer 2 (MAC addresses) and layer 3 (IP addresses).
Layer 2 is the default. The tool attempts to resolve MAC addresses unless directed otherwise.

Usage
=====

.. code-block:: bash

    plotcap  -f /capture.cap

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


Limitations
===========

- Although this is a command line tool, it requires a graphical environment and a web browser to render network maps. On headless systems we suggest using Xvfb to set up virtual sessions.
- PlotCap was tested on Linux only
- MAC addresses may not always be resolved to manufacturer names, especially if address randomization comes into play
- See the TODO file for more missing features