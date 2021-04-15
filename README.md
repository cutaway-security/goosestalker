# GooseStalker

## Purpose

GooseStalker is a project to analyze and interact with Ethernet types associated with IEC 61850. Currently, the project is based on the Goose network packet parsing from the [Keith Gray Power Engineering Goose Repo](https://github.com/keith-gray-powereng/goose). These modules and scripts will parse network traffic to understand the IEC 61850 communications and to interact with devices communicating with these protocols.

## Modules and Scripts

* Goose
  * goose.py - Scapy layers to analyze packets (see TODO)
  * goose_pdu.py - ASN1 layers to analyze Goose data
* Scripts
  * goose_parser.py - script to display the Scapy layers and parsed Goose data. Outputs text version of Goose layers and data.
* PCAPS  
  * GOOSE_wireshark.pcap - Wireshark's PCAP file for testing. This does not contain messages with VLAN layers (see TODO list).
  * [ITI IEC61850 Goose PCAPS](https://github.com/ITI/ICS-Security-Tools/tree/master/pcaps/IEC61850)
* DOCS - Research into IEC61850 that outlines usage and packet format
  * [6921_IEC61850Network_MS_20190712_Web.pdf](https://cms-cdn.selinc.com/assets/Literature/Publications/Technical%20Papers/6921_IEC61850Network_MS_20190712_Web.pdf?v=20190821-201111)
  * [B5_PS1_117_DE_Jenkins_2017.pdf](https://www.researchgate.net/publication/339303436_How_to_hack_an_IEC_61850_system_or_protect_one)
  * [TR-61850.pdf](https://www.fit.vut.cz/research/publication/11832/.en)
  * [elsarticle-template.pdf](https://www.researchgate.net/publication/312327440_Interpreting_and_implementing_IEC_61850-90-5_Routed-Sampled_Value_and_Routed-GOOSE_protocols_for_IEEE_C371182_compliant_wide-area_synchrophasor_data_transfer)
  * [energies-12-02536.pdf](https://www.mdpi.com/1996-1073/12/13/2536/pdf-vor)
  * [sensors-21-01554-v2.pdf](https://www.mdpi.com/1424-8220/21/4/1554/pdf)
* LICENSE - maintained the Keith's original MIT license for this work
* Pipfile - required Python modules. Probably contains a few more than necessary to allow for additional development. See requirements below.

## Requirements and Installation

* [Pipenv](https://docs.pipenv.org/) - Pipfile should contain all required packages, to include a few nice-to-haves.
  * [Scapy](https://github.com/secdev/scapy) - comes with its own set of required packages
  * [PyASN1](https://pypi.org/project/pyasn1/) - Python ASN1 module
  * [iPython](https://ipython.org/)
  * cryptography - may or may not need this
* [Wireshark](https://www.wireshark.org/) - you'll want a second source to analyze PCAPs
  * [Herb Falk’s Skunkwork Network Analyzer](http://www.otb-consultingservices.com/home/shop/skunkworks-network-analyzer/) - a bit dated, but helps to analyze Goose / MMS / IEC61850 packets.
  * [Tshark](https://www.wireshark.org/docs/man-pages/tshark.html) - because command line packet analysis is always more fun.
* Admin Privileges - you'll need administrative privileges to capture and resend data on your system's network interface. 

## TODO

* Convert parser into module for other scripts
* Script to provide packet statistics
* Script to identify endpoints
* Script to identify control packets
* Replay script
* Spoofing script
