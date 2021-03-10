# By Evan Yandle 3/9/2021
# Licensed to the Public Domain (Free for All)
# Use at your own risk
from TrafficInspect import TrafficInspect
from scapy.all import wireshark, PacketList


address = input('Server Address:')
if not address:
    address = 'alternativenation.net'

inspection = TrafficInspect(address)
inspection.listen_for_traffic()
inspection.summarize()


if input('open in wireshark?') in ['y', 'ye', 'yes']:
    wireshark(inspection.packets)
