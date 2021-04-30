#! /usr/bin/env python
#coding=utf-8

'''
	BigBro @ 2021.04
'''

from scapy.all import *
import signal

import utils
import handler

cap_port = 80
cap_if = "eth1"
filter = "tcp port %d" % cap_port
print "capture TCP packet of port %d on %s" % (cap_port, cap_if)
signal.signal(signal.SIGTERM, utils.signal_handler)
signal.signal(signal.SIGINT, utils.signal_handler)
signal.signal(signal.SIGUSR1, utils.signal_handler)
sniff(filter = filter, prn = handler.tcp_packet_handler, store = 0, iface = "eth1", count = 0)

utils.show_tcp_all_sessions()