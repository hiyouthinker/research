#!/usr/bin/env python
#coding=utf-8

'''
	BigBro @ 2021.04
'''
from scapy.all import *
import signal

import tcp_state

def send_tcp_pkts(type):
	keys = tcp_state.sessions.keys()
	for key in keys :
		value = tcp_state.sessions.get(key)
		state = value[0]
		seq = value[2]
		ack = value[1] + value[3]

		if (type == 0):
			l3 = IP(src=key[2], dst=key[0])/TCP(sport=key[3], dport=key[1], flags=tcp_state.tcp_flags_rstack, seq=seq, ack=ack)
			print ("reset to [%s:%d => %s:%d] session (state: %s, seq/ack: %d/%d, length: %d)"
				% (key[2], key[3], key[0], key[1], tcp_state.tcp_session_states[state], ack, seq, value[3]))
			value = (tcp_state.TCP_FIN_WAIT, value[1], value[2], value[3], tcp_state.TCP_SESSION_SUBSTATE_CLOSED | tcp_state.tcp_session_server_rst)
		else :
			l3 = IP(src=key[2], dst=key[0])/TCP(sport=key[3], dport=key[1], flags=tcp_state.tcp_flags_fin, seq=seq, ack=ack)
			print ("fin to [%s:%d => %s:%d] session (state: %s, seq/ack: %d/%d)"
				% (key[2], key[3], key[0], key[1], tcp_state.tcp_session_states[state], seq, ack))
			value = (tcp_state.TCP_FIN_WAIT, value[1], value[2], value[3], tcp_state.TCP_SESSION_SUBSTATE_CLOSED | tcp_state.tcp_session_server_rst)

		tcp_state.sessions.update({key : value})
		send(l3, verbose=False)

def show_tcp_all_sessions():
	keys = tcp_state.sessions.keys()
	print "session table: %d item(s)" % len(keys)
	for key in keys :
		value = tcp_state.sessions.get(key)
		state = value[0]
		if (state == tcp_state.TCP_FIN_WAIT):
			print ("\t[%s:%d => %s:%d], state: %s/%s (first %s)"
				% (key[0], key[1], key[2], key[3],
				tcp_state.tcp_session_states[state],
				tcp_state.tcp_session_substates[value[4] & 0x0f],
				tcp_state.tcp_session_destroy_first_pkt_dir[value[4] & 0xf0]))
		else :
			print ("\t[%s:%d => %s:%d], state: %s"
				% (key[0], key[1], key[2], key[3], tcp_state.tcp_session_states[state]))

def signal_handler(signum, stack):
	print 'Received: %d' % signum
	if (signum == signal.SIGINT):
		show_tcp_all_sessions()
		send_tcp_pkts(0)
		show_tcp_all_sessions()
		exit(0)
	elif (signum == signal.SIGUSR1):
		show_tcp_all_sessions()
	else :
		show_tcp_all_sessions()
		send_tcp_pkts(1)
		show_tcp_all_sessions()
