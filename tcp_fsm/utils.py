#! /usr/bin/env python
#coding=utf-8

'''
	BigBro @ 2021.04
'''

from scapy.all import *
import signal

tcp_flags_fin=0x01
tcp_flags_syn=0x02
tcp_flags_rst=0x04
tcp_flags_psh=0x08
tcp_flags_ack=0x10

tcp_flags_synack=(tcp_flags_syn|tcp_flags_ack)
tcp_flags_pshack=(tcp_flags_psh|tcp_flags_ack)
tcp_flags_rstack=(tcp_flags_rst|tcp_flags_ack)

TCP_SYN_SENT = 1
TCP_SYN_RECV = 2
TCP_ESTABLISHED = 3
TCP_FIN_WAIT = 4
TCP_RESET = 5

'''
	key
		sip, sport, dpi, dport
	value
		state, seq, ack, last TCP paylaod length	
'''
sessions = {}
tcp_pkt_flags = {0 : "No Flags", 1 : "SYN", 2 : "SYN + ACK", 3 : "PSH", 4 : "RST", 5 : "ACK", 6 : "FIN"}
tcp_pkt_states = {
	TCP_SYN_SENT : "TCP_SYN_SENT",
	TCP_SYN_RECV : "TCP_SYN_RECV",
	TCP_ESTABLISHED : "TCP_ESTABLISHED",
	TCP_FIN_WAIT : "TCP_FIN_WAIT",
	TCP_RESET : "TCP_RESET",
}

def send_tcp_pkts(type):
	keys = sessions.keys()
	for key in keys :
		value = sessions.get(key)
		state = value[0]
		seq = value[2]
		ack = value[1]
		if (type == 0):
			l3 = IP(src=key[2], dst=key[0])/TCP(sport=key[3], dport=key[1], flags=tcp_flags_rstack, seq=seq, ack=ack)
			print ("reset to [%s:%d => %s:%d] session (state: %s, seq/ack: %d/%d, length: %d)"
				% (key[2], key[3], key[0], key[1], tcp_pkt_states[state], ack, seq, value[3]))
		else :
			l3 = IP(src=key[2], dst=key[0])/TCP(sport=key[3], dport=key[1], flags=tcp_flags_fin, seq=seq, ack=ack)
			print ("fin to [%s:%d => %s:%d] session (state: %s, seq/ack: %d/%d)"
				% (key[2], key[3], key[0], key[1], tcp_pkt_states[state], seq, ack))
		send(l3, verbose=False)

def show_tcp_all_sessions():
	keys = sessions.keys()
	print ""
	print "session table: %d item(s)" % len(keys)
	for key in keys :
		value = sessions.get(key)
		state = value[0]
		print ("\t[%s:%d => %s:%d], state: %s" % (key[0], key[1], key[2], key[3], tcp_pkt_states[state]))

def signal_handler(signum, stack):
	print 'Received: %d' % signum
	if (signum == signal.SIGINT):
		send_tcp_pkts(0)
		show_tcp_all_sessions()
		exit(0)
	elif (signum == signal.SIGUSR1):
		show_tcp_all_sessions()
	else :
		send_tcp_pkts(1)
		show_tcp_all_sessions()

def tcp_flags_check(flags):
	if (flags & tcp_flags_syn):
		if (flags & tcp_flags_ack):
			return 2
		return 1
	elif (flags & tcp_flags_psh):
		return 3
	elif (flags & tcp_flags_rst):
		return 4
	elif (flags & tcp_flags_ack):
		return 5
	elif (flags & tcp_flags_fin):
		return 6
	else :
		return 0

def tcp_packet_handler(pkt):
	sip = pkt[IP].src
	dip = pkt[IP].dst
	sport = pkt[TCP].sport
	dport = pkt[TCP].dport
	flags = pkt[TCP].flags
	index = tcp_flags_check(flags)
	found = False

	print "[%s:%d => %s:%d], flags: %s (%x)" % (sip, sport, dip, dport, tcp_pkt_flags[index], flags)

	key = (sip, sport, dip, dport)

#	dict = sessions.get(key, False);
	if (sessions.has_key(key)) :
		found = True

	if (sport == 80 and dport != 80) :
		# This is packet from local host
		return

	# SYN
	if (index == 1):
		seq = random.randint(0, 4294967295)
		ack = pkt[TCP].seq + 1
		print "receive SYN, will insert the key/value to sessions"
		state = TCP_SYN_RECV
		value = (state, pkt[TCP].seq, 0, 0)
		sessions.update({key : value})
		flags = tcp_flags_synack
	else :
		if (found == False) :
			print "Session was not found, receive non-SYN (%s), IGNORE" % tcp_pkt_flags[index]
			return
		else :
			value = sessions.get(key)
			state = value[0]
			print "session state: %s, line: %d" % (tcp_pkt_states[state], sys._getframe().f_lineno )
		# ACK
		if (index == 5):
			if (state == TCP_SYN_RECV):
				value = (TCP_ESTABLISHED, value[1], value[2], value[3])
				sessions.update({key : value})
				print "TCP 3-way handshake was completed successfully"
			else :
				print "session state: %d, line: %d" % (state, sys._getframe().f_lineno )
			return
		# PUSH or PUSH + ACK
		elif (index == 3):
			ip_hdr_len = pkt[IP].len - pkt[IP].ihl * 4
			tcp_hdr_len = pkt[TCP].dataofs * 4
			tcp_data_len = ip_hdr_len - tcp_hdr_len
			seq = pkt[TCP].ack
			ack = pkt[TCP].seq + tcp_data_len
			flags = tcp_flags_ack
			value = (value[0], pkt[TCP].seq, pkt[TCP].ack, tcp_data_len)
		# RST
		elif (index == 4):
			print "receive RST, Ignore"
			value = (TCP_RESET, value[1], value[2], value[3])
			sessions.update({key : value})
			return
		# FIN
		elif (index == 6):
			seq = pkt[TCP].ack
			ack = pkt[TCP].seq + 1
			flags = tcp_flags_ack
		#	value = (value[0], pkt[TCP].seq, pkt[TCP].ack, 0)
		else :
			print "Invalid Packet: %s/%d" % (tcp_pkt_flags[index], index)
			return

		# insert or update(seq, ack, state etc.)
		sessions.update({key : value})

	l3 = IP(src=dip, dst=sip)/TCP(sport=dport, dport=sport, flags=flags,seq=seq,ack=ack)
	send(l3, verbose=False)
