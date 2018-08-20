/***************************
 * RAW Socket Client (TX/RX Any Ether Packet)
 * 	Copyright: https://github.com/hiyouthinker @2018
 *
****************************/

#define	IFNAMSIZ	16
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <assert.h>
#include <sys/types.h>
/* First definition of SCM_RIGHTS @ arpa/inet.h
 *								-> netinet/in.h
 *									-> sys/socket.h
 */
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/if_ether.h>

/* Second definition of SCM_RIGHTS @ linux/ppp_defs.h
 *									-> linux/ppp_defs.h
 *										-> linux/if.h -> linux/socket.h
 * 
 * define _LINUX_SOCKET_H to avoid to redefine SCM_RIGHTS
 */
#define _LINUX_SOCKET_H
#include <linux/ppp_defs.h>
typedef unsigned short __kernel_sa_family_t;
#include <linux/if_pppox.h>
#include "libdebug.h"

#define check_param_err() if(ret < 0){\
					printf("Invalid param: -%c %s.\n", opt, optarg);\
					help();\
				}

/* from pppoe_api.h */
#define MY_TAG_END_OF_LIST        	0x0000
#define MY_TAG_SERVICE_NAME       	0x0101
#define MY_TAG_AC_NAME			0x0102
#define MY_TAG_HOST_UNIQ          	0x0103
#define MY_TAG_AC_COOKIE          	0x0104
#define MY_TAG_VENDOR_SPECIFIC    	0x0105
#define MY_TAG_RELAY_SESSION_ID   	0x0110
#define MY_TAG_PPP_MAX_PAYLOAD	0x0120
#define MY_TAG_SERVICE_NAME_ERROR 	0x0201
#define MY_TAG_AC_SYSTEM_ERROR    	0x0202
#define MY_TAG_GENERIC_ERROR      		0x0203
#define MY_TAG_HDR_SIZE 			4

struct name_value_s{
	char *name;
	__u16 proto;
};

static struct opt_value_s opt_value;
static char *raw_cmd;

static struct name_value_s l3[] = {
			{"PPPoED", ETH_P_PPP_DISC},
			{"PPPoES", ETH_P_PPP_SES},
			{"IP", ETH_P_IP},
			{"ARP", ETH_P_ARP},
			{NULL, 0},
	};

static struct name_value_s l4[] = {
			{"ICMP", IPPROTO_ICMP},
			{"IGMP", IPPROTO_IGMP},
			{"TCP", IPPROTO_TCP},
			{"UDP", IPPROTO_UDP},
			{NULL, 0},
	};

static struct name_value_s pppoe_code[] = {
			{"PADI", PADI_CODE},
			{"PADR", PADR_CODE},
			{"PADT", PADT_CODE},
			{NULL, 0},
	};

static char MyPacket[2048];

static void help(void);

static __u16 get_proto_by_name(char *name, struct name_value_s *l)
{
	while(l->name){
		if(!strcasecmp(name, l->name))
			return l->proto;
		l++;
	}
	return 0;
}

static int get_mac_from_string(char *src, char *mac, int opt)
{
	int buf[6], i = 0;
	
	if(sscanf(src, "%02x:%02x:%02x:%02x:%02x:%02x"
		,&buf[0], &buf[1], &buf[2], &buf[3], &buf[4], &buf[5]) != 6){
		printf("Invalid param: -%c %s.\n", opt, optarg);
		help();/* exit */
	}
	for(; i< 6; i++){
		mac[i] = buf[i] & 0xff;
	}
	return 0;
}

static int build_PADI_packet(void *l3)
{
	struct pppoe_hdr *phdr;
	struct pppoe_tag *ptag;
	int len = 0;
	
	phdr = l3;
	phdr->ver = 1;
	phdr->type = 1;
	phdr->code = opt_value.pcode;
	phdr->sid = 0;

	len = 0;
	ptag = (struct pppoe_tag *)((char *)phdr + sizeof(*phdr));
	ptag->tag_type = MY_TAG_SERVICE_NAME;
	ptag->tag_len = htons(len);
	if(len)
		memcpy(ptag->tag_data, "", len);

	len += MY_TAG_HDR_SIZE;
	if(0){
		int pid = getpid();

		ptag = (struct pppoe_tag *)((char *)phdr + len);
		ptag->tag_type = htons(MY_TAG_HOST_UNIQ);
		ptag->tag_len = htons(sizeof(pid));
		memcpy(ptag->tag_data, &pid, sizeof(pid));
		len += sizeof(pid) + MY_TAG_HDR_SIZE;
	}
	phdr->length = htons(len);

	return (sizeof(*phdr) + len);
}

static int build_PADT_packet(void *l3)
{
	struct pppoe_hdr *phdr;

	if(!(opt_value.opt & MyPSID)){
		printf("Please input sessionID of PPPoE for PADT\n");
		help();		
	}
	
	phdr = l3;
	phdr->ver = 1;
	phdr->type = 1;
	phdr->code = opt_value.pcode;;
	phdr->sid = htons(opt_value.psid);

	phdr->length = htons(0);

	return (sizeof(*phdr));
}

static int build_pppoed_packet(void *l3)
{
	switch(opt_value.pcode){
		case PADI_CODE:
			return build_PADI_packet(l3);
		case PADR_CODE:
			return build_PADI_packet(l3);
		case PADT_CODE:
			return build_PADT_packet(l3);
		default:
			printf("Invalid Code\n");
			help();
			break;
	}
	return 0;
}

static int build_raw_packet(struct opt_value_s *ov)
{
	struct ethhdr *eth = (struct ethhdr *)MyPacket;
	struct vlan_ethhdr_s *vhdr;
	void *l3;
	int tot_len = 0;

	if((opt_value.opt & L2INFO) != L2INFO){
		printf("Please input SMac & DMac & L3 Protocol & Out-Interface\n");
		help();
	}
	
	memcpy(eth->h_dest, opt_value.dmac, ETH_ALEN);
	memcpy(eth->h_source, opt_value.smac, ETH_ALEN);
	
	if(opt_value.opt & MyTag){
		vhdr = (struct vlan_ethhdr_s *)MyPacket;
		vhdr->h_vlan_proto = htons(ETH_P_8021Q);
		vhdr->h_vlan_TCI = htons(opt_value.tag);
		vhdr->h_vlan_encapsulated_proto = htons(opt_value.l3proto);
		tot_len = sizeof(*vhdr);
	}
	else{
		eth->h_proto = htons(opt_value.l3proto);
		tot_len = sizeof(*eth);
	}
	l3 = MyPacket + tot_len;
	
	switch(opt_value.l3proto){
		case ETH_P_PPP_DISC:
			tot_len += build_pppoed_packet(l3);
			break;
		case ETH_P_PPP_SES:

			break;
		case ETH_P_IP:
			if((opt_value.opt & L3INFO) != L3INFO){
				printf("Please input L4 Protocol & Src IP & Dest IP\n");
				help();
			}
			tot_len += build_ip_packet(l3, &opt_value, 0);			
			break;
		case ETH_P_ARP:
			break;
	}
	
	return tot_len;
}

static void help(void)
{
	if(!cmd_and_param[0])/* standalone Mode */
		sprintf(cmd_and_param, "%s\nUsage: %s", MyCopyRight, raw_cmd);
	
	printf("%s\n", cmd_and_param);
	printf("\t-m %-20ssrc MAC\n", "<MAC>");
	printf("\t-M %-20sdst MAC\n", "<MAC>");
	printf("\t-a %-20ssrc Address\n", "<IP>");
	printf("\t-A %-20sdst Address\n", "<IP>");
	printf("\t-p %-20ssrc port\n", "<PORT>");
	printf("\t-P %-20sdst port\n", "<PORT>");
	printf("\t-l %-20slayer 3 proto\n", "<STRING>");
	printf("\t-L %-20slayer 4 proto\n", "<STRING>");
	printf("\t-e %-20sCode of PPPoE\n", "<STRING>");
	printf("\t-s %-20sSessionID of PPPoE\n", "<NUM>");
	printf("\t-t %-20stags\n", "<NUM>");
	printf("\t-o %-20sOut Interface\n", "<INTERFACE>");
	printf("\t-c %-20scount\n", "<NUM>");
	printf("\t-r %-20swait for reply\n", "");
	printf("\t-d %-20sdebug switch\n", "");
	printf("\t-h %-20sShow This\n", "");
	exit(0);
}

int main (int argc, char **argv)
{
	struct sockaddr_in si;
	struct sockaddr *sa;
	int fd, opt, ret, len;
	int count = 1, nsend = 0;
	int need_recv = 0;

	memset(&opt_value, 0, sizeof(opt_value));
	raw_cmd = argv[0];

	while ((opt = getopt(argc, argv, "o:m:M:a:A:p:P:l:L:e:s:t:c:rdh")) != -1) {
		switch (opt) {
			case 'o':
				strncpy(opt_value.ifname, optarg, sizeof(opt_value.ifname) - 1);
				opt_value.opt |= MyOIf;
				break;
			case 'm':
				get_mac_from_string(optarg, opt_value.smac, opt);
				opt_value.opt |= MySMAC;
				break;
			case 'M':
				get_mac_from_string(optarg, opt_value.dmac, opt);
				opt_value.opt |= MyDMAC;
				break;
			case 'a':{
				__u32 addr;
				ret = inet_addr(optarg);
				if(ret != -1){
					addr = (__u32)ret;
					ret = 0;/* Success */
				}
				check_param_err();
				opt_value.opt |= MySIP;
				opt_value.saddr = addr;
				break;
			}
			case 'A':{
				__u32 addr;
				ret = inet_addr(optarg);
				if(ret != -1){
					addr = (__u32)ret;
					ret = 0;/* Success */
				}
				check_param_err();
				opt_value.opt |= MyDIP;
				opt_value.daddr = addr;
				break;
			}
			case 'p':
				ret = atoi(optarg);
				if(ret > 65535)
					ret = -1;
				check_param_err();
				opt_value.opt |= MySPort;
				opt_value.sport = (__u16)ret;
				break;
			case 'P':
				ret = atoi(optarg);
				if(ret > 65535)
					ret = -1;
				check_param_err();
				opt_value.opt |= MyDPort;
				opt_value.dport = (__u16)ret;
				break;
			case 'l':
				ret = get_proto_by_name(optarg, l3);
				if(ret == 0)
					ret = -1;
				check_param_err();
				opt_value.opt |= MyL3Protocol;
				opt_value.l3proto = (__u16)ret;
				break;
			case 'L':
				ret = get_proto_by_name(optarg, l4);
				if(ret == 0)
					ret = -1;
				check_param_err();
				opt_value.opt |= MyL4Protocol;
				opt_value.l4proto = (__u8)ret;
				break;
			case 'e':
				ret = get_proto_by_name(optarg, pppoe_code);
				if(ret == 0)
					ret = -1;
				check_param_err();
				opt_value.opt |= MyPCode;
				opt_value.pcode = (__u8)ret;
				break;
			case 's':
				ret = atoi(optarg);
				if(ret > 65535 || !ret)
					ret = -1;
				check_param_err();
				opt_value.opt |= MyPSID;
				opt_value.psid = (__u16)ret;
				break;
			case 't':
				ret = atoi(optarg);
				if(ret > 4096)
					ret = -1;
				check_param_err();
				opt_value.opt |= MyTag;
				opt_value.tag = (__u16)ret;
				break;
			case 'c':
				ret = atoi(optarg);
				check_param_err();
				count = ret;
				break;
			case 'r':
				need_recv = 1;
				break;
			case 'd':
				debug_switch++;
				break;
			case 'h':
				help();
				break;
			default:
				printf("param error.\n");
				help();
				break;
		}
	}

	/* check option & build packet */
	len = build_raw_packet(&opt_value);

	debug_out(DEBUG_LEVEL_DETAIL, "TX packet: %s.\n", bin_to_hex_string(MyPacket, len));
	
	fd = socket(PF_PACKET, SOCK_PACKET, htons(opt_value.l3proto));
	if(fd < 0){
		debug_out(DEBUG_LEVEL_ERROR, "socket: %m\n");
		goto done;
	}

	sa = (struct sockaddr *)&si;
	strcpy(sa->sa_data, opt_value.ifname);
	
	if (bind(fd, (struct sockaddr *) sa, sizeof(*sa)) < 0) {
		debug_out(DEBUG_LEVEL_ERROR, "bind: %m\n");
		close(fd);
		goto done;
	}
	
	while(nsend++ < count){
		char rbuf[2048];

		if(sendto(fd, MyPacket, len, 0, (struct sockaddr *)&si, sizeof(si) ) < 0){
			debug_out(DEBUG_LEVEL_ERROR, "sendto Packet failure (%m), index: %d\n", nsend);
			continue;
		}
		debug_out(DEBUG_LEVEL_INFO, "TX Packet success, index: %d, len: %d\n", nsend, len);
		if(need_recv){
			int length = recv(fd, rbuf, sizeof(rbuf), 0);
			if(length < 0){
				debug_out(DEBUG_LEVEL_ERROR, "RX Packet failure (%m), index: %d\n", nsend);
				continue;
			}
			debug_out(DEBUG_LEVEL_DETAIL, "RX packet: %s, length: %d.\n", bin_to_hex_string(rbuf, length), length);
		}
	}
done:
	if(fd >= 0){
		close(fd);
	}
	return 0;
}
