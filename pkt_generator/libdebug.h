/***************************
 * for debug
 * 	Copyright: https://github.com/hiyouthinker @2018
 *
****************************/

#include <linux/if_ether.h>

typedef unsigned short __u16;
typedef unsigned int __u32;
typedef __u32 __be32;
typedef __u16 __sum16;
typedef __u32 __wsum;
typedef unsigned int u32;

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/* This is same as struct vlan_ethhdr in kernel */
struct vlan_ethhdr_s {
	unsigned char	h_dest[ETH_ALEN];
	unsigned char	h_source[ETH_ALEN];
	__u16		h_vlan_proto;
	__u16		h_vlan_TCI;
	__u16		h_vlan_encapsulated_proto;
};

struct opt_value_s{
	int opt;
	char smac[6], dmac[6];
	char ifname[16];
	__u32 saddr, daddr;
	__u16 sport, dport, tag;
	__u16 l3proto;
	__u8 l4proto;
	__u8 pcode;	/* Code of PPPoE */
	__u8 psid;	/* SessionID of PPPoE */
	__u16 window;	/* for TCP */
};

#define MyCopyRight	"Copyright: Version 2.0 @BigBro/2020"

#define MySMAC 			0x0001
#define MyDMAC 			0x0002
#define MySIP 			0x0004
#define MyDIP 			0x0008
#define MySPort 		0x0010
#define MyDPort 		0x0020
#define MyL3Protocol 	0x0040
#define MyL4Protocol 	0x0080
#define MyTCPWindow		0x0100
#define MyPCode 		0x0200
#define MyPSID 			0x0400
#define MyTag 			0x0800
#define MyOIf 			0x1000

#define L2INFO		(MySMAC | MyDMAC | MyL3Protocol | MyOIf)
#define L3INFO		(MyL4Protocol | MySIP | MyDIP)

enum{
	DEBUG_LEVEL_IMPORTANT = 0,
	DEBUG_LEVEL_NONE = DEBUG_LEVEL_IMPORTANT,
	DEBUG_LEVEL_ERROR = 1,
	DEBUG_LEVEL_WARNING,
	DEBUG_LEVEL_INFO,
	DEBUG_LEVEL_DETAIL,
};

extern char cmd_and_param[256];
extern int debug_switch;
extern int udp_size;
extern unsigned short sport;
extern unsigned short dport;
extern char *local_ip;

#define debug_out(level, x...) do{\
					if(debug_switch >= level)\
						printf(x);\
				}while(0)

extern int build_ip_packet(void *l3, void *param, __u8 proto);
extern int is_tcpudp_packet(char *packet, int proto);
extern unsigned short tcpudp_packet_port(char *packet, int dir);
extern int set_tcp_keepalive(int fd, int keepalive);
extern char *getopt_simple(int argc, char **argv);
extern char *bin_to_hex_string(char *data, int dataLen);
extern char *ip_packet_address(char *packet, int dir);
extern __sum16 tcp_v4_check(int len, __be32 saddr,
				   __be32 daddr, __wsum base);
extern __sum16 udp_v4_check(int len, __be32 saddr,
				   __be32 daddr, __wsum base);
extern __wsum csum_partial(const void *buff, int len, __wsum wsum);
extern unsigned short checksum1(const void *addr, unsigned int len);
extern unsigned short checksum2(const void *addr, unsigned int len);
extern unsigned short checksum3(unsigned short *addr, int nleft);
extern unsigned short checksum4(unsigned short *addr, int nleft);

