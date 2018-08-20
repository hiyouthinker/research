/***************************
 * for debug
 * 	Copyright: https://github.com/hiyouthinker @2018
 *
****************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/icmp.h>
#include <linux/igmp.h>
#include "libdebug.h"

#define CSUM_MANGLED_0 ((__sum16)0xffff)

static unsigned int seq = 0x3456;
static unsigned int ack = 0x0000;

char cmd_and_param[256];
int debug_switch = 0;
int udp_size = 0;
unsigned short sport = 20000;
unsigned short dport = 80;

char *local_ip = "192.168.1.1";

struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};

struct udphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
};

/* TCP socket options */
/* form linux/tcp.h */
#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TCP_MAXSEG		2	/* Limit MSS */
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_KEEPIDLE		4	/* Start keeplives after this period */
#define TCP_KEEPINTVL		5	/* Interval between keepalives */
#define TCP_KEEPCNT		6	/* Number of keepalives before death */
#define TCP_SYNCNT		7	/* Number of SYN retransmits */
#define TCP_LINGER2		8	/* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT	9	/* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP	10	/* Bound advertised window */
#define TCP_INFO		11	/* Information about this connection. */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */
#define TCP_CONGESTION		13	/* Congestion control algorithm */
#define TCP_MD5SIG		14	/* TCP MD5 Signature (RFC2385) */

/*
 *	TCP option
 */
/* from net/tcp.h */
#define TCPOPT_NOP		1	/* Padding */
#define TCPOPT_EOL		0	/* End of options */
#define TCPOPT_MSS		2	/* Segment size negotiating */
#define TCPOPT_WINDOW		3	/* Window scaling */
#define TCPOPT_SACK_PERM        4       /* SACK Permitted */
#define TCPOPT_SACK             5       /* SACK Block */
#define TCPOPT_TIMESTAMP	8	/* Better RTT estimations/PAWS */
#define TCPOPT_MD5SIG		19	/* MD5 Signature (RFC2385) */
#define TCPOPT_EXP		254	/* Experimental */

/*
 *     TCP option lengths
 */
/* from net/tcp.h */
#define TCPOLEN_MSS            4
#define TCPOLEN_WINDOW         3
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_TIMESTAMP      10
#define TCPOLEN_MD5SIG         18
#define TCPOLEN_EXP_FASTOPEN_BASE  4

static int build_tcp_options(__be32 *p)
{
	*p++ = htonl((TCPOPT_MSS << 24) |
			       (TCPOLEN_MSS << 16) |
			       1460);
	
	*p++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_NOP << 16) |
			       (TCPOPT_SACK_PERM << 8) |
			       TCPOLEN_SACK_PERM);
	
	*p++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_WINDOW << 16) |
			       (TCPOLEN_WINDOW << 8) |
			       0);

	return 4*3;
}

static int build_l4_packet(int proto, void *l4, struct iphdr *iph)
{      
	struct tcphdr *th;
	struct udphdr *uh;
	int l4_head_len, l4_data_len = 0;
	char *l4_data;
	__wsum wsum = 0;

	switch(proto){
		case IPPROTO_TCP:/* Build a SYN */
			l4_head_len = sizeof(*th);
			th = l4;
			th->source	= htons(sport++);
			th->dest		= htons(dport);
			th->seq		= htonl(seq++);
			th->ack_seq	= htonl(ack);
			th->window = htons(65535);
			th->check = 0;
			th->urg_ptr = 0;
			l4_head_len += build_tcp_options((__be32 *)(th + 1));
			/* The Length of TCP Header */
			*(((__be16 *)th) + 6)	= htons((l4_head_len >> 2) << 12 | 0);
			th->syn = 1;
			th->check = tcp_v4_check(l4_head_len + l4_data_len, iph->saddr, iph->daddr,
							 csum_partial(th, th->doff << 2, wsum));
			iph->tot_len = htons(sizeof(struct iphdr) + l4_head_len + l4_data_len);
			break;
		case IPPROTO_UDP:
			l4_head_len = sizeof(*uh);
			l4_data_len = udp_size;
			iph->tot_len = htons(sizeof(struct iphdr) + l4_head_len + l4_data_len);
			uh = l4;
			uh->source 	= htons(sport++);
			uh->dest 	= htons(dport);
			uh->len 		= htons(l4_head_len);
			uh->check 	= 0;
			if(l4_data_len){
				l4_data = l4 + l4_head_len;
				memset(l4_data, 'a', l4_data_len);
				wsum = csum_partial(l4_data, l4_data_len, 0);
			}
			uh->check = udp_v4_check(l4_head_len + l4_data_len, iph->saddr, iph->daddr, 
							csum_partial(uh, l4_head_len, wsum));
			if (uh->check == 0)
				uh->check = CSUM_MANGLED_0;
			break;
		default:
			return 0;
	}
	return l4_head_len + l4_data_len;
}

static int build_tcp_packet(void *l4, struct iphdr *iph)
{
	return build_l4_packet(IPPROTO_TCP, l4, iph);
}

static int build_udp_packet(void *l4, struct iphdr *iph)
{
	return build_l4_packet(IPPROTO_UDP, l4, iph);
}

int build_ip_packet(void *l3, void *param, __u8 proto)
{
	int len = 0;
	struct iphdr *iph = l3;
	struct opt_value_s *ov = param;

	iph->version = 4;
	iph->ihl = 5;
	iph->id = random();
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->check = 0;
		
	if(ov){
		iph->protocol = ov->l4proto;
		iph->saddr = ov->saddr;
		iph->daddr = ov->daddr;
		proto = ov->l4proto;
	}
	else{
		iph->protocol = proto;
		if(local_ip)
			iph->saddr = inet_addr(local_ip);
		else
			iph->saddr = (unsigned int)random();
	}
	
	switch(proto){
		case IPPROTO_TCP:
			len = build_tcp_packet(l3 + iph->ihl * 4, iph);
			break;
		case IPPROTO_UDP:
			len = build_udp_packet(l3 + iph->ihl * 4, iph);
			break;
		case IPPROTO_ICMP:
			
			break;
		case IPPROTO_IGMP:
			
			break;
	}
	iph->check = checksum1(iph, iph->ihl * 4);
	return len + iph->ihl * 4;
}

int is_tcpudp_packet(char *packet, int proto)
{
	struct iphdr *iph;

	iph = (struct iphdr*)packet;
	
	return (iph->protocol == proto);
}

unsigned short tcpudp_packet_port(char *packet, int dir)
{
	struct iphdr *iph = (struct iphdr*)packet;
	struct tcphdr *th = (struct tcphdr *)(packet + iph->ihl * 4);

	/* struct tcphdr & struct udphdr is same in the first 4 bytes*/
	if(dir)
		return ntohs(th->dest);
	else
		return ntohs(th->source);
}

int set_tcp_keepalive(int fd, int keepalive)
{
	int val = 60;

	setsockopt(fd, SOL_SOCKET, TCP_KEEPINTVL, (void *)&val, sizeof(val));

	val = 30;
	setsockopt(fd, SOL_SOCKET, TCP_KEEPIDLE, (void *)&val, sizeof(val));

	val = 5;
	setsockopt(fd, SOL_SOCKET, TCP_KEEPCNT, (void *)&val, sizeof(val));
		
	return setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive, sizeof(keepalive));
}

char *getopt_simple(int argc, char **argv)
{
	static int index = 0;

	argc -= index;
	argv += index;
	
	while(argc){
		index++;
		if(argv[0][0] != '-' || !argv[0][1] || argv[0][2]){
			argc--;
			argv++;
			continue;
		}
		return &argv[0][1];
	}
	index = 0;
	return NULL;
}

char *bin_to_hex_string(char *data, int dataLen)
{
	static char hex[1024];
	int i = 0, len = (1024 - 1)/3;

	len = len > dataLen ? dataLen : len;
	memset(hex, 0, 1024);
	if(!len){
		strcpy(hex, "Empty");
	}
	for(i = 0; i < len; i++){
		sprintf( &hex[3*i], "%02x ", data[i] & 0xff );
	}
	return hex;
}

char* ip_packet_address(char *packet, int dir)
{
	struct iphdr *iph;
	struct in_addr ia;

	iph = (struct iphdr*)packet;

	if(dir)
		ia.s_addr = iph->daddr;
	else
		ia.s_addr = iph->saddr;
	return inet_ntoa(ia);
}

static __wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
			unsigned short len,
			unsigned short proto,
			__wsum sum)
{
	unsigned long long s = (u32)sum;

	s += (u32)saddr;
	s += (u32)daddr;
#if defined(__BIG_ENDIAN_BITFIELD)
	s += proto + len;
#else
	s += (proto + len) << 8;
#endif
	s += (s >> 32);
	return (__wsum)s;
}

/*
 * Fold a partial checksum
 */
static __sum16 csum_fold(__wsum csum)
{
	u32 sum = (u32)csum;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__sum16)~sum;
}

static __sum16 csum_tcpudp_magic(__be32 saddr, __be32 daddr, unsigned short len,
		  unsigned short proto, __wsum sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

/*
 * Calculate(/check) TCP checksum
 */
__sum16 tcp_v4_check(int len, __be32 saddr,
				   __be32 daddr, __wsum base)
{
	return csum_tcpudp_magic(saddr,daddr,len,IPPROTO_TCP,base);
}

__sum16 udp_v4_check(int len, __be32 saddr,
				   __be32 daddr, __wsum base)
{
	return csum_tcpudp_magic(saddr,daddr,len,IPPROTO_UDP,base);
}

static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

static unsigned int do_csum(const unsigned char *buff, int len)
{
	int odd;
	unsigned int result = 0;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long) buff;
	if (odd) {
#if defined(__LITTLE_ENDIAN)
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	if (len >= 2) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *) buff;
			len -= 2;
			buff += 2;
		}
		if (len >= 4) {
			const unsigned char *end = buff + ((unsigned)len & ~3);
			unsigned int carry = 0;
			do {
				unsigned int w = *(unsigned int *) buff;
				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (buff < end);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1){
#if __BYTE_ORDER == __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	}
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

__wsum csum_partial(const void *buff, int len, __wsum wsum)
{
	unsigned int sum = (unsigned int)wsum;
	unsigned int result = do_csum(buff, len);

	/* add in old sum, and carry.. */
	result += sum;
	if (sum > result)
		result += 1;
	return (__wsum)result;
}

unsigned short checksum1(const void *addr, unsigned int len)
{      
	int nleft = len;
	int sum = 0;
	unsigned short *w = (unsigned short *)addr;
	unsigned short answer;

	while(nleft > 1){
		sum += *w++;
		nleft -= 2;
	}
	if(nleft == 1){
		answer = 0;
		*(unsigned char *)(&answer) = *(unsigned char *)w;
		sum += answer;
	}
	sum = (sum>>16) + (sum&0xffff);
#if 0
	sum += (sum>>16);
#else
	sum = (sum>>16) + (sum&0xffff);
#endif
	answer = ~sum;
	return answer;
}

/* from ip_fast_csum in lib/checksum.c in kernel */
/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 */
__sum16 checksum2(const void *addr, unsigned int len)
{
	return (__sum16)~do_csum(addr, len);
}
	
/* from busybox-1.20.2/libbb/inet_cksum.c */
unsigned short checksum3(unsigned short *addr, int nleft)
{
	/*
	 * Our algorithm is simple, using a 32 bit accumulator,
	 * we add sequential 16 bit words to it, and at the end, fold
	 * back all the carry bits from the top 16 bits into the lower
	 * 16 bits.
	 */
	unsigned sum = 0;
	while (nleft > 1) {
		sum += *addr++;
		nleft -= 2;
	}

	/* Mop up an odd byte, if necessary */
	if (nleft == 1) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
			sum += *(unsigned char*)addr;
#else
			sum += *(unsigned char*)addr << 8;
#endif
	}

	/* Add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
	sum += (sum >> 16);                     /* add carry */

	return (unsigned short)~sum;
}

/* from zebra/lib/checksum.c */
unsigned short checksum4(register u_short *ptr, register int nbytes)/* return checksum in low-order 16 bits */
{
	register long		sum;		/* assumes long == 32 bits */
	u_short			oddbyte;
	register u_short	answer;		/* assumes u_short == 16 bits */

	/*
	 * Our algorithm is simple, using a 32-bit accumulator (sum),
	 * we add sequential 16-bit words to it, and at the end, fold back
	 * all the carry bits from the top 16 bits into the lower 16 bits.
	 */

	sum = 0;
	while (nbytes > 1)  {
		sum += *ptr++;
		nbytes -= 2;
	}

				/* mop up an odd byte, if necessary */
	if (nbytes == 1) {
		oddbyte = 0;		/* make sure top half is zero */
		*((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
		sum += oddbyte;
	}

	/*
	 * Add back carry outs from top 16 bits to low 16 bits.
	 */

	sum  = (sum >> 16) + (sum & 0xffff);	/* add high-16 to low-16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;		/* ones-complement, then truncate to 16 bits */
	return(answer);
}
