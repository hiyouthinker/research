/* 
 * BigBro @2023
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/types.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>

#include "common.h"

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"

/* from busybox */
struct query {
	const char *name;
	unsigned qlen;
	unsigned char query[512];
};

static const char *const rcodes[] = {
	"NOERROR",    // 0
	"FORMERR",    // 1
	"SERVFAIL",   // 2
	"NXDOMAIN",   // 3
	"NOTIMP",     // 4
	"REFUSED",    // 5
	"YXDOMAIN",   // 6
	"YXRRSET",    // 7
	"NXRRSET",    // 8
	"NOTAUTH",    // 9
	"NOTZONE",    // 10
	"11",         // 11 not assigned
	"12",         // 12 not assigned
	"13",         // 13 not assigned
	"14",         // 14 not assigned
	"15",         // 15 not assigned
};

static void help(char *cmd)
{
	printf("(version: 1.0/BigBro)\n\n");
	printf("%s usage:\n", cmd);
	printf("\t-h\tshow this help\n");
	printf("\t-S\tsource ip\n");
	printf("\t-D\tdst ip\n");
	printf("\t-H\tdomain\n");
	printf("\t-c\ttotal loop times\n");
	printf("\t-C\tper domain loop times\n");
	printf("\t-d\tenable debug\n");

	exit(0);
}

static void sig_handler(int signo)
{
	printf("received signal: %d\n", signo);

	exit(0);
}

static int xsocket(int domain, int type, int protocol)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(0);
	}

	return fd;
}

static int xbind(int fd, const struct sockaddr *addr, socklen_t len)
{
	if (bind(fd, addr, len) < 0) {
		printf("failed to bind to " NIPQUAD_FMT ": %s\n", NIPQUAD(((struct sockaddr_in*)addr)->sin_addr.s_addr), strerror(errno));
		exit(0);
	}
}

static int xconnect(int fd, const struct sockaddr *addr, socklen_t len)
{
	if (connect(fd, addr, len) < 0) {
		printf("failed to connect to " NIPQUAD_FMT ": %s\n", NIPQUAD(((struct sockaddr_in*)addr)->sin_addr.s_addr), strerror(errno));
		exit(0);
	}
}

static void *xmalloc(size_t size)
{
	void *p = malloc(size);
	if (!p) {
		perror("malloc");
		exit(0);
	}
	return p;
}

/* from busybox/networking/nslookup.c */
static struct query *add_query(int type, const char *dname)
{
	struct query *q;
	ssize_t qlen;

	q = xmalloc(sizeof(struct query));

	qlen = res_mkquery(QUERY, dname, C_IN, type,
			/*data:*/ NULL, /*datalen:*/ 0,
			/*newrr:*/ NULL,
			q->query, sizeof(q->query));

	q->name = dname;
	q->qlen = qlen;

	return q;
}

/* from busybox/networking/nslookup.c */
static int parse_reply(const unsigned char *msg, size_t len)
{
	HEADER *header;
	ns_msg handle;
	ns_rr rr;
	int i, n, rdlen;
	const char *format = NULL;
	char astr[INET6_ADDRSTRLEN], dname[MAXDNAME];
	const unsigned char *cp;

	header = (HEADER *)msg;
	if (!header->aa)
		printf("Non-authoritative answer:\n");

	if (ns_initparse(msg, len, &handle) != 0) {
		//printf("Unable to parse reply: %s\n", strerror(errno));
		return -1;
	}

	for (i = 0; i < ns_msg_count(handle, ns_s_an); i++) {
		if (ns_parserr(&handle, ns_s_an, i, &rr) != 0) {
			//printf("Unable to parse resource record: %s\n", strerror(errno));
			return -1;
		}

		rdlen = ns_rr_rdlen(rr);

		switch (ns_rr_type(rr))
		{
		case ns_t_a:
			if (rdlen != 4) {
				printf("unexpected A record length %d\n", rdlen);
				return -1;
			}
			inet_ntop(AF_INET, ns_rr_rdata(rr), astr, sizeof(astr));
			debug_print(PRINT_INFO, "Name:\t%s\nAddress: %s\n", ns_rr_name(rr), astr);
			break;

		case ns_t_aaaa:
			if (rdlen != 16) {
				printf("unexpected AAAA record length %d\n", rdlen);
				return -1;
			}
			inet_ntop(AF_INET6, ns_rr_rdata(rr), astr, sizeof(astr));
			/* bind-utils-9.11.3 uses the same format for A and AAAA answers */
			debug_print(PRINT_INFO, "Name:\t%s\nAddress: %s\n", ns_rr_name(rr), astr);
			break;

		case ns_t_ns:
			if (!format)
				format = "%s\tnameserver = %s\n";
			/* fall through */

		case ns_t_cname:
			if (!format)
				format = "%s\tcanonical name = %s\n";
			/* fall through */

		case ns_t_ptr:
			if (!format)
				format = "%s\tname = %s\n";
			if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
					ns_rr_rdata(rr), dname, sizeof(dname)) < 0
			) {
				//printf("Unable to uncompress domain: %s\n", strerror(errno));
				return -1;
			}
			printf(format, ns_rr_name(rr), dname);
			break;

		case ns_t_mx:
			if (rdlen < 2) {
				printf("MX record too short\n");
				return -1;
			}
			n = ns_get16(ns_rr_rdata(rr));
			if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
					ns_rr_rdata(rr) + 2, dname, sizeof(dname)) < 0
			) {
				//printf("Cannot uncompress MX domain: %s\n", strerror(errno));
				return -1;
			}
			printf("%s\tmail exchanger = %d %s\n", ns_rr_name(rr), n, dname);
			break;

		case ns_t_txt:
			if (rdlen < 1) {
				//printf("TXT record too short\n");
				return -1;
			}
			n = *(unsigned char *)ns_rr_rdata(rr);
			if (n > 0) {
				memset(dname, 0, sizeof(dname));
				memcpy(dname, ns_rr_rdata(rr) + 1, n);
				printf("%s\ttext = \"%s\"\n", ns_rr_name(rr), dname);
			}
			break;

		case ns_t_soa:
			if (rdlen < 20) {
				printf("SOA record too short:%d\n", rdlen);
				return -1;
			}

			debug_print(PRINT_INFO, "%s\n", ns_rr_name(rr));

			cp = ns_rr_rdata(rr);
			n = ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
			                       cp, dname, sizeof(dname));
			if (n < 0) {
				//printf("Unable to uncompress domain: %s\n", strerror(errno));
				return -1;
			}

			debug_print(PRINT_INFO, "\torigin = %s\n", dname);
			cp += n;

			n = ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
			                       cp, dname, sizeof(dname));
			if (n < 0) {
				//printf("Unable to uncompress domain: %s\n", strerror(errno));
				return -1;
			}

			debug_print(PRINT_INFO, "\tmail addr = %s\n", dname);
			cp += n;

			debug_print(PRINT_INFO, "\tserial = %lu\n", ns_get32(cp));
			cp += 4;

			debug_print(PRINT_INFO, "\trefresh = %lu\n", ns_get32(cp));
			cp += 4;

			debug_print(PRINT_INFO, "\tretry = %lu\n", ns_get32(cp));
			cp += 4;

			debug_print(PRINT_INFO, "\texpire = %lu\n", ns_get32(cp));
			cp += 4;

			debug_print(PRINT_INFO, "\tminimum = %lu\n", ns_get32(cp));
			break;

		default:
			break;
		}
	}

	return i;
}

static int send_query(int fd, struct query *q)
{
	int len;
	__u8 reply[512];
	__u8 rcode;

	if (write(fd, q->query, q->qlen) < 0) {
		printf("failed to write to dns server\n");
		exit(0);
	}

	debug_print(PRINT_DEBUG, "sent query for %s\n", q->name);

	len = read(fd, reply, sizeof(reply));
	if (len < 0) {
		printf("failed to read: %s\n", strerror(errno));
		exit(0);
	}

	// check transaction
	if (memcmp(reply, q->query, 2) != 0) {
		printf("response does not match any query\n");
		exit(0);
	}

	rcode = reply[3] & 0x0f;

	debug_print(PRINT_DEBUG, "response matches %s (rcode: %s)\n", q->name, rcodes[rcode]);

	if (rcode != 0) {
		printf("** server can't find %s: %s\n", q->name, rcodes[rcode]);
	} else {
		if (parse_reply(reply, len) < 0)
			printf("*** Can't find %s: Parse error\n", q->name);
	}

	return 0;
}

static int xinet_aton(const char *cp, struct in_addr *inp)
{
	if (!inet_aton(cp, inp)) {
		printf("inet_aton: invalid ip %s\n", cp);
		exit(0);
	}

	return 0;
}

static int convert_ips(char *param, __be32 ips[])
{
	struct in_addr in;
	__be32 start, end;
	__u32 addr;
	int i = 0;
	char ip_string[128];
	char *p = ip_string, *tmp;

	strcpy(ip_string, param);

	if (!strchr(ip_string, ',')) {
		goto dash;
	}

	while ((tmp = strsep(&p, ",")) != NULL) {
		xinet_aton(tmp, &in);
		ips[i++] = in.s_addr;
	}

	return 0;
dash:
	p = strchr(ip_string, '-');
	if (p) {
		*p = '\0';
	}

	xinet_aton(ip_string, &in);
	start = in.s_addr;

	if (p) {
		xinet_aton(++p, &in);
		end = in.s_addr;
	} else {
		end = start;
	}

	if (ntohl(start) > ntohl(end) || (ntohl(end) - ntohl(start) >= 255)) {
		printf("invalid ip range: %s\n", param);
		return -1;
	}

	for (addr = ntohl(start); addr <= ntohl(end); addr++) {
		ips[i++] = htonl(addr);
	}

	return 0;
}

int main (int argc, char **argv)
{
	int opt, fd, len;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
	};
	__u16 sport, sport_beginning = 10000;
	char *domain = "t0.test.com";
	__be32 src_ips[256] = {0};
	__be32 dst_ips[256] = {0};
	int i, j, total_count = 0, loop = 0, count_per_domain = 1;

	while ((opt = getopt(argc, argv, "S:D:s:H:c:C:dh")) != -1) {
		switch (opt) {
		case 'S':
			if (convert_ips(optarg, src_ips) < 0)
				goto help;
			break;
		case 'D':
			if (convert_ips(optarg, dst_ips) < 0)
				goto help;
			break;
		case 's': {
			int tmp;

			tmp = atoi(optarg);
			if (tmp <= 0 || tmp > 65535) {
				printf("invalid param: %s\n", optarg);
				help(argv[0]);
			}
			sport_beginning = tmp;
			break;
		}
		case 'H':
			domain = optarg;
			break;
		case 'c':
			total_count = atoi(optarg);
			if (total_count <= 0) {
				printf("invalid param: %s\n", optarg);
				help(argv[0]);
			}
			break;
		case 'C':
			count_per_domain = atoi(optarg);
			if (count_per_domain <= 0) {
				printf("invalid param: %s\n", optarg);
				help(argv[0]);
			}
			break;
		case 'd':
			debug_level++;
			break;
		case 'h':
help:
		default:
			help(argv[0]);
			break;
		}
	}

	if (!src_ips[0]) {
		convert_ips("10.10.1.100,10.10.1.101", src_ips);
	}

	if (!dst_ips[0]) {
		convert_ips("10.10.2.53,10.10.2.153", dst_ips);
	}

	if (signal(SIGINT, sig_handler) || signal(SIGTERM, sig_handler)) {
		perror("signal");
		exit(0);
	}

	i = 0;

	debug_print(PRINT_NOTICE, "prepare to dns test: " NIPQUAD_FMT " => " NIPQUAD_FMT "\n", NIPQUAD(src_ips[0]), NIPQUAD(dst_ips[0]));
	debug_print(PRINT_NOTICE, "=====================================\n");

	while (1) {
		__be32 saddr, daddr;

		daddr = dst_ips[i++];
		if (!daddr)
			break;
		
		j = 0;

		while (1) {
			saddr = src_ips[j++];
			if (!saddr)
				break;

			sport = sport_beginning;

			while (1) {
				struct query *q;
				int k = 0;

				fd = xsocket(AF_INET, SOCK_DGRAM, 0);

				if (!sport) {
					break;
				}

				addr.sin_addr.s_addr = saddr;
				addr.sin_port = htons(sport++);
				xbind(fd, (struct sockaddr *)&addr, sizeof(addr));

				addr.sin_port = htons(53);
				addr.sin_addr.s_addr = daddr;
				xconnect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

				debug_print(PRINT_NOTICE, NIPQUAD_FMT ":%u" " => " NIPQUAD_FMT ":%u\n",
						NIPQUAD(saddr), sport == 0 ? 65535 : sport - 1,
						NIPQUAD(daddr), 53);

				q = add_query(T_A, domain);

				while (k++ < count_per_domain)
					send_query(fd, q);

				close(fd);

				if (total_count && ++loop >= total_count)
					break;
			}
		}
	}

	return 0;
}
