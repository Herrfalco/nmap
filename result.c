#include "result.h"

results_t	RESULTS = { 0 };

static int64_t		ip_idx(in_addr_t ip) {
	int64_t		i;

	for (i = 0; i < MAX_IPS; ++i)
		if (ip == OPTS.ips[i])
			return (i);
	return (-1);
}

static int64_t		port_idx(uint16_t port) {
	int64_t		i;

	for (i = 0; i < MAX_PORTS; ++i)
		if (ntohs(port) == OPTS.ports[i])
			return (i);
	return (-1);
}

static int64_t		scan_idx(uint16_t raw_port) {
	switch (port_2_scan(ntohs(raw_port))) {
		case ST_SYN:
			return (0);
		case ST_NULL:
			return (1);
		case ST_ACK:
			return (2);
		case ST_FIN:
			return (3);
		case ST_XMAS:
			return (4);
		case ST_UDP:
			return (5);
		default:
			return (-1);
	}
}

void				result_set(packet_t *pkt, result_t res) {
	int64_t		ip_i, port_i, scan_i;
	in_addr_t	ip;
	genh_t		*genh;

	ip = pkt->iph->saddr;
	genh = pkt->iph->protocol == IPPROTO_ICMP
		? (genh_t *)(pkt->icmph + 1)
		: (genh_t *)(pkt->iph + 1);
	if ((ip_i = ip_idx(ip)) < 0
			|| (port_i = port_idx(genh->source)) < 0
			|| (scan_i = scan_idx(genh->dest)) < 0)
		return ;
	if (!RESULTS[ip_i][port_i][scan_i])
		RESULTS[ip_i][port_i][scan_i] = res;
}

void				result_print(void) {
	uint64_t		ip_i, scan_i;
	int64_t			port_i;

	for (ip_i = 0; ip_i < OPTS.ip_nb; ++ip_i) {
		printf("IP address: %s\n", inet_ntoa(*(struct in_addr *)&OPTS.ips[ip_i]));
		for (port_i = OPTS.port_nb - 1; port_i >= 0; --port_i) {
			for (scan_i = 0; scan_i < OPTS.scan_nb; ++scan_i) {
				if (RESULTS[ip_i][port_i][scan_i] == R_OPEN)
					printf("%s %d: Open\n",
						SCAN_NAMES[scan_i],
						OPTS.ports[port_i]);
				else if (RESULTS[ip_i][port_i][scan_i] == R_CLOSE)
					printf("%s %d: Closed\n",
						SCAN_NAMES[scan_i],
						OPTS.ports[port_i]);
			}
		}
	}
}
