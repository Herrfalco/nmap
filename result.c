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
	switch (ntohs(raw_port) - LOCAL.addr.sin_port) {
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
	int64_t			ip_i, port_i, scan_i, scan_nb = bit_set(OPTS.scan);
	struct servent	*servent;

	for (ip_i = 0; ip_i < (int64_t)OPTS.ip_nb; ++ip_i) {
		printf("IP address: %s\n", inet_ntoa(*(struct in_addr *)&OPTS.ips[ip_i]));
		printf("Open ports:\n");
		printf("%-20s%-20s%-20s%-30s\n", "Port", "Service Name",
			"Results", "Conclusion");
		printf("---------------------------------------------------------------------------------\n");
		for (port_i = OPTS.port_nb - 1; port_i >= 0; --port_i) {
			servent = getservbyport(OPTS.ports[port_i], NULL);
			if (servent)
				printf("test: %d: %s\n", OPTS.ports[port_i], servent->s_name);
			for (scan_i = 0; scan_i < scan_nb; ++scan_i) {
				if (RESULTS[ip_i][port_i][scan_i] == R_OPEN)
					printf("%-20d%-20s%-20s%-30s\n",
						OPTS.ports[port_i],
						!servent ? "Unassigned" : servent->s_name,
						"SCAN_NAME(Open)",
						"Open");;
			}
		}
	}
}
