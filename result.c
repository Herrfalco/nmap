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

result_t	*result_ptr(in_addr_t ip, uint16_t targ_port, uint16_t local_port) {
	int64_t	ip_i, port_i, scan_i;

	if ((ip_i = ip_idx(ip)) < 0
			|| (port_i = port_idx(targ_port)) < 0
			|| (scan_i = scan_idx(local_port)) < 0)
		return (NULL);
	return (&RESULTS[ip_i][port_i][scan_i]);
}
