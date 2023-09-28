#include "../hdrs/result.h"

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

static void			serv_name(uint16_t port, char *s_buff) {
	struct servent	*servent;

	if ((servent = getservbyport(htons(port), NULL)))
		sprintf(s_buff, "%s/%s", servent->s_name, servent->s_proto);
	else
		sprintf(s_buff, "Unassigned");
}

static int			results_str(uint64_t scan_i, result_t res, char *r_buff) {
	char	eol[32] = { 0 }, cat_buf[BUFF_SZ] = { 0 };

	strcat(r_buff, SCAN_NAMES[OPTS.scans[scan_i]]);
	if (scan_i + 1 < OPTS.scan_nb)
		sprintf(eol, "%-31s", "\n");
	else
		sprintf(eol, "%s", "");
	switch (res) {
		case R_NONE:
			switch(OPTS.scans[scan_i]) {
				case ST_SYN:
					sprintf(cat_buf, "(Filtered)%s", eol);
					break;
				case ST_ACK:
					sprintf(cat_buf, "(Open|Close)%s", eol);
					break;
				default:
					sprintf(cat_buf, "(Open|Filtered)%s", eol);
					break;
			}
			break;
		case R_OPEN:
			sprintf(cat_buf, "(Open)%s", eol);
			break;
		case R_CLOSE:
			sprintf(cat_buf, "(Closed)%s", eol);
			break;
		case R_FILTERED:
			sprintf(cat_buf, "(Filtered)%s", eol);
			break;
		case R_UNFILTERED:
			sprintf(cat_buf, "(Unfiltered)%s", eol);
			break;
		case R_OPEN_CLOSE:
			sprintf(cat_buf, "(Open|Close)%s", eol);
			break;
		case R_OPEN_FILTERED:
			sprintf(cat_buf, "(Open|Filtered)%s", eol);
			break;
	}
	strcat(r_buff, cat_buf);
	return (0);
}

void				result_print(void) {
	uint64_t		ip_i, scan_i;
	int64_t			port_i;
	char			s_buff[BUFF_SZ] = { 0 }, r_buff[BUFF_SZ] = { 0 };
	uint8_t			is_open;

	for (ip_i = 0; ip_i < OPTS.ip_nb; ++ip_i) {
		printf("\n++++++++++++++++++++++++++++"
				"++++++++++++++++++++++++++++\n");
		printf("\nIP address: %s\n", inet_ntoa(*(struct in_addr *)&OPTS.ips[ip_i]));
		printf("Open ports:\n");
		printf("%-10s%-20s%s\n", "Port", "Service Name", "Results");
		printf("---------------------------"
				"--------------------------\n");
		for (port_i = OPTS.port_nb - 1; port_i >= 0; --port_i) {
			bzero(r_buff, BUFF_SZ);
			is_open = 0;
			for (scan_i = 0; scan_i < OPTS.scan_nb; ++scan_i) {
				results_str(scan_i, RESULTS[ip_i][port_i][scan_i], r_buff);	
				if (RESULTS[ip_i][port_i][scan_i] == R_OPEN)
					is_open = 1;
			}
			if (is_open) {
				bzero(s_buff, BUFF_SZ);
				serv_name(OPTS.ports[port_i], s_buff);
				printf("%-10d%-20s%s\n",
					OPTS.ports[port_i],
					s_buff,
					r_buff);
			}
		}
		printf("\nClosed/Filtered/Unfiltered ports\n");
		printf("%-10s%-20s%s\n", "Port", "Service Name", "Results");
		printf("---------------------------"
				"--------------------------\n");
		bzero(s_buff, BUFF_SZ);
		for (port_i = OPTS.port_nb - 1; port_i >= 0; --port_i) {
			bzero(r_buff, BUFF_SZ);
			is_open = 0;
			for (scan_i = 0; scan_i < OPTS.scan_nb; ++scan_i) {
				results_str(scan_i, RESULTS[ip_i][port_i][scan_i], r_buff);	
				if (RESULTS[ip_i][port_i][scan_i] == R_OPEN)
					is_open = 1;
			}
			if (!is_open) {
				bzero(s_buff, BUFF_SZ);
				serv_name(OPTS.ports[port_i], s_buff);
				printf("%-10d%-20s%s\n",
					OPTS.ports[port_i],
					s_buff,
					r_buff);
			}
		}
	}
}
