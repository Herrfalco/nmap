#include "../hdrs/result.h"

static results_t	RESULTS = { 0 };
static uint64_t		COUNT = 0;
static char			*RESULT_STR[] = {
	NULL, "(Open)", "(Close)", "(Filtered)", "(Unfiltered)", "(Open|Filtered)",
};
pthread_mutex_t		SETMUT = PTHREAD_MUTEX_INITIALIZER;

void				result_init(void) {
	COUNT = OPTS.ip_nb * OPTS.port_nb * OPTS.scan_nb;
}

uint64_t			result_complete(void) {
	return (!COUNT);
}

void				result_set(packet_t *pkt, result_t res) {
	uint64_t	ip_i, port_i, scan_i;

	for (ip_i = 0; ip_i < OPTS.ip_nb; ++ip_i)
		if (OPTS.ips[ip_i] == pkt->iph->saddr)
			break;
	for (port_i = 0; port_i < OPTS.port_nb; ++port_i)
		if (ntohs(((genh_t *)pkt->proth)->source) == OPTS.ports[port_i])
			break;
	scan_i = ntohs(((genh_t *)pkt->proth)->dest) - SRC_PORT;
	pthread_mutex_lock(&SETMUT);
	if (!RESULTS[ip_i][port_i][scan_i]) {
		RESULTS[ip_i][port_i][scan_i] = res;
		if (!--COUNT)
			sig_stop(0);
	}
	pthread_mutex_unlock(&SETMUT);
}

static void			serv_name(uint16_t port, char *s_buff) {
	struct servent	*servent;

	if ((servent = getservbyport(htons(port), "tcp")))
		sprintf(s_buff, "%s", servent->s_name);
	else
		sprintf(s_buff, "unknown");
}

static void			results_str(uint64_t scan_i, result_t res, char *r_buff) {
	char	buff[BUFF_SZ] = { 0 };

	if (scan_i)
		str_cat(r_buff, char_line(' ', LINE_SZ / 3 * 2 + 2));
	sprintf(buff, "%-5s", SCAN_NAMES[OPTS.scans[scan_i]]);
	str_cat(r_buff, buff);
	if (res)
		str_cat(r_buff, RESULT_STR[res]);
	else {
		switch(OPTS.scans[scan_i]) {
			case ST_SYN:
				__attribute__((fallthrough));
			case ST_ACK:
				str_cat(r_buff, RESULT_STR[R_FILTERED]);
				break;
			default:
				str_cat(r_buff, RESULT_STR[R_OPEN_FILTERED]);
				break;
		}
	}
	str_cat(r_buff, "\n");
}

void				result_print(void) {
	uint64_t		ip_i, scan_i, port_i;
	char			r_buff[BUFF_SZ] = { 0 }, buff[BUFF_SZ] = { 0 };
	uint8_t			is_open, is_close;
	uint8_t			addr_disp;

	for (ip_i = 0; ip_i < OPTS.ip_nb; ++ip_i) {
		addr_disp = 0;
		for (port_i = 0; port_i < OPTS.port_nb; ++port_i) {
			bzero(r_buff, BUFF_SZ);
			for (is_open = 0, is_close = 0, scan_i = 0; scan_i < OPTS.scan_nb; ++scan_i) {
				results_str(scan_i, RESULTS[ip_i][port_i][scan_i], r_buff);	
				switch (RESULTS[ip_i][port_i][scan_i]) {
					case R_OPEN:
						is_open = 1;
						break;
					case R_CLOSE:
						is_close = 1;
						break;
					default:
						break;
				}
			}
			if ((((OPTS.flag & F_OPEN)
				|| !(OPTS.flag & (F_OPEN | F_CLOSE | F_OTHER))) && is_open)
				|| ((OPTS.flag & F_CLOSE) && is_close)
				|| ((OPTS.flag & F_OTHER) && !(is_close || is_open))) {
				if (!addr_disp) {
					addr_disp = 1;
					sprintf(buff, "IP address: %s", inet_ntoa(*(struct in_addr *)&OPTS.ips[ip_i]));
					printf("\n\n%s\n", centered(buff, LINE_SZ));
					printf("%s\n", char_line('-', LINE_SZ));
					printf("%s", centered("Port", LINE_SZ / 3));
					printf("|%s|", centered("Service Name", LINE_SZ / 3));
					printf("%s\n", centered("Result", LINE_SZ / 3));
					printf("%s\n", char_line('-', LINE_SZ));
				}
				serv_name(OPTS.ports[port_i], buff);
				printf("%-*d %-*s %s", LINE_SZ / 3, OPTS.ports[port_i],
					LINE_SZ / 3, buff,
					r_buff);
			}
		}
		if (addr_disp)
			printf("%s\n", char_line('-', LINE_SZ));
	}
}
