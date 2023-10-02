/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   filter.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/09 16:37:22 by fcadet            #+#    #+#             */
/*   Updated: 2023/10/02 19:13:57 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../hdrs/filter.h"

char			*filter_init(void) {
	static char	filt[32 * (MAX_IPS + MAX_PORTS + SCANS_NB)] = { 0 };
	char		buff[BUFF_SZ];
	uint64_t	i, start, range = 0;

	str_cat(filt, "(");
	for (i = 0; i < OPTS.ip_nb; ++i) {
		sprintf(buff, "src host %s%s",
			inet_ntoa(*(struct in_addr *)&OPTS.ips[i]),
			i + 1 == OPTS.ip_nb ? ") and (((" : " or ");
		str_cat(filt, buff);
	}
	for (i = 0; i < OPTS.port_nb; ++i) {
		if (i + 1 >= OPTS.port_nb
			|| OPTS.ports[i + 1] - OPTS.ports[i] > 1) {
			if (range)
				sprintf(buff, "src portrange %lu-%u%s",
					start, OPTS.ports[i],
					i + 1 == OPTS.port_nb ? ") and (" : " or ");
			else
				sprintf(buff, "src port %d%s", OPTS.ports[i],
					i + 1 == OPTS.port_nb ? ") and (" : " or ");
			str_cat(filt, buff);
			range = 0;
		} else if (!range) {
			start = OPTS.ports[i];
			range = 1;
		}
	}
	if (OPTS.scan_nb > 1)
		sprintf(buff, "dst portrange %u-%lu",
			SRC_PORT, SRC_PORT + OPTS.scan_nb - 1);
	else
		sprintf(buff, "dst port %u", SRC_PORT);
	str_cat(filt, buff);
	str_cat(filt, ") and (tcp or udp)) or icmp)");
	return (filt);
}

void			filter_print(char *filt) {
	printf("%s\n", filt);
}

void			filter_bpf_free(struct bpf_program *bpf) {
	if (bpf->bf_insns) {
		free(bpf->bf_insns);
		bpf->bf_insns = NULL;
	}
}
