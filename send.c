/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   send.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/11 10:02:10 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/11 20:48:53 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "parse.h"

int		init(data_t *data, opts_t *opts) {
	if (sock_init()) 
		return (1);
	if (local_init(data))
		return (2);
	data->iph = (struct iphdr *)data->pkt;
	data->tcph = (struct tcphdr *)(data->iph + 1);
	for (i = 0; i < opts->ip_nb; ++i) {
		for (j = 0; j < opts->port_nb; ++j) {
			data->remote[i][j].sin_family = AF_INET;
			data->remote[i][j].sin_addr.s_addr = opts->ips[i];
			data->remote[i][j].sin_port = htons(opts->ports[j]);
		}
	}
	return (0);
}

void	fill_headers(data_t *data, opts_t *opts, uint64_t i, uint64_t j) {
	uint8_t		scan;
	int			y;

	for (y = 0; y < SCANS_NB; ++y)
		if ((scan = ((opts->scan >> y) & 1))) {
			if (scan != S_UDP)
				fill_tcp_headers(data, i, j, scan);
//			else
//				fill_udp_headers();
		}
}

void				get_thrd_rng(thrd_rng_t *rng, uint64_t ) {
	uint64_t		tot, div, rem, raw_i;

	tot = OPTS.ip_nb * OPTS.port_nb;
	div = tot / OPTS.speedup;
	rem = tot % OPTS.speedup;
	raw_i = (div * idx) + (idx < rem ? idx : rem);
	rng->ips = &OPTS.ips[raw_i / OPTS.port_nb];
//	rng->ip_nb = 
	rng->ports = &OPTS.ports[raw_i / OPTS.ip_nb];
//	rng->port_nb = 
}
