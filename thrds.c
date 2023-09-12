/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thrds.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/11 20:26:04 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/12 09:49:43 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "thrds.h"

int			SEND_SOCK = 0;
results_t	RESULTS = { 0 };

char		*thrds_init(void) {
	int			one = 1;

	if ((SEND_SOCK = socket(AF_INET, SOCK_RAW, ETH_P_ALL)) < 0
			|| setsockopt(SEND_SOCK, IPPROTO_IP, IP_HDRINCL,
				&one, sizeof(one)))
		return (strerror(errno));
}

int64_t		thrds_run(thrds_arg_t *args) {
	filt_t				filt;
	pcap_t				*cap;
	char				*err;
	struct bpf_program	fp;

	if (!(cap = pcap_open_live(LOCAL.dev_name,
		PCAP_SNAPLEN_MAX, 0, PCAP_TIME_OUT, args->err)))
		return (-1);
	if ((err = filter_init(&filt, &args->job))) {
		strncpy(args->err, err, BUFF_SZ);
		return (-1);
	}
	if (pcap_compile(cap, &fp, filt.data, 1,
				PCAP_NETMASK_UNKNOWN)) {
		
	}

}

char	*thrds_send(job_t *job) {
	uint8_t					data[BUFF_SZ], stop;
	packet_t				packet;
	struct sockaddr_in		dst = { .sin_family = AF_INET };
	scan_t					scan;
	uint64_t				i = job->idx / OPTS.port_nb,
							j = job->idx % OPTS.port_nb;

	packet_init(&packet, data, 0);
	for (stop = 0; !stop; ++i, j = 0) {
		for (; j < OPTS.port_nb; ++j) {
			if ((i * OPTS.port_nb + j) >= job->idx + job->nb) {
				stop = 1;
				break;
			}
			dst.sin_addr.s_addr = OPTS.ips[i];
			dst.sin_port = OPTS.ports[j];
			for (scan = ST_SYN; scan < ST_MAX; scan <<= 1) {
				if (OPTS.scan & scan) {
					packet_fill(&packet, &dst, scan);
//					packet_print(&packet);
					if (sendto(SEND_SOCK, data, packet.sz, 0,
								(struct sockaddr *)&dst,
								sizeof(struct sockaddr_in)) < 0)
						return (strerror(errno));
				}
			}
		}
	}
	return (0);
}
