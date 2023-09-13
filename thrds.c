/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thrds.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/11 20:26:04 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/13 13:28:09 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "thrds.h"

int					SEND_SOCK = 0;
results_t			RESULTS = { 0 };
pthread_mutex_t		PRINT = PTHREAD_MUTEX_INITIALIZER;
thrds_arg_t			THRDS[MAX_THRDS] = { 0 };

static void			thrds_print_wrapper(thrds_arg_t *args, print_fn_t fn, void *arg) {
	pthread_mutex_lock(&PRINT);
	printf("%u > ", args->id);
	fn(arg);
	printf("\n");
	pthread_mutex_unlock(&PRINT);
}

char				*thrds_init(void) {
	int			one = 1;

	if ((SEND_SOCK = socket(AF_INET, SOCK_RAW, ETH_P_ALL)) < 0
			|| setsockopt(SEND_SOCK, IPPROTO_IP, IP_HDRINCL,
				&one, sizeof(one)))
		return (strerror(errno));
	return (NULL);
}

static char			*thrds_send(thrds_arg_t *args) {
	uint8_t					data[BUFF_SZ];
	packet_t				packet;
	struct sockaddr_in		dst = { .sin_family = AF_INET };
	scan_t					scan;
	uint64_t				i = args->job.idx / OPTS.port_nb,
							j = args->job.idx % OPTS.port_nb,
							max = args->job.idx + args->job.nb;

	packet_init(&packet, data, 0);
	for (; (i * OPTS.port_nb + j) < max; ++i, j = 0) {
		for (; j < OPTS.port_nb && (i * OPTS.port_nb + j) < max; ++j) {
			dst.sin_addr.s_addr = OPTS.ips[i];
			dst.sin_port = htons(OPTS.ports[j]);
			for (scan = ST_SYN; scan < ST_MAX; scan <<= 1) {
				if (OPTS.scan & scan) {
					packet_fill(&packet, &dst, scan);
//					thrds_print_wrapper(args, (print_fn_t)packet_print, &packet);
					if (sendto(SEND_SOCK, data, packet.sz, 0,
								(struct sockaddr *)&dst,
								sizeof(struct sockaddr_in)) < 0)
						return (strerror(errno));
				}
			}
		}
	}
	return (NULL);
}

static void			thrds_recv(thrds_arg_t *args, const struct pcap_pkthdr *pkt_hdr, const uint8_t *pkt) {
	(void)pkt_hdr;
	thrds_print_wrapper(args, (print_fn_t)packet_print, ((struct ether_header *)pkt) + 1);
}

static int64_t		thrds_run(thrds_arg_t *args) {
	filt_t				filt;
	pcap_t				*cap;
	struct bpf_program	fp;

	if (!(cap = pcap_open_live(LOCAL.dev_name,
		PCAP_SNAPLEN_MAX, 0, PCAP_TIME_OUT, args->err_buff)))
		return (-1);
	if ((args->err_ptr = filter_init(&filt, &args->job)))
		return (-1);
//	thrds_print_wrapper(args, (print_fn_t )filter_print, &filt);
	if (pcap_compile(cap, &fp, filt.data, 1,
				PCAP_NETMASK_UNKNOWN) == PCAP_ERROR
			|| pcap_setfilter(cap, &fp) == PCAP_ERROR) {
		args->err_ptr = pcap_geterr(cap);
		return (-1);
	}
	
	if ((args->err_ptr = thrds_send(args)))
		return (-1);
	//LOOP NEEDED ?
	for (;;) {
		if (pcap_dispatch(cap, 0, (pcap_handler)thrds_recv, (void *)args)
				== PCAP_ERROR) {
			args->err_ptr = pcap_geterr(cap);
			return (-1);
		}
	}
	return (0);
}

char				*thrds_spawn(void) {
	uint64_t		i,
					tot = OPTS.port_nb * OPTS.ip_nb,
					div = tot / OPTS.speedup,
					rem = tot % OPTS.speedup;

	for (i = 1; i < OPTS.speedup; ++i) {
		THRDS[i].job.nb = div + (i < rem);
		THRDS[i].job.idx = i * div + (i < rem ? i : rem);
		THRDS[i].id = i;
		printf("%lu: idx: %lu nb: %lu\n", i, THRDS[i].job.idx, THRDS[i].job.nb);
		if (pthread_create(&THRDS[i].thrd, NULL,
				(void *)thrds_run, &THRDS[i]))
			return (THRDS[i].err_ptr ?
					THRDS[i].err_ptr : THRDS[i].err_buff);
	}
	return (NULL);
}
