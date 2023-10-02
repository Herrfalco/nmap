/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thrds.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/11 20:26:04 by fcadet            #+#    #+#             */
/*   Updated: 2023/10/01 21:47:52 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../hdrs/signal.h"

int					SEND_SOCK = 0;
pthread_mutex_t		PRINT = PTHREAD_MUTEX_INITIALIZER;
thrds_arg_t			THRDS[MAX_THRDS] = { 0 };

static void			thrds_recv(thrds_arg_t *args, const struct pcap_pkthdr *pkt_hdr,
		const uint8_t *pkt);

static void			thrds_print_wrapper(thrds_arg_t *args, thrds_print_fn fn, void *arg) {
	pthread_mutex_lock(&PRINT);
	printf("%u > ", args->id);
	fn(arg);
	pthread_mutex_unlock(&PRINT);
}

static void			print_error(char *err) {
	print_main_error(err, 0);
}

char				*thrds_init(void) {
	int			one = 1;

	if ((SEND_SOCK = socket(AF_INET, SOCK_RAW, ETH_P_ALL)) < 0
			|| setsockopt(SEND_SOCK, IPPROTO_IP, IP_HDRINCL,
				&one, sizeof(one)))
		return (strerror(errno));
	return (NULL);
}

void				thrds_fini(void) {
	close(SEND_SOCK);
}

static void		thrds_clean(thrds_arg_t *args) {
	filter_bpf_free(&args->bpf);
	pcap_close(args->cap);
}

static char		*recv_loop(uint64_t ms, thrds_arg_t *args) {
	struct timeval	tv_start, tv_cur;

	if (gettimeofday(&tv_start, NULL))
		return ("Can't get current time");
	for (tv_cur = tv_start; !is_elapsed(&tv_start, &tv_cur, ms);) {
		if (sig_catch()) {
			thrds_clean(args);
			pthread_exit(NULL);
		}
		if (pcap_dispatch(args->cap, 0, (pcap_handler)thrds_recv, (void *)args)
				== PCAP_ERROR) {
			args->err_ptr = pcap_geterr(args->cap);
			return ("Can't call dispatch function");
		}
		if (gettimeofday(&tv_cur, NULL))
			return ("Can't get current time");
	} 
	return (NULL);
}

static char			*thrds_send(thrds_arg_t *args) {
	uint8_t					data[BUFF_SZ] = { 0 };
	packet_t				packet;
	struct sockaddr_in		dst = { .sin_family = AF_INET };
	uint64_t				s, p, a, i, max;
	char					*err;

	packet_init(&packet, data, BUFF_SZ);
	for (i = args->job.idx, max = i + args->job.nb; i < max; ++i) {
		p = i % OPTS.port_nb;
		a = i / OPTS.port_nb;
		dst.sin_addr.s_addr = OPTS.ips[a];
		dst.sin_port = htons(OPTS.ports[p]);
		for (s = 0; s < OPTS.scan_nb; ++s) {
			packet_fill(&packet, &dst, OPTS.scans[s]);
//			thrds_print_wrapper(args, (thrds_print_fn)packet_print, &packet);
			if (sendto(SEND_SOCK, data, packet.sz, 0,
						(struct sockaddr *)&dst,
						sizeof(struct sockaddr_in)) < 0)
				return (strerror(errno));
			if ((err = recv_loop(OPTS.tempo, args)))
				return (err);
		}
	}
	return (NULL);
}

static void			thrds_recv(thrds_arg_t *args, const struct pcap_pkthdr *pkt_hdr, const uint8_t *pkt) {
	packet_t			packet;
	struct ether_header	*ethh = (struct ether_header *)pkt;
	genh_t				*genh;
	scan_t				scan;

	if (ntohs(ethh->ether_type) == ETHERTYPE_IP
			&& pkt_hdr->len == pkt_hdr->caplen
			&& pkt_hdr->len >= ETHH_SZ + IPH_SZ) {
		packet_init(&packet, (void *)((struct ether_header *)pkt + 1),
				pkt_hdr->len - sizeof(struct ether_header));
		switch(packet.iph->protocol) {
			case IPPROTO_TCP:
				if (pkt_hdr->len < ETHH_SZ + IPH_SZ + TCPH_SZ)
					return ;
				switch (port_2_scan(ntohs(packet.tcph->dest))) {
					case ST_SYN:
						if (packet.tcph->rst)
							result_set(&packet, R_CLOSE);
						else if (packet.tcph->ack || packet.tcph->syn)
							result_set(&packet, R_OPEN);
						break;
					case ST_NULL:
						__attribute__((fallthrough));
					case ST_FIN:
						__attribute__((fallthrough));
					case ST_XMAS:
						if (packet.tcph->rst)
							result_set(&packet, R_CLOSE);
						break;
					case ST_ACK:
						if (packet.tcph->rst)
							result_set(&packet, R_UNFILTERED);
						break;
					default:
						break;
				}
				break ;
			case IPPROTO_UDP:
				if (pkt_hdr->len < ETHH_SZ + IPH_SZ + UDPH_SZ)
					return ;
				if (port_2_scan(ntohs(packet.udph->dest)) == ST_UDP)
					result_set(&packet, R_OPEN);
				break ;
			case IPPROTO_ICMP:
				if (pkt_hdr->len < ETHH_SZ + IPH_SZ
						+ ICMPH_SZ + HDR_PORTS_SZ
						|| packet.icmph->type != 3
						|| !((packet.icmph->code >= 1
								&& packet.icmph->code <= 3)
							|| packet.icmph->code == 9
							|| packet.icmph->code == 10
							|| packet.icmph->code == 13))
					return ;
				genh = (genh_t *)(packet.icmph + 1);
				scan = port_2_scan(ntohs(genh->dest));
				result_set(&packet,
					(scan == ST_UDP && packet.icmph->code == 3)
					? R_CLOSE : R_FILTERED);
			default:
				break ;
		}
//		thrds_print_wrapper(args, (thrds_print_fn)packet_print, &packet);
	} else
		thrds_print_wrapper(args, (thrds_print_fn)print_error,
			"Corrupted packet received");
}

static void		thrds_run(thrds_arg_t *args) {
	if (!(args->cap = pcap_open_live(LOCAL.dev_name,
		PCAP_SNAPLEN_MAX, 0, PCAP_TIME_OUT, args->err_buff)))
		return (thrds_clean(args));
	thrds_print_wrapper(args, (thrds_print_fn)filter_print, args->filt);
	if (pcap_compile(args->cap, &args->bpf, args->filt, 1,
				PCAP_NETMASK_UNKNOWN) == PCAP_ERROR
			|| pcap_setfilter(args->cap, &args->bpf) == PCAP_ERROR) {
		args->err_ptr = pcap_geterr(args->cap);
		return (thrds_clean(args));
	}
	filter_bpf_free(&args->bpf);
	if ((args->err_ptr = thrds_send(args)))
		return (thrds_clean(args));
	args->err_ptr = recv_loop(OPTS.timeout, args);
	return (thrds_clean(args));
}

void				thrds_single(void) {
	THRDS->job.nb = OPTS.port_nb * OPTS.ip_nb;
	THRDS->filt = filter_init();
	thrds_run(THRDS);
}

char				*thrds_spawn(void) {
	uint64_t		tot = OPTS.port_nb * OPTS.ip_nb,
					div = tot / OPTS.speedup,
					rem = tot % OPTS.speedup, i;
	char			*filt = filter_init();

	for (i = 0; i < OPTS.speedup; ++i) {
		if (!(THRDS[i].job.nb = div + (i < rem)))
			break ;
		THRDS[i].job.idx = i * div + (i < rem ? i : rem);
		THRDS[i].id = i;
		THRDS[i].filt = filt;
		if (pthread_create(&THRDS[i].thrd, NULL,
				(void *)thrds_run, &THRDS[i])) {
			sig_stop();
			OPTS.speedup = i;
			return ("Can't spawn every speedup threads");
		}
	}
	return (NULL);
}
