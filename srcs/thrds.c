/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thrds.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/11 20:26:04 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/28 09:31:22 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../hdrs/signal.h"

int					SEND_SOCK = 0;
pthread_mutex_t		PRINT = PTHREAD_MUTEX_INITIALIZER;
thrds_arg_t			THRDS[MAX_THRDS] = { 0 };

static void			thrds_recv(thrds_arg_t *args, const struct pcap_pkthdr *pkt_hdr, const uint8_t *pkt);

static void			thrds_print_wrapper(thrds_arg_t *args, print_fn_t fn, void *arg) {
	pthread_mutex_lock(&PRINT);
	printf("%u > ", args->id);
	fn(arg);
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

static int			recv_loop(uint64_t ms, thrds_arg_t *args) {
	struct timeval	tv_start, tv_cur;

	if (gettimeofday(&tv_start, NULL))
		return (-1);
	for (tv_cur = tv_start; !is_elapsed(&tv_start, &tv_cur, ms)
			&& !SIG_CATCH;) {
		if (pcap_dispatch(args->cap, 0, (pcap_handler)thrds_recv, (void *)args)
				== PCAP_ERROR) {
			args->err_ptr = pcap_geterr(args->cap);
			return (-1);
		}
		if (gettimeofday(&tv_cur, NULL))
			return (-1);
	} 
	return (0);
}

static char			*thrds_send(thrds_arg_t *args) {
	uint8_t					data[BUFF_SZ] = { 0 };
	packet_t				packet;
	struct sockaddr_in		dst = { .sin_family = AF_INET };
	uint64_t				s, p, a, i, max;

	packet_init(&packet, data, BUFF_SZ);
	for (i = args->job.idx, max = i + args->job.nb; i < max; ++i) {
		p = i % OPTS.port_nb;
		a = i / OPTS.port_nb;
		dst.sin_addr.s_addr = OPTS.ips[a];
		dst.sin_port = htons(OPTS.ports[p]);
		for (s = 0; s < OPTS.scan_nb; ++s) {
			packet_fill(&packet, &dst, OPTS.scans[s]);
//			thrds_print_wrapper(args, (print_fn_t)packet_print, &packet);
			if (sendto(SEND_SOCK, data, packet.sz, 0,
						(struct sockaddr *)&dst,
						sizeof(struct sockaddr_in)) < 0)
				return (strerror(errno));
			if (recv_loop(OPTS.tempo, args))
				return ("Can't get time");
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
		packet_init(&packet, (void *)((struct ether_header *)pkt + 1), pkt_hdr->len - sizeof(struct ether_header));
		switch(packet.iph->protocol) {
			case IPPROTO_TCP:
				if (pkt_hdr->len < ETHH_SZ + IPH_SZ + TCPH_SZ)
					return ;
				switch (port_2_scan(ntohs(packet.tcph->dest))) {
					case ST_SYN:
						if (packet.tcph->rst)
							result_set(&packet, R_CLOSE);
						else if (packet.tcph->ack)
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
				if (scan == ST_UDP) {
					if (packet.icmph->code == 3)
						result_set(&packet, R_CLOSE);
					else
						result_set(&packet, R_FILTERED);
				} else if (scan == ST_ACK)
					result_set(&packet, R_OPEN_CLOSE);
				else
					result_set(&packet, R_FILTERED);
			default:
				break ;
		}
//		thrds_print_wrapper(args, (print_fn_t)packet_print, &packet);
	} else
		thrds_print_wrapper(args, (print_fn_t)print_error,
			"Recv Error: No IP type packet or Trunked packet");
}

static int64_t		thrds_run(thrds_arg_t *args) {
	if (handle_sig())
		return (-1);
	if (!(args->cap = pcap_open_live(LOCAL.dev_name,
		PCAP_SNAPLEN_MAX, 0, PCAP_TIME_OUT, args->err_buff)))
		return (-1);
	if ((args->err_ptr = filter_init(&args->filt, &args->job)))
		return (-1);
//	thrds_print_wrapper(args, (print_fn_t)filter_print, &args->filt);
	if (pcap_compile(args->cap, &args->fp, args->filt.data, 1,
				PCAP_NETMASK_UNKNOWN) == PCAP_ERROR
			|| pcap_setfilter(args->cap, &args->fp) == PCAP_ERROR) {
		args->err_ptr = pcap_geterr(args->cap);
		return (-1);
	}
	filter_destroy(&args->filt);
	if (args->fp.bf_insns)
		free(args->fp.bf_insns);
	if ((args->err_ptr = thrds_send(args)))
		return (-1);
	if (recv_loop(OPTS.timeout, args))
		return (-1);
	pcap_close(args->cap);
	return (0);
}

void				thrds_single(void) {
	THRDS->job.nb = OPTS.port_nb * OPTS.ip_nb;
	thrds_run(THRDS);
}

char				*thrds_spawn(void) {
	uint64_t		tot = OPTS.port_nb * OPTS.ip_nb,
					div = tot / OPTS.speedup,
					rem = tot % OPTS.speedup, i;

	for (i = 0; i < OPTS.speedup; ++i) {
		if (!(THRDS[i].job.nb = div + (i < rem)))
			break ;
		THRDS[i].job.idx = i * div + (i < rem ? i : rem);
		THRDS[i].id = i;
		if (pthread_create(&THRDS[i].thrd, NULL,
				(void *)thrds_run, &THRDS[i]))
			return ("Can't create new thread");
	}
	return (NULL);
}