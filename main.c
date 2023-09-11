/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/07 15:57:25 by fcadet            #+#    #+#             */
/*   Updated: 2023/08/30 09:16:56 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "parse.h"

struct				ip_pseudo_s {
	uint32_t		src;
	uint32_t		dst;
	uint8_t			pad;
	uint8_t			prot;
	uint16_t		tcp_seg_sz;
};

typedef struct ip_pseudo_s		ip_pseudo_t;

typedef enum			scan_flag_e {
	F_NULL,
	F_URG,
	F_ACK,
	F_PSH,
	F_RST,
	F_SYN,
	F_FIN,
	F_XMAS,
	F_UDP
}						scan_flag_t;

typedef enum			result_e {
	R_NONE,
	R_OPEN,
	R_CLOSE,
	R_FILTERED,
}						result_t;

typedef enum			scan_type_e {
	S_SYN,
	S_NULL,
	S_ACK,
	S_FIN,
	S_XMAS,
	S_UDP
}						scan_type_t;

typedef struct			entry_s {
	scan_type_t			scan:3;
	result_t			result:2;
	time_t				ts;
}						entry_t;

typedef entry_t			ports_t[MAX_PORTS];
typedef ports_t			ips_t[MAX_IPS];

typedef struct			glob_s {
	ips_t				ip_lst;
	int					sock;
}						glob_t;

typedef struct			data_s {
	char				pkt[BUFF_SZ];
	char				dev_name[BUFF_SZ];
	char				filters[MAX_THRDS][BUFF_SZ];
	struct iphdr		*iph;
	struct tcphdr		*tcph;
	struct sockaddr_in	local;
	struct sockaddr_in	remote[MAX_IPS][MAX_PORTS];
	pcap_t				*cap;
}						data_t;

glob_t	glob = { 0 };

void	sig_handler(int) {
	printf("SIGINT\n");
	close(glob.sock);
	exit(0);
}

int		sock_init(void) {
	int	on = 1;

	if ((glob.sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		perror("socket():");
		return (1);
	}
	if (setsockopt(glob.sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on))) {
		close(glob.sock);
		perror("setsockopt():");
		return (2);
	}
	return (0);
}

int		pcap_error(char *err, pcap_if_t *all_devs) {
	fprintf(stderr, "pcap(): %s\n", err);
	if (all_devs)
		pcap_freealldevs(all_devs);
	return (1);
}

int		local_init(data_t *data) {
	char				buff_err[PCAP_ERRBUF_SIZE] = { 0 };
	pcap_if_t			*all_devs = { 0 }, *dev = { 0 };
	struct pcap_addr	*addr = NULL;

	if (pcap_findalldevs(&all_devs, buff_err))
		return (pcap_error(buff_err, NULL));
    for (dev = all_devs; dev; dev = dev->next) {
        if (!(dev->flags & PCAP_IF_LOOPBACK)
				&& (dev->flags & PCAP_IF_UP)
				&& (dev->flags & PCAP_IF_RUNNING)) {
            for (addr = dev->addresses; addr; addr = addr->next) {
                if (addr->addr && addr->addr->sa_family == AF_INET) {
					strncpy(data->dev_name, dev->name, BUFF_SZ);
					data->local.sin_family = AF_INET;
					data->local.sin_port = htons(SRC_PORT);
					data->local.sin_addr = ((struct sockaddr_in *)addr->addr)->sin_addr;
					pcap_freealldevs(all_devs);
					return (0);
				}
            }
        }
    }
	return (pcap_error("No valid local address", all_devs));
}

int		init(data_t *data, opts_t *opts) {
	uint64_t	i, j;

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

int		cap_init(data_t *data) {
	char		buff_err[BUFF_SZ];

	if (!(data->cap = pcap_open_live(data->dev_name,
			PCAP_SNAPLEN_MAX, 0, PCAP_TIME_OUT, buff_err))) {
		fprintf(stderr, "pcap_open_live(): %s\n", buff_err);
		return (1);
	}
	return (0);
}

uint16_t checksum(uint16_t *data, uint64_t nbytes) {
    uint32_t	 sum;

	for (sum = 0; nbytes; nbytes -= 2, sum += *(data++), sum = (sum & 0xffff) + (sum >> 16));
    return (~sum);
}

void		fill_tcp_headers(data_t *data, uint64_t i, uint64_t j, scan_type_t scan) {
	ip_pseudo_t			*ipp = ((ip_pseudo_t *)data->tcph) - 1;

	ipp->src = data->local.sin_addr.s_addr;
	ipp->dst = data->remote[i][j].sin_addr.s_addr;
	ipp->prot = IPPROTO_TCP;
	ipp->tcp_seg_sz = htons(sizeof(struct tcphdr));

    data->tcph->source = data->local.sin_port;
    data->tcph->dest = data->remote[i][j].sin_port;
	data->tcph->seq = htonl(i + j);
	data->tcph->ack_seq = htonl(i + j);
    data->tcph->doff = sizeof(struct tcphdr) / 4;
	data->tcph->fin = ((scan == S_FIN || scan == S_XMAS) ? 1 : 0);
    data->tcph->syn = (scan == S_SYN ? 1 : 0);
	data->tcph->psh = (scan == S_XMAS ? 1 : 0);
	data->tcph->ack = (scan == S_ACK ? 1 : 0);
	data->tcph->urg = (scan == S_XMAS ? 1 : 0);
	data->tcph->window = MAX_WIN;
    data->tcph->check = checksum((uint16_t *)ipp,
			sizeof(ip_pseudo_t) + sizeof(struct tcphdr));
    data->iph->version = 4;
    data->iph->ihl = sizeof(struct iphdr) / 4;
    data->iph->ttl = 255;
    data->iph->protocol = IPPROTO_TCP;
	data->iph->saddr = data->local.sin_addr.s_addr;
    data->iph->daddr = data->remote[i][j].sin_addr.s_addr;
}

void		print_packet(void *packet) {
	struct iphdr			*ip = (struct iphdr *)packet;
	struct tcphdr			*tcp = (struct tcphdr *)(ip + 1);

	printf("seq: %d ", ntohl(tcp->seq));
	printf("ack_seq: %d ", ntohl(tcp->ack_seq));
	printf("%s::%d > ",
			inet_ntoa(*(struct in_addr *)&ip->saddr),
			ntohs(tcp->source));
	printf("%s::%d",
			inet_ntoa(*(struct in_addr *)&ip->daddr),
			ntohs(tcp->dest));
	printf("%s%s%s%s%s%s\n",
			tcp->fin ? " FIN" : "",
			tcp->syn ? " SYN" : "",
			tcp->rst ? " RST" : "",
			tcp->psh ? " PSH" : "",
			tcp->ack ? " ACK" : "",
			tcp->urg ? " URG" : ""
		  );
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

int		main(int, char **argv) {
	opts_t		*opts = NULL;
	data_t		data = { 0 };
	uint64_t	i, j;

	if (parse(argv, &opts))
		return (1);
	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		perror("sig_handler():");
		return (2);
	}
	if (init(&data, opts))
		return (3);
	// THREADS
	if (cap_init(&data))
		return (4);
	// END THREADS
	for (i = 0; i < opts->ip_nb; ++i) {
		for (j = 0; j < opts->port_nb; ++j) {
			fill_headers(&data, opts, i, j);
			print_packet(data.pkt);
			if (sendto(glob.sock, data.pkt,
						sizeof(struct iphdr) + sizeof(struct tcphdr),
						0, (struct sockaddr *)&data.remote[i][j],
						sizeof(struct sockaddr_in)) == -1) {
				perror("sendto():");
				return (5);
			}
			printf("Packet sent");
		}
	}
	return (0);
}

/*

void	cap_handler(uint8_t *data, const struct pcap_pkthdr *pkt_hdr, const uint8_t *pkt) {
	const struct	ether_header	*ethh = (const struct ether_header *)pkt;
	const struct	iphdr			*iph = (const struct iphdr *)(ethh + 1);
	const struct	tcphdr			*tcph = { 0 };
	const struct	icmphdr			*icmph = { 0 };

	char	ip_src[INET_ADDRSTRLEN];

	(void)pkt_hdr;
	(void)data;
	if (ntohs(ethh->ether_type) == ETHERTYPE_IP) {
		inet_ntop(AF_INET, &(iph->saddr), ip_src, INET_ADDRSTRLEN);
		if (!str_n_cmp(ip_src, DST_ADDR, INET_ADDRSTRLEN)) {
			switch(iph->protocol) {
				case IPPROTO_TCP:
					tcph = (const struct tcphdr *)(iph + 1);
					printf("TCP from: %s:%d\n", ip_src, ntohs(tcph->source));
					break ;
				case IPPROTO_ICMP:
					icmph = (const struct icmphdr *)(iph + 1);
					iph = (const struct iphdr *)(icmph + 1);
					tcph = (const struct tcphdr *)(iph + 1);
					printf("ICMP from: %s:%d\n", ip_src, ntohs(tcph->dest));
					break ;
				case IPPROTO_UDP:
					break ;
					tcph = (const struct tcphdr *)(iph + 1);
					printf("UDP from: %s:%d\n", ip_src, ntohs(tcph->source));
					break ;
				default:
					printf("Unknown Protocol: %d from: %s\n", iph->protocol, ip_src);
					break;
			}
		}
	}
	return ;
}
int		main(void) {
	int					on = 1;
    char				data[BUFF_SZ] = { 0 },
						dev_name[BUFF_SZ] = { 0 },
						buff_err[PCAP_ERRBUF_SIZE] = { 0 },
						filters[MAX_THRDS][BUFF_SZ];
    struct iphdr		*iph = (struct iphdr *)data;
    struct tcphdr		*tcph = (struct tcphdr *)(iph + 1);
	struct sockaddr_in	local = { 0 }, remote = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = inet_addr(DST_ADDR),
		.sin_port = htons(DST_PORT)
	};
	pcap_t				*cap;

//	PCAP INIT (FILTERS ?) | THR
	if (!(cap = pcap_open_live(dev_name, PCAP_SNAPLEN_MAX, 0, PCAP_TIME_OUT, buff_err))) {
		fprintf(stderr, "pcap_open_live error: %s\n", buff_err);
		return (6);
	}
//	CREATE + SEND TCP PACKET | NO_THR
	printf("%s\n", inet_ntoa(local.sin_addr));
	fill_headers(iph, tcph, local, remote, SCAN_TYPE);
	print_packet(data);
    if (sendto(sock, data,
				sizeof(struct iphdr) + sizeof(struct tcphdr),
				0, (struct sockaddr *)&remote,
				sizeof(struct sockaddr_in)) == -1) {
        perror("Sendto error");
        return (5);
    }
	printf("Packet sent.\n");
//	RECEPTION | THR
	while (42) {
		if (pcap_dispatch(cap, 0, cap_handler, 0) == PCAP_ERROR) {
			fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(cap));
			return (6);
		}
	}
	printf("Packet received.\n");
//	CLEAN | THR
	close(sock);
	pcap_close(cap);
	return (0);
}

*/
