/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   test.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/30 09:16:03 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/02 16:14:56 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#define BUFF_SZ				4096
#define MIN_PORT			49152
#define	MAX_PORT			65536	
#define SRC_PORT			55555
#define DST_PORT			80
#define DST_ADDR			/*"91.211.165.100"*/"1.1.1.1"
#define MAX_WIN				0xff
#define SCAN_TYPE			SYN
#define PCAP_SNAPLEN_MAX	65535
#define PCAP_TO				-1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <signal.h>
#include <ifaddrs.h>
#include <errno.h>
#include <pthread.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>

int					sock;

struct				ip_pseudo_s {
	uint32_t		src;
	uint32_t		dst;
	uint8_t			pad;
	uint8_t			prot;
	uint16_t		tcp_seg_sz;
};

typedef enum		scan_flag_e {
	NUL,
	URG,
	ACK,
	PSH,
	RST,
	SYN,
	FIN,
	XMAS,
	UDP
}					scan_flag_t;

typedef struct ip_pseudo_s		ip_pseudo_t;

uint16_t checksum(uint16_t *data, uint64_t nbytes) {
    uint32_t	 sum;

	for (sum = 0; nbytes; nbytes -= 2, sum += *(data++), sum = (sum & 0xffff) + (sum >> 16));
    return (~sum);
}

void	sig_handler(int) {
	printf("SIGINT\n");
	close(sock);
	exit(0);
}

int		pcap_error(char *err, pcap_if_t *all_devs) {
	fprintf(stderr, "Pcap error: %s\n", err);
	if (all_devs)
		pcap_freealldevs(all_devs);
	return (-1);
}

int		get_local(struct sockaddr_in *local, char *dev_name, uint64_t dev_sz) {
	char				buff_err[PCAP_ERRBUF_SIZE];
	pcap_if_t			*all_devs = NULL;
	uint32_t			dev_ip;
	uint32_t			dev_msk;

	if (pcap_findalldevs(&all_devs, buff_err))
		pcap_error(buff_err, NULL);
	if (!all_devs)
		pcap_error("No interface", all_devs);
	strncpy(dev_name, all_devs->name, dev_sz);
	if (pcap_lookupnet(dev_name, &dev_ip, &dev_msk, buff_err))
		pcap_error(buff_err, all_devs);
	local->sin_family = AF_INET;
	local->sin_port = htons(SRC_PORT);
	local->sin_addr = *((struct in_addr *)&dev_ip);
	pcap_freealldevs(all_devs);
	return (0);
}

void		fill_headers(struct iphdr *iph, struct tcphdr *tcph, struct sockaddr_in local,
							struct sockaddr_in remote, scan_flag_t scan) {
	ip_pseudo_t			*ipp = ((ip_pseudo_t *)tcph) - 1;

	ipp->src = local.sin_addr.s_addr;
	ipp->dst = remote.sin_addr.s_addr;
	ipp->prot = IPPROTO_TCP;
	ipp->tcp_seg_sz = htons(sizeof(struct tcphdr));

    tcph->source = local.sin_port;
    tcph->dest = remote.sin_port;
	tcph->seq = htonl(42);
	tcph->ack_seq = htonl(42);
    tcph->doff = sizeof(struct tcphdr) / 4;
	tcph->fin = ((scan == FIN || scan == XMAS) ? 1 : 0);
    tcph->syn = (scan == SYN ? 1 : 0);
	tcph->psh = ((scan == PSH || scan == XMAS) ? 1 : 0);
	tcph->ack = (scan == ACK ? 1 : 0);
	tcph->urg = ((scan == URG || scan == XMAS) ? 1 : 0);
	tcph->window = MAX_WIN;
    tcph->check = checksum((uint16_t *)ipp,
			sizeof(ip_pseudo_t) + sizeof(struct tcphdr));
	bzero(iph, sizeof(struct iphdr));
    iph->version = 4;
    iph->ihl = sizeof(struct iphdr) / 4;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
	iph->saddr = local.sin_addr.s_addr;
    iph->daddr = remote.sin_addr.s_addr;
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
/*
	char					buff[BUFF_SZ];
	struct iphdr			*ip = (struct iphdr *)buff;
	struct tcphdr			*tcp = (struct tcphdr *)(ip + 1);

	for (;;) {
		if (recvfrom(sock, buff, BUFF_SZ, 0, NULL, NULL) < 0)
			fprintf(stderr, "recv error\n");
		if (ntohs(tcp->dest) == SRC_PORT) {
			print_packet(buff);
			return (NULL);
		}
	}
*/

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
		if (!strcmp(ip_src, DST_ADDR)) {
			switch(iph->protocol) {
				case IPPROTO_TCP:
					tcph = (const struct tcphdr *)(iph + 1);
					printf("TCP from: %s:%d\n", ip_src, ntohs(tcph->dest));
					break ;
				case IPPROTO_ICMP:
					icmph = (const struct icmphdr *)(iph + 1);
					printf("ICMP from: %s:%d\n", ip_src, icmph->type);
					break ;
				case IPPROTO_UDP:
					break ;
					tcph = (const struct tcphdr *)(iph + 1);
					printf("UDP from: %s:%d\n", ip_src, ntohs(tcph->dest));
					break ;
				default:
					printf("Unknown Protocol from: %s\n", ip_src);
					break;
			}
		}
	}
	return ;
}

void	sniffer_fn(pcap_t *cap) {
	while (42) {
		if (pcap_dispatch(cap, 0, cap_handler, 0) == PCAP_ERROR) {
			fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(cap));
			return ;
		}
	}
}

int		main(void) {
	int					on = 1;
    char				data[BUFF_SZ] = { 0 },
						dev_name[BUFF_SZ] = { 0 };
//						buff_err[PCAP_ERRBUF_SIZE] = { 0 };
    struct iphdr		*iph = (struct iphdr *)data;
    struct tcphdr		*tcph = (struct tcphdr *)(iph + 1);
	struct sockaddr_in	local = { 0 }, remote = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = inet_addr(DST_ADDR),
		.sin_port = htons(DST_PORT)
	};
//	pcap_t				*cap;
//	pthread_t			sniffer;

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
        perror("Sig handler error");
        return (1);
    }
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("Socket error");
        return (2);
    }
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on))) {
		close(sock);
        perror("Socket option error");
        return (3);
    }
	if (get_local(&local, dev_name, BUFF_SZ)) {
		close(sock);
		perror("Local error");
		return (4);
	}
	fill_headers(iph, tcph, local, remote, SCAN_TYPE);
	/*
	if (pthread_create(&sniffer, NULL, sniffer_fn, NULL)) {
		close(sock);
		fprintf(stderr,
				"Sniffer creation: Fail to create thread\n");
	}
	*/
	print_packet(data);
    if (sendto(sock, data,
				sizeof(struct iphdr) + sizeof(struct tcphdr),
				0, (struct sockaddr *)&remote,
				sizeof(struct sockaddr_in)) == -1) {
        perror("Sendto error");
        return (5);
    }
	printf("Packet sent.\n");
/*	if (!(cap = pcap_open_live(dev_name, PCAP_SNAPLEN_MAX, 0, PCAP_TO, buff_err))) {
		fprintf(stderr, "pcap_open_live error: %s\n", buff_err);
		return (6);
	}
	sniffer_fn(cap);
*/	printf("Packet received.\n");
//	pthread_join(sniffer, NULL);
	close(sock);
//	pcap_close(cap);
	return (0);
}
