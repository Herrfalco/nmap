/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   test.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/30 09:16:03 by fcadet            #+#    #+#             */
/*   Updated: 2023/08/30 12:13:34 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#define BUFF_SZ				4096
#define SRC_PORT			54321
#define DST_PORT			80
#define DST_IP 				"127.0.0.1"
#define DEF_WIN_SZ			5840

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct				ip_pseudo_s {
	uint32_t		src;
	uint32_t		dst;
	uint8_t			pad;
	uint8_t			prot;
	uint16_t		tcp_seg_sz;
};

typedef struct ip_pseudo_s		ip_pseudo_t;

unsigned short checksum(uint16_t *data, uint64_t nbytes) {
    uint64_t	 sum;

	for (sum = 0; nbytes; nbytes -= 2, sum += *(data++));
	for (; sum >> 16; sum = (sum & 0xffff) + (sum >> 16));
    return (~sum);
}

void	response(int sock, struct sockaddr *src_addr) {
	char				buff[BUFF_SZ];
	socklen_t	sock_sz = sizeof(struct sockaddr_in);

	if (recvfrom(sock, buff, BUFF_SZ, 0 , src_addr, &sock_sz) < 0)
		fprintf(stderr, "recv error\n");
	alarm(1);
}

int		main() {
    int					sock;
    char				data[BUFF_SZ] = { 0 };
    struct iphdr		*iph = (struct iphdr *)data;
    struct tcphdr		*tcph = (struct tcphdr *)(iph + 1);
	ip_pseudo_t			*ipp = ((ip_pseudo_t *)tcph) - 1;
    struct sockaddr_in	dst_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(DST_PORT),
		.sin_addr.s_addr = inet_addr(DST_IP),
	};

	ipp->src = htons(SRC_PORT);
	ipp->dst = dst_addr.sin_port;
	ipp->prot = IPPROTO_TCP;
    tcph->source = ipp->src;
    tcph->dest = ipp->dst;
    tcph->doff = sizeof(struct tcphdr) / 4;
    tcph->syn = 1;
    tcph->check = checksum((uint16_t *)iph, sizeof(ip_pseudo_t) + sizeof(struct tcphdr));
	bzero(iph, sizeof(struct iphdr));
    iph->version = 4;
    iph->ihl = sizeof(struct iphdr) / 4;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr(DST_IP);
    iph->daddr = dst_addr.sin_addr.s_addr;
    iph->check = checksum((uint16_t *)data, iph->tot_len);

    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("Socket error");
        return (1);
    }
    if (sendto(sock, data, iph->tot_len, 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr)) == -1) {
        perror("Sendto error");
        return (1);
    }

    printf("SYN packet sent.\n");
	response(sock, (struct sockaddr *)&dst_addr);
    close(sock);

    return 0;
}
