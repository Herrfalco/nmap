/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   test.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/30 09:16:03 by fcadet            #+#    #+#             */
/*   Updated: 2023/08/31 21:25:32 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#define BUFF_SZ				4096
#define MIN_PORT			49152
#define	MAX_PORT			65536	
#define DST_PORT			80
#define DST_IP 				"91.211.165.100"
#define DEF_WIN_SZ			5840

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <signal.h>
#include <ifaddrs.h>
#include <errno.h>

int					sock;

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

void	sig_handler(int) {
	printf("SIGINT\n");
	close(sock);
	exit(0);
}

int		bind_2_local(struct sockaddr_in *local) {
    struct ifaddrs		*ifaddr, *i;
	uint32_t			port;

    if (getifaddrs(&ifaddr) == -1)
		return (-1);
	local->sin_family = AF_INET;
    for (i = ifaddr; i != NULL; i = i->ifa_next) {
		if (i->ifa_addr && i->ifa_addr->sa_family == AF_INET
				&& !(i->ifa_flags & IFF_LOOPBACK) && (i->ifa_flags & IFF_UP)
				&& (i->ifa_flags & IFF_RUNNING)) {
			local->sin_addr = ((struct sockaddr_in *)i->ifa_addr)->sin_addr;
			break;
		}
    }
	freeifaddrs(ifaddr);
	if (!i) {
		errno = EADDRNOTAVAIL;
		return (-1);
	}
	for (port = MIN_PORT; port < MAX_PORT; ++port) {
		local->sin_port = htons(port);
		if (!bind(sock, (struct sockaddr *)local, sizeof(struct sockaddr_in)))
			return (0);
	}
	errno = EADDRNOTAVAIL;
	return (-1);
}

int		print_addr_and_port(void) {
	struct sockaddr_in		result = { 0 };
	uint64_t				sz = sizeof(result);

	if (getsockname(sock, (struct sockaddr *)&result, (socklen_t *)&sz))
		return (-1);
	printf("addr: %s, port: %d\n", inet_ntoa(result.sin_addr), ntohs(result.sin_port));
	return (0);
}

void	response(void) {
	struct sockaddr_in		addr;
	uint64_t				sz;
	char					buff[BUFF_SZ];
	ssize_t					ret;

	if ((ret = recvfrom(sock, buff, BUFF_SZ, 0, (struct sockaddr *)&addr, (socklen_t *)&sz) < 0))
		fprintf(stderr, "recv error\n");
	printf("size: %ld, addr: %s, port: %d\n", sz, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
}

int		main(void) {
	int						on = 1;
    char				data[BUFF_SZ] = { 0 };
    struct iphdr		*iph = (struct iphdr *)data;
    struct tcphdr		*tcph = (struct tcphdr *)(iph + 1);
	ip_pseudo_t			*ipp = ((ip_pseudo_t *)tcph) - 1;
	struct sockaddr_in	local = { 0 }, remote = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = inet_addr(DST_IP),
		.sin_port = htons(DST_PORT),
	};

	(void)remote;
	(void)ipp;
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
	if (bind_2_local(&local)) {
		close(sock);
		perror("Bind error");
		return (4);
	}
	print_addr_and_port();

	ipp->src = local.sin_addr.s_addr;
	ipp->dst = inet_addr(DST_IP);
	ipp->prot = IPPROTO_TCP;
	ipp->tcp_seg_sz = sizeof(struct tcphdr);

    tcph->source = local.sin_port;
    tcph->dest = remote.sin_port;
    tcph->doff = sizeof(struct tcphdr) / 4;
    tcph->syn = 1;
    tcph->check = checksum((uint16_t *)ipp, sizeof(ip_pseudo_t) + sizeof(struct tcphdr));

	bzero(iph, sizeof(struct iphdr));
    iph->version = 4;
    iph->ihl = sizeof(struct iphdr) / 4;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
	iph->saddr = local.sin_addr.s_addr;
    iph->daddr = inet_addr(DST_IP);

    if (sendto(sock, data, iph->tot_len, 0, (struct sockaddr *)&remote, sizeof(struct sockaddr_in)) == -1) {
        perror("Sendto error");
        return (1);
    }
    printf("SYN packet sent.\n");

	response();

	close(sock);
	return (0);
}
