/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   packet.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/11 14:41:31 by fcadet            #+#    #+#             */
/*   Updated: 2023/10/02 23:14:08 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../hdrs/packet.h"

static uint16_t packet_checksum(uint16_t *data, uint64_t nbytes) {
    uint32_t	 sum;

	for (sum = 0; nbytes;
			nbytes -= 2,
			sum += *(data++),
			sum = (sum & 0xffff) + (sum >> 16));
    return (~sum);
}

static void		packet_fill_tcp(packet_t *packet, struct sockaddr_in *dst, scan_t scan) {
	packet->ipp->src = LOCAL.addr.s_addr;
	packet->ipp->dst = dst->sin_addr.s_addr;
	packet->ipp->prot = IPPROTO_TCP;
	packet->ipp->seg_sz = htons(sizeof(struct tcphdr));
	packet->tcph->source = htons(scan_2_port(scan));
	packet->tcph->dest = dst->sin_port;
	packet->tcph->doff = sizeof(struct tcphdr) / 4;
	packet->tcph->fin = scan == ST_FIN || scan == ST_XMAS;
	packet->tcph->syn = scan == ST_SYN;
	packet->tcph->psh = scan == ST_XMAS;
	packet->tcph->ack = scan == ST_ACK;
	packet->tcph->urg = scan == ST_XMAS;
	packet->tcph->window = htons(MAX_WIN);
	packet->tcph->check = packet_checksum((uint16_t *)packet->ipp,
			sizeof(ip_pseudo_t) + sizeof(struct tcphdr));
	bzero(packet->iph, sizeof(struct iphdr));
}

static void		packet_fill_udp(packet_t *packet, struct sockaddr_in *dst, uint64_t body_sz) {
	packet->ipp->src = LOCAL.addr.s_addr;
	packet->ipp->dst = dst->sin_addr.s_addr;
	packet->ipp->prot = IPPROTO_UDP;
	packet->ipp->seg_sz = htons(sizeof(struct udphdr) + body_sz);
	packet->udph->source = htons(scan_2_port(ST_UDP));
	packet->udph->dest = dst->sin_port;
	packet->udph->len = htons(sizeof(struct udphdr) + body_sz);
	packet->udph->check = packet_checksum((uint16_t *)packet->ipp,
			sizeof(ip_pseudo_t) + sizeof(struct udphdr) + body_sz);
	bzero(packet->iph, sizeof(struct iphdr));
}

static void		packet_fill_ip(packet_t *packet, in_addr_t dst, uint8_t prot) {
    packet->iph->version = 4;
    packet->iph->ihl = sizeof(struct iphdr) / 4;
    packet->iph->ttl = 255;
    packet->iph->protocol = prot;
	packet->iph->saddr = LOCAL.addr.s_addr;
    packet->iph->daddr = dst;
}

void			packet_init(packet_t *packet, uint8_t *data, uint64_t sz) {
	packet->iph = (struct iphdr *)data;
	packet->proth = packet->iph + 1;
	packet->ipp = ((ip_pseudo_t *)packet->proth) - 1;
	packet->sz = sz;
}

void			packet_fill(packet_t *packet, struct sockaddr_in *dst, scan_t scan) {
	uint8_t		*payload = NULL;
	uint64_t	sz = 0;

	bzero(packet->iph, packet->sz);
	if (scan == ST_UDP) {
		switch (ntohs(dst->sin_port)) {
			case DNS_PORT:
				payload = (uint8_t *)DNS_PAYLOAD;
				sz = DNS_SZ;
				break;
			case SNMP_PORT:
				payload = (uint8_t *)SNMP_PAYLOAD;
				sz = SNMP_SZ;
				break;
			case DHCP_PORT:
				payload = (uint8_t *)DHCP_PAYLOAD;
				sz = DHCP_SZ;
		}
		mem_cpy((uint8_t *)(packet->udph + 1), payload, sz);
		packet_fill_udp(packet, dst, sz);
		packet_fill_ip(packet, dst->sin_addr.s_addr, IPPROTO_UDP);
		packet->sz = sizeof(struct iphdr) + sizeof(struct udphdr) + sz;
	} else {
		packet_fill_tcp(packet, dst, scan);
		packet_fill_ip(packet, dst->sin_addr.s_addr, IPPROTO_TCP);
		packet->sz = sizeof(struct iphdr) + sizeof(struct tcphdr);
	}
}

void			packet_print(packet_t *packet) {
	switch (packet->iph->protocol) {
		case (IPPROTO_TCP):
			printf("[TCP] ");
			printf("%s::%d > ",
					inet_ntoa(*(struct in_addr *)&packet->iph->saddr),
					ntohs(packet->tcph->source));
			printf("%s::%d ",
					inet_ntoa(*(struct in_addr *)&packet->iph->daddr),
					ntohs(packet->tcph->dest));
			printf("%s%s%s%s%s%s\n",
					packet->tcph->fin ? " FIN" : "",
					packet->tcph->syn ? " SYN" : "",
					packet->tcph->rst ? " RST" : "",
					packet->tcph->psh ? " PSH" : "",
					packet->tcph->ack ? " ACK" : "",
					packet->tcph->urg ? " URG" : ""
				  );
			break;
		case (IPPROTO_UDP):
			printf("[UDP] ");
			printf("%s > %s\n",
					inet_ntoa(*(struct in_addr *)&packet->iph->saddr),
					inet_ntoa(*(struct in_addr *)&packet->iph->daddr));
			break;
		case (IPPROTO_ICMP):
			printf("[ICMP] ");
			printf("%s > %s\n",
					inet_ntoa(*(struct in_addr *)&packet->iph->saddr),
					inet_ntoa(*(struct in_addr *)&packet->iph->daddr));
			break;
		default:
			printf("[UNK] ");
			printf("%s > %s\n",
					inet_ntoa(*(struct in_addr *)&packet->iph->saddr),
					inet_ntoa(*(struct in_addr *)&packet->iph->daddr));
	}
}
