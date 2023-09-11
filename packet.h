/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   packet.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/11 14:40:52 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/11 22:05:54 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef PACKET_H
#define PACKET_H

#include "local.h"

typedef struct			ip_pseudo_s {
	uint32_t			src;
	uint32_t			dst;
	uint8_t				pad;
	uint8_t				prot;
	uint16_t			tcp_seg_sz;
}						ip_pseudo_t;

typedef enum			packet_typ_e {
	PT_TCP,
	PT_UDP,
	PT_ICMP,
}						packet_typ_t;

typedef struct			packet_s {
	struct iphdr		*iph;
	union				{
		void			*proth;
		struct tcphdr	*tcph;
		struct udphdr	*udph;
		struct icmphdr	*icmph;
	};
	ip_pseudo_t			*ipp;
	uint64_t			sz;
}						packet_t;

void	packet_init(packet_t *packet, uint8_t *data, uint64_t sz);
void	packet_fill(packet_t *packet, struct sockaddr_in *dst, scan_t scan);
void	packet_print(packet_t *packet);

#endif // PACKET_H
