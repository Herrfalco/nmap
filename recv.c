/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   recv.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/11 14:15:52 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/12 09:18:28 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

int		cap_init(data_t *data) {
	char		buff_err[BUFF_SZ];

	if (!(data->cap = pcap_open_live(data->dev_name,
			PCAP_SNAPLEN_MAX, 0, PCAP_TIME_OUT, buff_err))) {
		fprintf(stderr, "pcap_open_live(): %s\n", buff_err);
		return (1);
	}
	return (0);
}

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
