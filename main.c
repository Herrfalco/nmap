/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/07 15:57:25 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/11 14:56:06 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "thrds.h"

int		main(int, char **argv) {
//	data_t		data = { 0 };
//	uint64_t	i, j;
	char		*err;

	if ((err = parse(argv))) {
		fprintf(stderr, "Error: %s\n", err);
		return (1);
	}
	parse_print(NULL);
	if ((err = local_init())) {
		fprintf(stderr, "Error: %s\n", err);
		return (2);
	}
	local_print(NULL);
	if ((err = thrds_init())) {
		fprintf(stderr, "Error: %s\n", err);
		return (3);
	}
	if ((err = thrds_spawn())) {
		fprintf(stderr, "Error: %s\n", err);
		return (4);
	}
	while (42);
	/*
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
	*/
	return (0);
}

/*

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
/*
int		main(int, char **argv) {
	filts_t			filt_lst;
	char			*err;

	if (parse(argv))
		return (0);
	if ((err = filter_lst_init(&filt_lst)))
		printf("Error: %s\n", err);
	for (uint64_t i = 0; filt_lst.strs && i < filt_lst.sz; ++i)
		printf("thread %ld:%s\n\n", i + 1, filt_lst.strs[i].data);
	filter_lst_destroy(&filt_lst);
	return (0);
}
*/

