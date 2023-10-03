/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   local.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/11 14:55:43 by fcadet            #+#    #+#             */
/*   Updated: 2023/10/01 17:49:49 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../hdrs/local.h"

local_t		LOCAL = { 0 };

char		*local_init(void) {
	char				err[PCAP_ERRBUF_SIZE];
	static char			buff[BUFF_SZ];
	pcap_if_t			*all_devs = NULL, *dev = NULL;
	struct pcap_addr	*addr = NULL;

	if (pcap_findalldevs(&all_devs, err)) {
		snprintf(buff, BUFF_SZ, "pcap_findalldevs: %s", err);
		return (buff);
	}
    for (dev = all_devs; dev; dev = dev->next) {
        if (!(dev->flags & PCAP_IF_LOOPBACK)
				&& (dev->flags & PCAP_IF_UP)
				&& (dev->flags & PCAP_IF_RUNNING)) {
            for (addr = dev->addresses; addr; addr = addr->next) {
                if (addr->addr && addr->addr->sa_family == AF_INET) {
					str_n_cpy(LOCAL.dev_name, dev->name, BUFF_SZ);
					LOCAL.addr = ((struct sockaddr_in *)addr->addr)->sin_addr;
					pcap_freealldevs(all_devs);
					return (NULL);
				}
            }
        }
    }
	pcap_freealldevs(all_devs);
	return ("No connected device available");
}

void		local_print(void *) {
	char	buff[BUFF_SZ];

	sprintf(buff, "%-*s", TITLE_SZ, "Interface:");
	printf("    %s%s\n", buff, LOCAL.dev_name);
	sprintf(buff, "%-*s", TITLE_SZ, "IP address:");
	printf("    %s%s\n", buff, inet_ntoa(LOCAL.addr));
}
