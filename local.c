/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   local.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/11 14:55:43 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/12 15:04:18 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "local.h"

local_t		LOCAL = { 0 };

char		*local_init(void) {
	char				err[PCAP_ERRBUF_SIZE];
	static char			buff[BUFF_SZ];
	pcap_if_t			*all_devs, *dev = { 0 };
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
					strncpy(LOCAL.dev_name, dev->name, BUFF_SZ);
					LOCAL.addr.sin_family = AF_INET;
					LOCAL.addr.sin_port = htons(SRC_PORT);
					LOCAL.addr.sin_addr = ((struct sockaddr_in *)addr->addr)->sin_addr;
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
	printf("device: %s, IP: %s\n", LOCAL.dev_name,
			inet_ntoa(LOCAL.addr.sin_addr));
}
