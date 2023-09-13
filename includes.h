/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   includes.h                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/12 15:00:44 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/12 15:01:45 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef INCLUDES_H
#define INCLUDES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <signal.h>
#include <ifaddrs.h>
#include <errno.h>
#include <pthread.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>

#define				BUFF_SZ				0x1000
#define				MAX_PORTS			0x400
#define				MIN_PORT_VAL		0xc000
#define				MAX_PORT_VAL		0xffff
#define				MAX_IPS				0x200
#define				SRC_PORT			55555
#define				FILE_SZ				((INET_ADDRSTRLEN + 1) * MAX_IPS)
#define				MAX_THRDS			250
#define				FLAGS_NB			6
#define				SCANS_NB			6
#define				MAX_WIN				0xff
#define				PCAP_SNAPLEN_MAX	0xffff
#define				PCAP_TIME_OUT		-1

#endif // INCLUDES_H
