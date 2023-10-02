/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   includes.h                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/12 15:00:44 by fcadet            #+#    #+#             */
/*   Updated: 2023/10/02 23:21:35 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef INCLUDES_H
#define INCLUDES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <sys/time.h>

#define BUFF_SZ				0x1000
#define MAX_PORTS			0x400
#define MAX_PORT_VAL		0xffff
#define MAX_IPS				0x10
#define SRC_PORT			55555
#define FILE_SZ				((INET_ADDRSTRLEN + 1) * MAX_IPS)
#define MAX_THRDS			250
#define FLAGS_NB			11
#define SCANS_NB			6
#define MAX_WIN				0xff
#define PCAP_SNAPLEN_MAX	0xffff
#define PCAP_TIME_OUT		-1
#define ETHH_SZ				14
#define IPH_SZ				20
#define TCPH_SZ				20
#define ICMPH_SZ			8
#define UDPH_SZ				8
#define HDR_PORTS_SZ		4
#define DEF_TIMEOUT			250
#define MAX_TIMEOUT			60001
#define DEF_TEMPO			250
#define MAX_TEMPO			10001
#define LINE_SZ				80
#define TITLE_SZ			15
#define DNS_PORT			53
#define DNS_PAYLOAD 		"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00"
#define DNS_SZ				12
#define SNMP_PORT			161
#define SNMP_PAYLOAD		"\x30\x3a\x02\x01\x03\x30\x0f\x02\x02\x4a\x69\x02\x03\x00\xff\xe3" \
							"\x04\x01\x04\x02\x01\x03\x04\x10\x30\x0e\x04\x00\x02\x01\x00\x02" \
							"\x01\x00\x04\x00\x04\x00\x04\x00\x30\x12\x04\x00\x04\x00\xa0\x0c" \
							"\x02\x02\x37\xf0\x02\x01\x00\x02\x01\x00\x30\x00"
#define SNMP_SZ				60
#define DHCP_PORT			67
#define DHCP_PAYLOAD		"\x01\x01\x06\x00\x01\x23\x45\x67\x00\x00\x00\x00\xff\xff\xff\xff" \
							"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0e\x35\xd4" \
							"\xd8\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
							"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
							"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
							"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
							"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
							"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
							"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
							"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
							"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
							"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
							"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
							"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
							"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63" \
							"\x35\x01\x08\xff"
#define DHCP_SZ				244

#endif // INCLUDES_H
