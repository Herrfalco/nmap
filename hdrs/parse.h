/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/12 15:01:52 by fcadet            #+#    #+#             */
/*   Updated: 2023/10/01 17:28:08 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef PARSE_H
#define PARSE_H

#include "utils.h"

typedef enum		flag_e {
	F_HELP = 0x1,
	F_PORTS = 0x2,
	F_IP = 0x4,
	F_FILE = 0x8,
	F_SPEEDUP = 0x10,
	F_SCAN = 0x20,
	F_TIMEOUT = 0x40,
	F_TEMPO = 0x80,
	F_REVERT = 0x100,
}					flag_t;

typedef enum		scan_e {
	ST_SYN,
	ST_NULL,
	ST_ACK,
	ST_FIN,
	ST_XMAS,
	ST_UDP,
	ST_ICMP,
}					scan_t;

typedef struct		opts_s {
	uint16_t		ports[MAX_PORTS];
	uint64_t		port_nb;
	in_addr_t		ips[MAX_IPS];
	uint64_t		ip_nb;
	scan_t			scans[SCANS_NB];
	uint64_t		scan_nb;
	uint64_t		timeout;
	uint64_t		tempo;
	uint64_t		speedup;
	uint16_t		flag;
}					opts_t;

typedef char		*(*parse_fn_t)(char *);

char				*parse(char **argv);
void				parse_print(void *);

uint16_t			scan_2_port(scan_t scan);
scan_t				port_2_scan(uint16_t port);

extern opts_t		OPTS;
extern char			*SCAN_NAMES[];

#endif // PARSE_H
