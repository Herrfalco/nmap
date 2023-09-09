/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/12 15:01:52 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/09 16:46:40 by fcadet           ###   ########.fr       */
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
}					flag_t;

typedef enum		scan_e {
	ST_SYN = 0x1,
	ST_NULL = 0x2,
	ST_ACK = 0x4,
	ST_FIN = 0x8,
	ST_XMAX = 0x10,
	ST_UDP = 0x20,
	ST_ALL = 0x3f,
}					scan_t;

typedef struct		opts_s {
	uint16_t		ports[MAX_PORTS];
	uint64_t		port_nb;
	in_addr_t		ips[MAX_IPS];
	uint64_t		ip_nb;
	uint8_t			speedup;
	uint8_t			scan;
	uint8_t			flag;
}					opts_t;

typedef char		*(*parse_fn_t)(char *);

extern opts_t		OPTS;

int					parse(char **argv);

#endif // PARSE_H
