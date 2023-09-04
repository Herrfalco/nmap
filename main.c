/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/07 15:57:25 by fcadet            #+#    #+#             */
/*   Updated: 2023/08/30 09:16:56 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "parse.h"

typedef enum			result_e {
	R_NONE,
	R_OPEN,
	R_CLOSE,
	R_FILTERED,
}						result_t;

typedef enum			scan_type_e {
	S_NULL,
	S_SYN,
	S_ACK,
	S_FIN,
	S_XMAS,
	S_UDP
}						scan_type_t;

typedef struct			entry_s {
	scan_type_t			scan:3;
	result_t			result:2;
	time_t				ts;
}						entry_t;

typedef entry_t			ports_t[MAX_PORTS];
typedef ports_t			ips_t[MAX_IPS];

typedef struct			glob_s {
	ips_t				ip_lst;
}						glob_t;

int		main(int, char **argv) {
	if (parse(argv))
		return (0);
	return (0);
}
