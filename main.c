/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/07 15:57:25 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/09 18:22:29 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "filter.h"

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
