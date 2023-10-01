/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thrds.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/11 20:28:46 by fcadet            #+#    #+#             */
/*   Updated: 2023/10/01 21:18:51 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef THRDS_H
#define THRDS_H

#include "result.h"

typedef struct			thrds_arg_s {
	job_t				job;
	char				err_buff[BUFF_SZ];
	char				*err_ptr;
	uint8_t				id;
	pcap_t				*cap;
	filt_t				filt;
	struct bpf_program	bpf;
	pthread_t			thrd;
}						thrds_arg_t;

typedef void	*(*thrds_handler)(void *);
typedef void	(*thrds_print_fn)(void *);

char		*thrds_init(void);
void		thrds_fini(void);
char		*thrds_spawn(void);
void		thrds_single(void);

extern	thrds_arg_t	THRDS[MAX_THRDS];

#endif // THRDS_H
