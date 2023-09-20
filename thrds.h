/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thrds.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/11 20:28:46 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/12 15:36:18 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef THRDS_H
#define THRDS_H

#include "result.h"

typedef struct	thrds_arg_s {
	job_t		job;
	char		err_buff[BUFF_SZ];
	char		*err_ptr;
	uint8_t		id;
	pthread_t	thrd;
}				thrds_arg_t;

typedef void	*(*thrds_handler)(void *);

char	*thrds_init(void);
char	*thrds_spawn(void);

extern	thrds_arg_t	THRDS[MAX_THRDS];

#endif // THRDS_H
