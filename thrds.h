/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thrds.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/11 20:28:46 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/12 09:30:28 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef THRDS_H
#define THRDS_H

#include "filter.h"

typedef enum	result_e {
	R_NONE,
	R_OPEN,
	R_CLOSE,
	R_FILTERED,
}				result_t;

typedef struct	thrds_arg_s {
	job_t		job;
	char		err[BUFF_SZ];
}				thrds_arg_t;

typedef result_t		results_t[MAX_IPS][MAX_PORTS][SCANS_NB];

typedef void	*(*thrds_handler)(void *);

extern results_t		RESULTS;

#endif // THRDS_H
