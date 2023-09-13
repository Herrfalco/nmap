/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   filter.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/09 16:37:49 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/12 15:03:22 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FILTER_H
#define FILTER_H

#include "packet.h"

typedef struct		filt_s {
	char			*data;
	uint64_t		sz;
}					filt_t;

typedef struct	job_s {
	uint64_t	idx;
	uint64_t	nb;
}				job_t;

char			*filter_init(filt_t *filt, job_t *job);
void			filter_print(filt_t *filt);
void			filter_destroy(filt_t *filt);

#endif // FILTER_H
