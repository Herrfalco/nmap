/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   filter.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/09 16:37:49 by fcadet            #+#    #+#             */
/*   Updated: 2023/10/02 19:48:01 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FILTER_H
#define FILTER_H

#include "packet.h"

typedef struct		job_s {
	uint64_t		idx;
	uint64_t		nb;
}					job_t;

char			*filter_init(void);
void			filter_print(char *filt);
void			filter_bpf_free(struct bpf_program *bpf);

#endif // FILTER_H
