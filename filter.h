/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   filter.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/09 16:37:49 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/09 16:41:47 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FILTER_H
#define FILTER_H

#include "parse.h"

typedef struct		str_s {
	char			*data;
	uint64_t		sz;
}					str_t;

typedef	struct		filts_s {
	str_t			*strs;
	uint64_t		sz;
}					filts_t;

char				*filter_lst_init(filts_t *filts);
void				filter_lst_destroy(filts_t *filts);

#endif // FILTER_H
