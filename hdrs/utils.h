/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/12 15:04:30 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/22 09:17:29 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef UTILS_H
#define UTILS_H

#include "includes.h"

typedef void	(*print_fn_t)(void *);

void			print_error(char *str);
int				str_n_cmp(char *s1, char *s2, uint64_t n);
int				str_cmp(char *s1, char *s2);
uint8_t			bit_set(uint8_t byte);
uint8_t			is_elapsed(struct timeval *tv_start,
					struct timeval *tv_cur, time_t delta);

#endif // UTILS_H
