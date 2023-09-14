/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/12 15:04:30 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/14 15:32:59 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef UTILS_H
#define UTILS_H

#include "includes.h"

typedef void	(*print_fn_t)(void *);

int				str_n_cmp(char *s1, char *s2, uint64_t n);
int				str_cmp(char *s1, char *s2);
uint8_t			bit_set(uint8_t byte);

#endif // UTILS_H
