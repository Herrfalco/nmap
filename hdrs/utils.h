/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/12 15:04:30 by fcadet            #+#    #+#             */
/*   Updated: 2023/10/02 22:15:47 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef UTILS_H
#define UTILS_H

#include "includes.h"

int				print_main_error(char *str, int ret);
int				str_n_cmp(char *s1, char *s2, uint64_t n);
int				str_cmp(char *s1, char *s2);
void			str_n_cpy(char *dst, char *src, uint64_t n);
void			str_cpy(char *dst, char *src);
void			mem_cpy(uint8_t *dst, uint8_t *src, uint64_t sz);
void			str_cat(char *s1, char *s2);
uint64_t		str_len(char *s);
uint8_t			bit_set(uint8_t byte);
uint8_t			is_elapsed(struct timeval *tv_start,
					struct timeval *tv_cur, time_t delta);
char			*char_line(char c, uint64_t sz);
char			*centered(char *str, uint64_t width);

#endif // UTILS_H
