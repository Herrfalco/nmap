/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/12 15:00:11 by fcadet            #+#    #+#             */
/*   Updated: 2023/10/01 18:17:57 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../hdrs/includes.h"

int				print_main_error(char *str, int ret) {
	fprintf(stderr, "Error: %s\n", str);
	return (ret);
}

void			str_n_cpy(char *dst, char *src, uint64_t n) {
	for (; n && *src; --n, ++dst, ++src)
		*dst = *src;
	if (n)
		*dst = '\0';
	else
		dst[n] = '\0';
}

void			str_cpy(char *dst, char *src) {
	for (; *src; ++dst, ++src)
		*dst = *src;
	*dst = '\0';
}

int				str_n_cmp(char *s1, char *s2, uint64_t n) {
	for (; n && *s1 && *s1 == *s2; --n, ++s1, ++s2);
	return (n ? *s1 - *s2 : 0);
}

int				str_cmp(char *s1, char *s2) {
	for (; *s1 && *s1 == *s2; ++s1, ++s2);
	return (*s1 - *s2);
}

uint64_t		str_len(char *s) {
	uint64_t		i;

	for (i = 0; s[i]; ++i);
	return (i);
}

uint8_t			bit_set(uint8_t byte) {
	return ((byte & 0x1)
		+ ((byte >> 1) & 0x1)
		+ ((byte >> 2) & 0x1)
		+ ((byte >> 3) & 0x1)
		+ ((byte >> 4) & 0x1)
		+ ((byte >> 5) & 0x1)
		+ ((byte >> 6) & 0x1)
		+ ((byte >> 7) & 0x1));
}

uint8_t			is_elapsed(struct timeval *tv_start, struct timeval *tv_cur, time_t delta) {
	return (((tv_cur->tv_sec - tv_start->tv_sec) * 1000
		+ (tv_cur->tv_usec - tv_start->tv_usec) / 1000) >= delta);
}

char			*char_line(char c, uint64_t sz) {
	static char		buff[BUFF_SZ];
	uint64_t		i;

	for (i = 0; i < sz; ++i)
		buff[i] = c;
	buff[i] = '\0';
	return (buff);
}

char			*centered(char *str, uint64_t width) {
	static char		buff[BUFF_SZ];
	uint64_t		len = str_len(str), pad = (width - len) / 2;

	sprintf(buff, "%s%s%s", char_line(' ', pad),
			str, char_line(' ', width - (pad + len)));
	return (buff);
}
