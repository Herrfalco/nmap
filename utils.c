/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/12 15:00:11 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/14 19:17:47 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "includes.h"

void			print_error(char *str) {
	fprintf(stderr, "%s\n", str);
}

int				str_n_cmp(char *s1, char *s2, uint64_t n) {
	for (; n && *s1 && *s1 == *s2; --n, ++s1, ++s2);
	return (n ? *s1 - *s2 : 0);
}

int				str_cmp(char *s1, char *s2) {
	for (; *s1 && *s1 == *s2; ++s1, ++s2);
	return (*s1 - *s2);
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

uint8_t			idx_2_scan(uint8_t scans, uint8_t min, uint8_t max, uint8_t idx) {
	uint8_t		s;

	for (s = min; s < max; s <<= 1) {
		if (scans & s) {
			if (!idx)
				return (s);
			--idx;
		}
	}
	return (0);
}
