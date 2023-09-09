/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   filter.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/09 16:37:22 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/09 18:35:19 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "filter.h"

static char			*str_add(str_t *str, char *data) {
	uint64_t		len = strlen(data);
	char			*new;

	if (!(new = realloc(str->data, (str->sz + len + 1) * sizeof(char))))
		return ("Can't allocate memory for string extension");
	strcpy(new + str->sz, data);
	str->data = new;
	str->sz += len;
	return (NULL);
}

void				filter_lst_destroy(filts_t *filts) {
	uint64_t		i;

	for (i = 0; i < filts->sz; ++i)
		free(filts->strs[i].data);
	free(filts->strs);
	filts->strs = NULL;
	filts->sz = 0;
}

static char			*filter_lst_alloc(filts_t *filts) {
	filts->sz = 0;
	if (!(filts->strs = malloc(sizeof(str_t) * OPTS.speedup)))
		return ("Fail to allocate memory for filter list");
	bzero(filts->strs, sizeof(str_t) * OPTS.speedup);
	return (NULL);
}

static char			*filter_add_ports(str_t *str, uint64_t *cnt, uint64_t *nb) {
	char			buff[BUFF_SZ], *err;
	uint16_t		start;
	uint8_t			range = 0;

	if ((err = str_add(str, "(")))
		return (err);
	for (; *nb && *cnt < OPTS.port_nb; ++*cnt, --*nb) {
		if (*nb <= 1 || *cnt + 1 >= OPTS.port_nb
				|| OPTS.ports[*cnt + 1] - OPTS.ports[*cnt] > 1) {
			if (range)
				sprintf(buff, "portrange %d-%d or ", start, OPTS.ports[*cnt]);
			else
				sprintf(buff, "port %d or ", OPTS.ports[*cnt]);
			if ((err = str_add(str, buff)))
				return (err);
			range = 0;
		} else if (!range) {
			start = OPTS.ports[*cnt];
			range = 1;
		}
	}
	str->sz -= 4;
	str->data[str->sz] = '\0';
	return (str_add(str, ")"));
}

static char			*filter_add_addr(str_t *str, uint64_t *cnt, uint64_t nb) {
	char			*err;

	if (!nb)
		return (NULL);
	while (nb) {
		if ((err = str_add(str, "(host "))
				|| (err = str_add(str, inet_ntoa(*(struct in_addr *)&OPTS.ips[*cnt])))
				|| (err = str_add(str, " and "))
				|| (err = filter_add_ports(str, cnt + 1, &nb)))
			return (err);
		if (cnt[1] == OPTS.port_nb) {
			cnt[1] = 0;
			++*cnt;
		}
		if (nb && (err = str_add(str, ") or ")))
			return (err);
	}
	return (str_add(str, ")"));
}

char				*filter_lst_init(filts_t *filts) {
	uint64_t	div, rem, cnt[2] = { 0 };
	char		*err;

	if (!OPTS.speedup) {
		filts->strs = NULL;
		filts->sz = 0;
		return (NULL);
	}
	if ((err = filter_lst_alloc(filts)))
		return (err);
	div = OPTS.ip_nb * OPTS.port_nb / OPTS.speedup;
	rem = OPTS.ip_nb * OPTS.port_nb % OPTS.speedup;
	for (; filts->sz < OPTS.speedup; ++filts->sz) {
		if ((err = filter_add_addr(filts->strs + filts->sz, cnt,
						div + !!rem))) {
			filter_lst_destroy(filts);
			return (err);
		}
		if (rem)
			--rem;
	}
	return (NULL);
}
