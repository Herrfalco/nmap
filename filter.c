/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   filter.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/09 16:37:22 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/12 14:52:31 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "filter.h"

static char			*filt_add(filt_t *filt, char *data) {
	uint64_t		len = strlen(data);
	char			*new;

	if (!(new = realloc(filt->data, (filt->sz + len + 1) * sizeof(char))))
		return ("Can't allocate memory for string extension");
	strcpy(new + filt->sz, data);
	filt->data = new;
	filt->sz += len;
	return (NULL);
}

char				*filter_init(filt_t *filt, job_t *job) {
	uint64_t	i = job->idx / OPTS.port_nb,
				j = job->idx % OPTS.port_nb;
	uint16_t	start;
	char		*err, buff[BUFF_SZ];
	uint8_t		range = 0;

	filt->data = NULL;
	filt->sz = 0;
	if (!job->nb)
		return (NULL);
	for (; (i * OPTS.port_nb + j) < job->idx + job->nb; ++i, j = 0) {
		if ((err = filt_add(filt, "(src host "))
				|| (err = filt_add(filt, inet_ntoa(*(struct in_addr *)&OPTS.ips[i])))
				|| (err = filt_add(filt, " and ")))
			return (err);
		for (; j < OPTS.port_nb && (i * OPTS.port_nb + j) < job->idx + job->nb; ++j) {
			if (i + 1 >= OPTS.port_nb || OPTS.ports[i + 1] - OPTS.ports[i] > 1) {
				if (range)
					sprintf(buff, "(src portrange %d-%d) or ", start, OPTS.ports[i]);
				else
					sprintf(buff, "(src port %d) or ", OPTS.ports[i]);
				if ((err = filt_add(filt, buff)))
					return (err);
				range = 0;
			} else if (!range) {
				start = OPTS.ports[i];
				range = 1;
			}
		}
		if ((err = filt_add(filt, "icmp) or ")))
			return (err);
	}
	filt->sz -= 4;
	filt->data[filt->sz] = '\0';
	return (filt_add(filt, ")"));
}

void			filter_destroy(filt_t *filt) {
	if (filt->data)
		free(filt->data);
}
