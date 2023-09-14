/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   filter.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/09 16:37:22 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/14 17:59:41 by fcadet           ###   ########.fr       */
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
	uint64_t	scan_nb = bit_set(OPTS.scan),
				s = job->idx % scan_nb,
				p = job->idx / scan_nb % OPTS.port_nb,
				i = job->idx / scan_nb / OPTS.port_nb,
				max = job->idx + job->nb;
	uint8_t		stop = 0;
	char		*err, buff[BUFF_SZ];

	if (!job->nb)
		return (NULL);
	for (; !stop && i < OPTS.ip_nb; ++i, p = 0) {
		if ((err = filt_add(filt, "(src host "))
				|| (err = filt_add(filt, inet_ntoa(*(struct in_addr *)&OPTS.ips[i])))
				|| (err = filt_add(filt, " and (")))
			return (err);
		for (; !stop && p < OPTS.port_nb; ++p, s = 0) {
			if (i * OPTS.port_nb + p * scan_nb + s >= max) {
				stop = 1;
				break;
			}
			sprintf(buff, "%u", OPTS.ports[p]);
			if ((err = filt_add(filt, "(src port "))
					|| (err = filt_add(filt, buff))
					|| (err = filt_add(filt, " and (")))
				return (err);
			for (; s < scan_nb; ++s) {
				if (i * OPTS.port_nb + p * scan_nb + s >= max) {
					stop = 1;
					break;
				}
				sprintf(buff, "%u", SRC_PORT
						+ idx_2_scan(OPTS.scan, ST_SYN, ST_MAX, s));
				if ((err = filt_add(filt, "dst port "))
						|| (err = filt_add(filt, buff))
						|| (err = filt_add(filt, " or ")))
					return (err);
			}
			filt->sz -= 4;
			if ((err = filt_add(filt, ")) or ")))
				return (err);
		}
		filt->sz -= 4;
		if ((err = filt_add(filt, ")) or ")))
			return (err);
	}
	filt->sz -= 4;
	filt->data[filt->sz] = '\0';
	return (NULL);
}
/*
char				*filter_init(filt_t *filt, job_t *job) {
	uint64_t	i = job->idx / OPTS.port_nb,
				j = job->idx % OPTS.port_nb,
				max = job->idx + job->nb;
	uint16_t	start;
	char		*err, buff[BUFF_SZ];
	uint8_t		range = 0, stop = 0;

	filt->data = NULL;
	filt->sz = 0;
	if (!job->nb)
		return (NULL);
	for (;i < OPTS.ip_nb && !stop; ++i, j = 0) {
		if ((err = filt_add(filt, "(src host "))
				|| (err = filt_add(filt, inet_ntoa(*(struct in_addr *)&OPTS.ips[i])))
				|| (err = filt_add(filt, " and (")))
			return (err);
		for (; !stop && j < OPTS.port_nb; ++j) {
			if ((i * OPTS.port_nb + j) >= max - 1)
				stop = 1;
			if (stop || j + 1 >= OPTS.port_nb || OPTS.ports[j + 1] - OPTS.ports[j] > 1) {
				if (range)
					sprintf(buff, "(src portrange %d-%d) or ", start, OPTS.ports[j]);
				else
					sprintf(buff, "(src port %d) or ", OPTS.ports[j]);
				if ((err = filt_add(filt, buff)))
					return (err);
				range = 0;
			} else if (!range) {
				start = OPTS.ports[j];
				range = 1;
			}
		}
		if ((err = filt_add(filt, "icmp)) or ")))
			return (err);
	}
	filt->sz -= 4;
	filt->data[filt->sz] = '\0';
	return (NULL);
}
*/
void			filter_print(filt_t *filt) {
	printf("%s", filt->data);
}

void			filter_destroy(filt_t *filt) {
	if (filt->data)
		free(filt->data);
}
