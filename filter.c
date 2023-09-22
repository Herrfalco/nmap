/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   filter.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/09 16:37:22 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/22 09:25:28 by fcadet           ###   ########.fr       */
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
	uint64_t	s = job->idx % OPTS.scan_nb,
				p = job->idx / OPTS.scan_nb % OPTS.port_nb,
				i = job->idx / OPTS.scan_nb / OPTS.port_nb,
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
			if (i * OPTS.port_nb + p * OPTS.scan_nb + s >= max) {
				stop = 1;
				break;
			}
			sprintf(buff, "%u", OPTS.ports[p]);
			if ((err = filt_add(filt, "(src port "))
					|| (err = filt_add(filt, buff))
					|| (err = filt_add(filt, " and (")))
				return (err);
			for (; s < OPTS.scan_nb; ++s) {
				if (i * OPTS.port_nb + p * OPTS.scan_nb + s >= max) {
					stop = 1;
					break;
				}
				sprintf(buff, "%u", scan_2_port(OPTS.scans[i]));
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

void			filter_print(filt_t *filt) {
	printf("%s", filt->data);
}

void			filter_destroy(filt_t *filt) {
	if (filt->data)
		free(filt->data);
}
