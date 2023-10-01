/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   filter.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/09 16:37:22 by fcadet            #+#    #+#             */
/*   Updated: 2023/10/01 14:14:45 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../hdrs/filter.h"

static char			*filt_add(filt_t *filt, char *data) {
	uint64_t		len = str_len(data);
	char			*new;

	if (!(new = realloc(filt->data, (filt->sz + len + 1) * sizeof(char)))) {
		free(filt->data);
		filt->data = NULL;
		return ("Can't allocate memory for string extension");
	}
	str_cpy(new + filt->sz, data);
	filt->data = new;
	filt->sz += len;
	return (NULL);
}

char				*filter_init(filt_t *filt, job_t *job) {
	uint64_t	p = job->idx % OPTS.port_nb,
				i = job->idx / OPTS.port_nb,
				max = job->idx + job->nb;
	uint16_t	start;
	uint8_t		stop = 0, range = 0;
	char		*err, buff[BUFF_SZ];

	switch (job->nb) {
		case 0:
			return (NULL);
		case 1:
			sprintf(buff, "dst port %u and ", SRC_PORT);
			break;
		default:
			sprintf(buff, "dst portrange %u-%lu and ",
					SRC_PORT, SRC_PORT + OPTS.scan_nb - 1);
	}
	if ((err = filt_add(filt, buff)))
		return (err);
	for (; !stop && i < OPTS.ip_nb; ++i, p = 0) {
		sprintf(buff, "(src host %s and (", inet_ntoa(*(struct in_addr *)&OPTS.ips[i]) );
		if ((err = filt_add(filt, buff)))
			return (err);
		for (; !stop && p < OPTS.port_nb; ++p) {
			if ((i * OPTS.port_nb + p + 1) >= max)
				stop = 1;
			if (stop || p + 1 >= OPTS.port_nb || OPTS.ports[p + 1] - OPTS.ports[p] > 1) {
				if (range)
					sprintf(buff, "src portrange %d-%d or ", start, OPTS.ports[p]);
				else
					sprintf(buff, "src port %d or ", OPTS.ports[p]);
				if ((err = filt_add(filt, buff)))
					return (err);
				range = 0;
			} else if (!range) {
				start = OPTS.ports[p];
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

void			filter_print(filt_t *filt) {
	if (filt->data)
		printf("%s\n", filt->data);
}

void			filter_destroy(filt_t *filt) {
	if (filt->data)
		free(filt->data);
}
