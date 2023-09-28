/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/07 15:57:25 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/28 10:02:18 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "thrds.h"

int		main(int, char **argv) {
	uint64_t		i;
	char			*err;
	uint8_t			error = 0;
	struct timeval	start, end;
	uint64_t		ms;

	if ((err = parse(argv))) {
		fprintf(stderr, "Error: %s\n", err);
		return (1);
	}
	parse_print(NULL);
	if ((err = local_init())) {
		fprintf(stderr, "Error: %s\n", err);
		return (2);
	}
	local_print(NULL);
	if ((err = thrds_init())) {
		fprintf(stderr, "Error: %s\n", err);
		return (3);
	}
	if (gettimeofday(&start, NULL))
		return (4);
	if (OPTS.speedup) {
		if ((err = thrds_spawn())) {
			fprintf(stderr, "Error: %s\n", err);
			return (5);
		}
		for (i = 0; i < OPTS.speedup; ++i)
			pthread_join(THRDS[i].thrd, NULL);
		for (i = 0; i < OPTS.speedup; ++i) {
			if (THRDS[i].err_ptr) {
				error = 1;
				fprintf(stderr, "Error: %s\n", THRDS[i].err_ptr);
			} else if (*THRDS[i].err_buff) {
				error = 1;
				fprintf(stderr, "Error: %s\n", THRDS[i].err_buff);
			}
		}
	} else {
		thrds_single();
		if (THRDS->err_ptr) {
			error = 1;
			fprintf(stderr, "Error: %s\n", THRDS->err_ptr);
		} else if (*THRDS->err_buff) {
			error = 1;
			fprintf(stderr, "Error: %s\n", THRDS->err_buff);
		}
	}
	if (error)
		return (5);
	if (gettimeofday(&end, NULL)) {
		fprintf(stderr, "Error: Can't get current time\n");
		return (6);
	}
	ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;
	printf("Scan time: %ld.%ld\n", ms / 1000, ms % 1000);
	result_print();
	return (0);
}
