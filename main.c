/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/07 15:57:25 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/22 18:07:13 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "thrds.h"

int		main(int, char **argv) {
	uint64_t		i;
	char			*err;
	struct timeval	start, end;

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
	if ((err = thrds_spawn())) {
		fprintf(stderr, "Error: %s\n", err);
		return (5);
	}
	for (i = 0; i < OPTS.speedup; ++i)
		pthread_join(THRDS[i].thrd, NULL);
	if (gettimeofday(&end, NULL))
		return (4);
	printf("Scan time: %ld.%ld\n", end.tv_sec - start.tv_sec,
	((end.tv_sec * 1000 + end.tv_usec) - (start.tv_usec * 1000 + start.tv_usec)) % 1000);
	result_print();
	return (0);
}
