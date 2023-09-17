/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/07 15:57:25 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/18 00:29:36 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "thrds.h"

int		main(int, char **argv) {
//	data_t		data = { 0 };
//	uint64_t	i, j;
	char		*err;

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
	if ((err = thrds_spawn())) {
		fprintf(stderr, "Error: %s\n", err);
		return (4);
	}
	while (42);
	return (0);
}
