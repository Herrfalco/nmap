/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/07 15:57:25 by fcadet            #+#    #+#             */
/*   Updated: 2023/10/02 21:24:49 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../hdrs/thrds.h"

int		main(int, char **argv) {
	uint64_t		i;
	char			*err, buff[BUFF_SZ] = { 0 };
	uint8_t			error = 0;
	struct timeval	start, end;
	uint64_t		ms;

	if ((err = handle_sig()))
		return (print_main_error(err, 1));
	if (getuid())
		return (print_main_error("ft_nmap must be run with sudo", 2));
	if ((err = parse(argv)))
		return (print_main_error(err, 3));
	printf("\n%s\n", char_line('.', LINE_SZ / 2));
	printf("%s\n", centered("FT_NMAP", LINE_SZ / 2));
	printf("%s\n", char_line('.', LINE_SZ / 2));
	printf("Configuration:\n");
	parse_print(NULL);
	if ((err = local_init()))
		return (print_main_error(err, 4));
	printf("%s\n", char_line('.', LINE_SZ / 2));
	printf("Network:\n");
	local_print(NULL);
	printf("%s\n", char_line('.', LINE_SZ / 2));
	if ((err = thrds_init()))
		return (print_main_error(err, 5));
	if (gettimeofday(&start, NULL)) {
		thrds_fini();
		return (print_main_error(strerror(errno), 7));
	}
	result_init();
	err = thrds_spawn();
	for (i = 0; i < OPTS.speedup; ++i)
		pthread_join(THRDS[i].thrd, NULL);
	for (i = 0; i < OPTS.speedup; ++i) {
		if (THRDS[i].err_ptr || *THRDS[i].err_buff) {
			error = 1;
			fprintf(stderr, "Error: Thread n.%ld: %s\n", i,
					THRDS[i].err_ptr ? THRDS[i].err_ptr : THRDS[i].err_buff);
		}
	}
	thrds_fini();
	if (err)
		return (print_main_error(err, 10));
	else if (error)
		return (print_main_error("Thread failure detected", 11));
	if (!sig_catch() || result_complete()) {
		if (gettimeofday(&end, NULL))
			return (print_main_error("Can't get current time", 8));
		ms = (end.tv_sec - start.tv_sec) * 1000
			+ (end.tv_usec - start.tv_usec) / 1000;
		sprintf(buff, ">> Scan duration: %ld.%03lds <<",
				ms / 1000, ms % 1000);
		printf("%s\n", centered(buff, LINE_SZ / 2));
		printf("%s\n", char_line('.', LINE_SZ / 2));
		result_print();
	}
	return (0);
}
