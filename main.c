/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/07 15:57:25 by fcadet            #+#    #+#             */
/*   Updated: 2023/08/08 19:03:00 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#define				MIN_PORT	1
#define				MAX_PORT	1025
#define				MAX_IPS		512
#define				MAX_IP_SZ	15
#define				FILE_SZ		((MAX_IP_SZ + 1) * MAX_IPS)
#define				MAX_THRDS	251
#define				FLAGS_NB	6
#define				SCANS_NB	6

char		*FLAG_NAMES[] = {
	"help", "ports", "ip", "file", "speedup", "scan",
};

char		*SCAN_NAMES[] = {
	"SYN", "NULL", "ACK", "FIN", "XMAX", "UDP",
};

typedef enum		flag_e {
	F_HELP = 0x1,
	F_PORTS = 0x2,
	F_IP = 0x4,
	F_FILE = 0x8,
	F_SPEEDUP = 0x10,
	F_SCAN = 0x20,
}					flag_t;

typedef enum		scan_e {
	ST_SYN = 0x1,
	ST_NULL = 0x2,
	ST_ACK = 0x4,
	ST_FIN = 0x8,
	ST_XMAS = 0x10,
	ST_UDP = 0x20,
}					scan_t;

typedef struct		opts_s {
	uint16_t		ports[2];
	in_addr_t		ips[MAX_IPS];
	uint64_t		ip_nb;
	uint8_t			speedup;
	uint8_t			scan;
	uint8_t			flag;
}					opts_t;

opts_t		OPTS = { 
	.ports = { 1, 1024 },
	.ips = { 0 },
	.ip_nb = 0,
	.speedup = 0,
	.scan = ST_SYN,
};

/*
uint8_t		OPT_EXCL[] = {
	F_PORTS | F_IP | F_FILE | F_SPEEDUP | F_SCAN,	// F_HELP
	F_HELP,											// F_PORTS
	F_HELP | F_FILE,								// F_IP
	F_HELP | F_IP,									// F_FILE
	F_HELP,											// F_SPEEDUP
	F_HELP,											// F_SCAN
};
*/

uint8_t		OPT_EXCL[] = {
	0,				// F_HELP
	0,				// F_PORTS
	0 | F_FILE,		// F_IP
	0 | F_IP,		// F_FILE
	0,				// F_SPEEDUP
	0,				// F_SCAN
};

typedef int			(*parse_fn_t)(char *);

int				parse_flag(char *arg, parse_fn_t *parse_fn);

int				str_n_cmp(char *s1, char *s2, uint64_t n) {
	for (; n && *s1 && *s1 == *s2; --n, ++s1, ++s2);
	return (n ? *s1 - *s2 : 0);
}

int				str_cmp(char *s1, char *s2) {
	for (; *s1 && *s1 == *s2; ++s1, ++s2);
	return (*s1 - *s2);
}

void			print_opts(void) {
	struct in_addr	ip = { 0 };
	uint64_t		i;

	printf("help: %s\n", OPTS.flag & F_HELP ? "true" : "false");
	printf("ports: %d-%d\n", OPTS.ports[0], OPTS.ports[1]);
	printf("ips: ");
	for (i = 0; i < OPTS.ip_nb; ++i) {
		ip.s_addr = OPTS.ips[i];
		printf("%s%s\n", i ? "     " : "", inet_ntoa(ip));
	}
	printf("%sspeedup: %d\n", i ? "" : "\n", OPTS.speedup);
	printf("scan: ");
	for (i = 0; i < FLAGS_NB; ++i)
		if (OPTS.scan & (1 << i))
			printf("%s ", SCAN_NAMES[i]);
	printf("\b \n");
}

int				parse_ports(char *arg) {
	uint8_t		i;

	if (!arg)
		return (-1);
	OPTS.ports[0] = 0;
	OPTS.ports[1] = 0;
	for (i = 0; i < 2; ++i, ++arg) {
		for (; *arg >= '0' && *arg <= '9'; ++arg) {
			OPTS.ports[i] *= 10;
			OPTS.ports[i] += *arg - '0';
		}
		if (!*arg) {
			if (!i)
				OPTS.ports[1] = OPTS.ports[0] + 1;
			return (0);
		} else if (!i && *arg != '-')
			break;
	}
	return (-1);
}

int				parse_ip(char *arg) {
	if (!arg)
		return (-1);
	return ((OPTS.ips[OPTS.ip_nb++] = inet_addr(arg)) == INADDR_NONE);
}

int				parse_file(char *arg) {
	char		buff[FILE_SZ + 1] = { 0 };
	int64_t		sz;
	uint16_t	i;
	int			fd;

	if (!arg || (fd = open(arg, O_RDONLY)) < 0)
		return (-1);
	if ((sz = read(fd, buff, FILE_SZ)) < 0) {
		close(fd);
		return (-1);
	}
	for (i = 0; i < sz && OPTS.ip_nb < MAX_IPS; ++OPTS.ip_nb) {
		if ((OPTS.ips[OPTS.ip_nb] = inet_addr(buff + i)) == INADDR_NONE) {
			close(fd);
			return (-1);
		}
		for (; i < sz && buff[i] != '\n'; ++i);
		++i;
	}
	close(fd);
	return (0);
}

int				parse_speedup(char *arg) {
	if (!arg)
		return (-1);
	for (; *arg >= '0' && *arg <= '9'; ++arg) {
		OPTS.speedup *= 10;
		OPTS.speedup += *arg - '0';
	}
	return (!!*arg);
}

static int		parse_scan_name(char *arg) {
	uint8_t			scan;
	uint64_t		i;

	for (i = 0; i < SCANS_NB; ++i)
		if (!str_cmp(SCAN_NAMES[i], arg))
			break;
	scan = 1 << i;
	if (i == SCANS_NB || (scan & OPTS.scan))
		return (-1);
	OPTS.scan |= scan;
	return (0);
}

int				parse_scan(char *arg) {
	uint64_t		i;

	if (!arg)
		return (-1);
	OPTS.scan = 0;
	for (i = 0; arg[i]; ++i) {
		if (arg[i] == '+') {
			arg[i] = '\0';
			if (parse_scan_name(arg))
				return (-1);
			arg += i + 1;
			i = 0;
		}
	}
	return (parse_scan_name(arg));
}

int				parse_flag(char *arg, parse_fn_t *parse_fn) {
	parse_fn_t	parse_fns[] = {
		NULL,
		parse_ports,
		parse_ip,
		parse_file,
		parse_speedup,
		parse_scan,
	};
	flag_t		flag;
	uint8_t		i;
	
	if (str_n_cmp(arg, "--", 2))
		return (-1);
	arg += 2;
	for (i = 0; i < FLAGS_NB; ++i) {
		if (!str_cmp(FLAG_NAMES[i], arg)) {
			flag = 1 << i;
			if (OPTS.flag & (OPT_EXCL[i] | flag))
				return (-1);
			OPTS.flag |= flag;
			*parse_fn = parse_fns[i];
			return (0);
		}
	}
	return (-1);
}

int				parse_args(char **argv) {
	parse_fn_t		parse_fn;

	for (parse_fn = NULL; *argv; ++argv) {
		if (!parse_fn) {
			if (parse_flag(*argv, &parse_fn))
				return (-1);
		} else if (parse_fn(*argv))
			return (-1);
		else
			parse_fn = NULL;
	}
	return (!!parse_fn);
}

int				parse_check(void) {
	return (OPTS.ports[0] < 1
		|| OPTS.ports[0] >= OPTS.ports[1]
		|| OPTS.ports[1] > 1024
		|| !OPTS.ip_nb);
}

int			main(int, char **argv) {
	if (parse_args(++argv) || parse_check()) {
		printf("parsing error\n");
		return (1);
	}
	print_opts();
	return (0);
}
