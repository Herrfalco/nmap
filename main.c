/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/07 15:57:25 by fcadet            #+#    #+#             */
/*   Updated: 2023/08/09 16:39:58 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#define				MAX_PORTS	1024
#define				MAX_IPS		512
#define				MAX_IP_SZ	15
#define				FILE_SZ		((MAX_IP_SZ + 1) * MAX_IPS)
#define				MAX_THRDS	250
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
	ST_XMAX = 0x10,
	ST_UDP = 0x20,
	ST_ALL = 0x3f,
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
	.scan = ST_ALL,
};

uint8_t		OPT_EXCL[] = {
	F_PORTS | F_IP | F_FILE | F_SPEEDUP | F_SCAN,	// F_HELP
	F_HELP,											// F_PORTS
	F_HELP | F_FILE,								// F_IP
	F_HELP | F_IP,									// F_FILE
	F_HELP,											// F_SPEEDUP
	F_HELP,											// F_SCAN
};

typedef char		*(*parse_fn_t)(char *);

char			*parse_flag(char *arg, parse_fn_t *parse_fn);

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

char			*parse_ports(char *arg) {
	uint8_t		i;

	if (!arg)
		return ("Ports not specified");
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
			return (NULL);
		} else if (!i && *arg != '-')
			break;
	}
	return ("Invalid ports");
}

char			*parse_ip(char *arg) {
	if (!arg)
		return ("IP not specified");
	return ((OPTS.ips[OPTS.ip_nb++] = inet_addr(arg)) == INADDR_NONE
			? "Invalid IP" : NULL);
}

char			*parse_file(char *arg) {
	char		buff[FILE_SZ + 1] = { 0 };
	int64_t		sz;
	uint16_t	i;
	int			fd;

	if (!arg)
		return ("IP file not specified");
	else if ((fd = open(arg, O_RDONLY)) < 0)
		return ("Can't open IP file");
	else if ((sz = read(fd, buff, FILE_SZ)) < 0) {
		close(fd);
		return ("Can't read IP file");
	}
	for (i = 0; i < sz && OPTS.ip_nb < MAX_IPS; ++OPTS.ip_nb) {
		if ((OPTS.ips[OPTS.ip_nb] = inet_addr(buff + i)) == INADDR_NONE) {
			close(fd);
			return ("Invalid IP file");
		}
		for (; i < sz && buff[i] != '\n'; ++i);
		++i;
	}
	close(fd);
	return (NULL);
}

char			*parse_speedup(char *arg) {
	if (!arg)
		return ("Speedup not specified");
	for (; *arg >= '0' && *arg <= '9'; ++arg) {
		OPTS.speedup *= 10;
		OPTS.speedup += *arg - '0';
	}
	return (*arg ? "Invalid speedup" : NULL);
}

static char		*parse_scan_name(char *arg) {
	uint8_t			scan;
	uint64_t		i;

	for (i = 0; i < SCANS_NB; ++i)
		if (!str_cmp(SCAN_NAMES[i], arg))
			break;
	scan = 1 << i;
	if (i == SCANS_NB)
		return ("Invalid scan type");
	else if (scan & OPTS.scan)
		return ("Scan type duplicate");
	OPTS.scan |= scan;
	return (NULL);
}

char			*parse_scan(char *arg) {
	uint64_t		i;
	char			*error;

	if (!arg)
		return ("Scan type not specified");
	OPTS.scan = 0;
	for (i = 0; arg[i]; ++i) {
		if (arg[i] == '+') {
			arg[i] = '\0';
			if ((error = parse_scan_name(arg)))
				return (error);
			arg += i + 1;
			i = 0;
		}
	}
	return (parse_scan_name(arg));
}

char			*parse_flag(char *arg, parse_fn_t *parse_fn) {
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
		return ("Invalid argument");
	arg += 2;
	for (i = 0; i < FLAGS_NB; ++i) {
		if (!str_cmp(FLAG_NAMES[i], arg)) {
			flag = 1 << i;
			if (OPTS.flag & OPT_EXCL[i])
				return ("Incompatible options");
			else if (OPTS.flag & flag)
				return ("Option duplicate");
			OPTS.flag |= flag;
			*parse_fn = parse_fns[i];
			return (NULL);
		}
	}
	return ("Unrecognized option");
}

char			*parse_args(char **argv) {
	parse_fn_t		parse_fn;
	char			*error;

	for (parse_fn = NULL; *argv; ++argv) {
		if (!parse_fn) {
			if ((error = parse_flag(*argv, &parse_fn)))
				return (error);
		} else if ((error = parse_fn(*argv)))
			return (error);
		else
			parse_fn = NULL;
	}
	return (parse_fn ? parse_fn(NULL) : NULL);
}

char			*parse_check(void) {
	if (OPTS.ports[0] >= OPTS.ports[1] || OPTS.ports[1] - OPTS.ports[0] > MAX_PORTS)
		return ("Unvalid ports");
	else if (OPTS.speedup > MAX_THRDS)
		return ("Invalid speedup value");
	return (OPTS.ip_nb || OPTS.flag & F_HELP ? NULL : "No IP specified");
}

uint8_t			disp_help(uint8_t error) {
	if (!error)
		printf("FT_NMAP v1.0 - 42 Paris's project, by fcadet & apitoise (9/2023)\n\n");
	printf(	"Usage:    ft_nmap [--ip IP] or [--file FILE] or [--help]\n\n"
			"Options:  --help       display help informations\n"
			"          --ports      port or a range of ports (upto 1024)\n"
			"          --ip         target IP address (IPV4)\n"
			"          --file       file containing a list of IP address (upto 512)\n"
			"          --speedup    number of aditionnal threads (upto 250))\n"
			"          --scan       scan types combined with a '+'\n"
			"                       (SYN, NULL, ACK, FIN, XMAX, UDP)\n");
	return (error);
}

int			main(int, char **argv) {
	char		*error;

	if ((error = parse_args(++argv))
			|| (error = parse_check())) {
		printf("Error:    %s\n\n", error);
		return (disp_help(1));
	}
	if (OPTS.flag & F_HELP) {
		return (disp_help(0));
	}
	print_opts();
	return (0);
}
