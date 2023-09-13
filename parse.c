/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/12 14:59:20 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/12 15:05:33 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "parse.h"

static char		*FLAG_NAMES[] = {
	"help", "ports", "ip", "file", "speedup", "scan",
};

static char		*SCAN_NAMES[] = {
	"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP",
};

opts_t			OPTS = { 
	.ports = { 0 },
	.port_nb = 0,
	.ips = { 0 },
	.ip_nb = 0,
	.speedup = 0,
	.scan = ST_ALL,
};

static uint8_t	OPT_EXCL[] = {
	F_PORTS | F_IP | F_FILE | F_SPEEDUP | F_SCAN,	// F_HELP
	F_HELP,											// F_PORTS
	F_HELP | F_FILE,								// F_IP
	F_HELP | F_IP,									// F_FILE
	F_HELP,											// F_SPEEDUP
	F_HELP,											// F_SCAN
};

static char		*parse_flag(char *arg, parse_fn_t *parse_fn);

void			parse_print(void *) {
	struct in_addr	ip = { 0 };
	uint64_t		i;
	uint16_t		lst;
	uint8_t			range = 0;

	printf("help: %s\n", OPTS.flag & F_HELP ? "true" : "false");
	printf("ports: %d", (lst = *OPTS.ports));
	for (i = 1; i < OPTS.port_nb; lst = OPTS.ports[i], ++i) {
		if (OPTS.ports[i] - lst > 1) {
			if (range)
				printf("-%d,%d", lst, OPTS.ports[i]);
			else
				printf(",%d", OPTS.ports[i]);
			range = 0;
		} else
			range = 1;
	}
	if (range)
		printf("-%d", lst);
	printf(" (%ld ports)\n", OPTS.port_nb);
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

static char		*save_port(uint32_t start, uint32_t end, uint8_t num, uint8_t range) {
	if (!num)
		return ("Invalid port");
	if (range) {
		if (end <= start)
			return ("Invalid port range");
	} else
		start = end;
	if (OPTS.port_nb && start <= OPTS.ports[OPTS.port_nb - 1])
		return ("Not ascending ports");
	if (OPTS.port_nb + (end + 1 - start) > MAX_PORTS)
		return ("Invalid number of ports");
	for (; start <= end; ++start)
		OPTS.ports[OPTS.port_nb++] = start;
	return (NULL);
}

static char		*parse_ports(char *arg) {
	uint8_t		num, range;
	uint32_t	start, end;
	char		*error;

	if (!arg)
		return ("Ports not specified");
	for (start = 0, end = 0, num = 0, range = 0; *arg; ++arg) {
		if (*arg >= '0' && *arg <= '9') {
			end *= 10;
			end += *arg - '0';
			if (end > MAX_PORT_VAL)
				return ("Invalid port value");
			num = 1;
		} else if (*arg == '-') {
			if (range || !num)
				return ("Invalid port range");
			start = end;
			end = 0;
			range = 1;
			num = 0;
		} else if (*arg == ',') {
			if ((error = save_port(start, end, num, range)))
				return (error);
			end = 0;
			range = 0;
			num = 0;
		} else
			return ("Invalid delimiter in ports option");
	}
	return (save_port(start, end, num, range));
}

static char		*parse_ip(char *arg) {
	if (!arg)
		return ("IP not specified");
	return ((OPTS.ips[OPTS.ip_nb++] = inet_addr(arg)) == INADDR_NONE
			? "Invalid IP" : NULL);
}

static char		*parse_file(char *arg) {
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

static char		*parse_speedup(char *arg) {
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

static char		*parse_scan(char *arg) {
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

static char		*parse_flag(char *arg, parse_fn_t *parse_fn) {
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

static char		*parse_args(char **argv) {
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

static char		*parse_check(void) {
	if (OPTS.speedup > MAX_THRDS)
		return ("Invalid speedup value (max 250)");
	return (OPTS.ip_nb || OPTS.flag & F_HELP ? NULL : "No IP specified");
}

static char		*disp_help(char *err) {
	static char		buff[BUFF_SZ * 2] = { 0 },
					*title = "FT_NMAP v1.0 - 42 Paris's project, by fcadet & apitoise (9/2023)",
					*help = "Usage:    ft_nmap [--ip IP] or [--file FILE] or [--help]\n\n"
							"Options:  --help       display help informations\n"
							"          --ports      ascending ports or range of ports (max 1024)\n"
							"						(e.g. 1,10-12,17,19,20-30)\n"
							"          --ip         target IP address (IPV4)\n"
							"          --file       file containing a list of IP address (upto 512)\n"
							"          --speedup    number of aditionnal threads (upto 250))\n"
							"          --scan       scan types combined with a '+'\n"
							"                       (SYN, NULL, ACK, FIN, XMAS, UDP)\n";

	snprintf(buff, BUFF_SZ * 2, "%s\n\n%s",
			err ? err : title, help);
	return (buff);
}

static void		init_ports(void) {
	for (OPTS.port_nb = 0; OPTS.port_nb < MAX_PORTS; ++OPTS.port_nb)
		OPTS.ports[OPTS.port_nb] = OPTS.port_nb + 1;
}

char			*parse(char **argv) {
	char		*error;

	if ((error = parse_args(++argv))
			|| (error = parse_check())) {
		return (disp_help(error));
	} else if (OPTS.flag & F_HELP) {
		printf("%s\n", disp_help(NULL));
		return (NULL);
	} else if (!(OPTS.flag & F_PORTS))
		init_ports();
	return (NULL);
}
