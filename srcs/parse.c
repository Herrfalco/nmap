/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/12 14:59:20 by fcadet            #+#    #+#             */
/*   Updated: 2023/10/01 18:37:22 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../hdrs/parse.h"

static char		*FLAG_NAMES[] = {
	"help", "ports", "ip", "file", "speedup",
	"scan", "timeout", "tempo", "revert",
};

char		*SCAN_NAMES[] = {
	"SYN", "NULL", "ACK", "FIN", "XMAS", "UDP",
};

opts_t			OPTS = { 0 };

static uint8_t	OPT_EXCL[] = {
	F_PORTS | F_IP | F_FILE | F_SPEEDUP | F_SCAN,	// F_HELP
	F_HELP,											// F_PORTS
	F_HELP | F_FILE,								// F_IP
	F_HELP | F_IP,									// F_FILE
	F_HELP,											// F_SPEEDUP
	F_HELP,											// F_SCAN
	F_HELP,											// F_TIMEOUT
	F_HELP,											// F_TEMPO
	F_HELP,											// F_REVERT
};

static char		*parse_flag(char *arg, parse_fn_t *parse_fn);

void			parse_print(void *) {
	struct in_addr	ip = { 0 };
	uint64_t		i;
	uint16_t		lst;
	uint8_t			range = 0;
	char			buff[BUFF_SZ];

	sprintf(buff, "%-*s", TITLE_SZ, "IPs:");
	printf("    %s", buff);
	for (i = 0; i < OPTS.ip_nb; ++i) {
		ip.s_addr = OPTS.ips[i];
		sprintf(buff, "%*s", !!i * (TITLE_SZ + 4), "");
		printf("%s%s\n", buff, inet_ntoa(ip));
	}
	sprintf(buff, "%-*s", TITLE_SZ, "Ports:");
	printf("    %s%d", buff, (lst = *OPTS.ports));
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
	sprintf(buff, "%-*s", TITLE_SZ, "Scans:");
	printf("    %s", buff);
	for (i = 0; i < OPTS.scan_nb; ++i)
		printf("%s ", SCAN_NAMES[OPTS.scans[i]]);
	printf("\n");
	sprintf(buff, "%-*s", TITLE_SZ, "Speedup:");
	printf("    %s%ld threads\n", buff, OPTS.speedup);
	sprintf(buff, "%-*s", TITLE_SZ, "Timeout:");
	printf("    %s%ldms\n", buff, OPTS.timeout);
	sprintf(buff, "%-*s", TITLE_SZ, "Tempo:");
	printf("    %s%ldms\n", buff, OPTS.tempo);
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
	struct sockaddr_in	dst;
	char				dst_ip[INET_ADDRSTRLEN];
	struct addrinfo		*infos, hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_RAW,
		.ai_protocol = IPPROTO_IP,
	};
	in_addr_t			in_addr;

	if (!arg)
		return ("IP not specified");
	if ((in_addr = inet_addr(arg)) == INADDR_NONE) {
		if (!getaddrinfo(arg, NULL, &hints, &infos)) {
			dst = *((struct sockaddr_in *)infos->ai_addr);
			inet_ntop(AF_INET, &dst.sin_addr, dst_ip, INET_ADDRSTRLEN);
			in_addr = inet_addr(dst_ip);
		}
	}
	return ((OPTS.ips[OPTS.ip_nb++] = in_addr) == INADDR_NONE
		? "Invalip IP address" : NULL);


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
		if (OPTS.speedup > MAX_THRDS)
			return ("Speedup is too big");
	}
	return (*arg ? "Invalid speedup" : NULL);
}

static char		*parse_timeout(char *arg) {
	if (!arg)
		return ("Timeout not specified");
	for (; *arg >= '0' && *arg <= '9'; ++arg) {
		OPTS.timeout *= 10;
		OPTS.timeout += *arg - '0';
		if (OPTS.timeout >= MAX_TIMEOUT)
			return ("Timeout is too big");
	}
	return (*arg ? "Invalid timeout" : NULL);
}

static char		*parse_tempo(char *arg) {
	if (!arg)
		return ("Temporization not specified");
	for (; *arg >= '0' && *arg <= '9'; ++arg) {
		OPTS.tempo *= 10;
		OPTS.tempo += *arg - '0';
		if (OPTS.tempo >= MAX_TEMPO)
			return ("Temporization is too big");
	}
	return (*arg ? "Invalid temporization" : NULL);
}


static uint8_t	scan_idx(scan_t scan) {
	uint8_t		i;

	for (i = 0; i < OPTS.scan_nb; ++i)
		if (OPTS.scans[i] == scan)
			break;
	return (i);
}

static uint8_t	scan_set(scan_t scan) {
	return (scan_idx(scan) != OPTS.scan_nb);
}

static char		*parse_scan_name(char *arg) {
	uint64_t		i;

	for (i = 0; i < SCANS_NB; ++i)
		if (!str_cmp(SCAN_NAMES[i], arg))
			break;
	if (i == SCANS_NB)
		return ("Invalid scan type");
	else if (scan_set(i))
		return ("Scan type duplicate");
	OPTS.scans[OPTS.scan_nb++] = i;
	return (NULL);
}

static char		*parse_scan(char *arg) {
	uint64_t		i;
	char			*error;

	if (!arg)
		return ("Scan type not specified");
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
		parse_timeout,
		parse_tempo,
		NULL,
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
	if ((error = parse_fn ? parse_fn(NULL) : NULL))
		return (error);
	return (OPTS.ip_nb || OPTS.flag & F_HELP ? NULL : "No IP specified");
}

static char		*disp_help(char *err) {
	static char		buff[BUFF_SZ * 2] = { 0 },
					*title = "FT_NMAP v1.3 - 42 Paris's project, by fcadet & apitoise (09/2023)",
					*help = "Usage:    ft_nmap [--ip IP] or [--file FILE] or [--help]\n\n"
							"Options:  --help       display help informations\n"
							"          --ports      ascending ports or range of ports (max 1024)\n"
							"                       (e.g. 1,10-12,17,19,20-30)\n"
							"          --ip         target IP address (IPV4)\n"
							"          --file       file containing a list of IP address (upto 512)\n"
							"          --speedup    number of aditionnal threads (upto 250))\n"
							"          --scan       scan types combined with a '+'\n"
							"                       (SYN, NULL, ACK, FIN, XMAS, UDP)\n"
							"          --timeout    time to wait for a response\n"
							"          --tempo      sending temporization\n"
							"          --revert     inverted result (not open)";

	snprintf(buff, BUFF_SZ * 2, "%s\n\n%s",
			err ? err : title, help);
	return (buff);
}

static void		init_ports(void) {
	for (OPTS.port_nb = 0; OPTS.port_nb < MAX_PORTS; ++OPTS.port_nb)
		OPTS.ports[OPTS.port_nb] = OPTS.port_nb + 1;
}

static void		init_scans(void) {
	for (OPTS.scan_nb = 0; OPTS.scan_nb < SCANS_NB; ++OPTS.scan_nb)
		OPTS.scans[OPTS.scan_nb] = OPTS.scan_nb;
}

char			*parse(char **argv) {
	char		*error;

	if ((error = parse_args(++argv)))
		return (disp_help(error));
	else if (OPTS.flag & F_HELP) {
		printf("%s\n", disp_help(NULL));
		exit(0);
	}
	if (!(OPTS.flag & F_PORTS))
		init_ports();
	if (!(OPTS.flag & F_TIMEOUT))
		OPTS.timeout = DEF_TIMEOUT;
	if (!(OPTS.flag & F_TEMPO))
		OPTS.tempo = DEF_TEMPO;
	if (!(OPTS.flag & F_SCAN))
		init_scans();
	return (NULL);
}

uint16_t			scan_2_port(scan_t scan) {
	return (SRC_PORT + scan_idx(scan));
}

scan_t				port_2_scan(uint16_t port) {
	return (OPTS.scans[port - SRC_PORT]);
}
