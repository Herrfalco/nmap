#include "includes.h"

pthread_mutex_t		mutex = PTHREAD_MUTEX_INITIALIZER;

typedef	struct			thrd_data_s {
	pthread_t			thrd;
	int					id;
	struct bpf_program	fp;
	char				*filter;
}						thrd_data_t;

typedef void *(*thrd_fn)(void *);

void	print_mutex(int id, char *str, char *info) {
	pthread_mutex_lock(&mutex);
	printf("%d: %s", id, str);
	if (info)
		printf("%s", info);
	printf("\n");
	pthread_mutex_unlock(&mutex);
}

void	cap_handler(uint8_t *data, const struct pcap_pkthdr *pkt_hdr, const uint8_t *pkt) {
	const struct ether_header	*ethh = (const struct ether_header *)pkt;
	const struct iphdr			*iph = (const struct iphdr *)(ethh + 1);
	const struct tcphdr			*tcph = { 0 };
	const struct icmphdr		*icmph = { 0 };
	char						ip_src[INET_ADDRSTRLEN];

	(void)pkt_hdr;
	printf("%d: OK\n", ((thrd_data_t *)data)->id);
}

void	*thrds_handler(thrd_data_t *arg) {
	pcap_t	*cap;
	char	buff_err[PCAP_ERRBUF_SIZE];

	print_mutex(arg->id, "created", NULL);
	if (!(cap = pcap_open_live("lo", PCAP_SNAPLEN_MAX,
								0, PCAP_TIME_OUT, buff_err))) {
		print_mutex(arg->id, "pcap_open_live failed: ", buff_err);
		pthread_exit(NULL);
	}
	print_mutex(arg->id, "cap opened", NULL);
	if (pcap_compile(cap, &arg->fp, arg->filter, 1, PCAP_NETMASK_UNKNOWN)) {
		print_mutex(arg->id, "pcap_compile failed", NULL);
		pthread_exit(NULL);
	}
	if (pcap_setfilter(cap, &arg->fp)) {
		print_mutex(arg->id, "pcap_setfilter failed", NULL);
		pthread_exit(NULL);
	}
	while (42) {
		if (pcap_dispatch(cap, 0, cap_handler, (uint8_t *)arg) == PCAP_ERROR) {
			print_mutex(arg->id, "pcap_dispatch failed", pcap_geterr(cap));
			pthread_exit(NULL);
		}
	}
	print_mutex(arg->id, "filters sets", NULL);
}

int		main(void) {
	thrd_data_t	one = { .id = 1, .filter = "src port 777" }, two = { .id = 2, .filter = "src port 666" };

	if (pthread_create(&one.thrd, NULL, (thrd_fn)thrds_handler, &one)) {
		fprintf(stderr, "one error\n");
		return (0);
	}
	if (pthread_create(&two.thrd, NULL, (thrd_fn)thrds_handler, &two)) {
		fprintf(stderr, "one error\n");
		return (0);
	}
	pthread_join(one.thrd, 0);
	pthread_join(two.thrd, 0);
	pthread_mutex_destroy(&mutex);
	return (0);
}
