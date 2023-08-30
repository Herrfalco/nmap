/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/07 15:57:25 by fcadet            #+#    #+#             */
/*   Updated: 2023/08/13 10:04:32 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "parse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define MIN_DYN_PORT		49152
#define MAX_DYN_PORT		65536
#define SOURCE_PORT			12345
#define DESTINATION_PORT	80
#define DESTINATION_IP 		"127.0.0.1"
#define DEF_WIN_SZ			5840

unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    unsigned long sum;
    unsigned short oddbyte;
    unsigned short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (unsigned short)~sum;

    return answer;
}

int		main() {
    int sockfd;
    char datagram[4096] = { 0 };
    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    struct sockaddr_in dest_addr;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd == -1) {
        perror("Socket error");
        return 1;
    }

    memset(datagram, 0, sizeof(datagram));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DESTINATION_PORT);
    dest_addr.sin_addr.s_addr = inet_addr(DESTINATION_IP);

    iph->version = 4; //ipv4
    iph->ihl = 5; // length of ip header in 32bit words (no options)
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr); // length of packet ip + tcp hdr
    iph->id = htons(54321); // ID need to relate on this for multithread ?
    iph->ttl = 255; // ttl max
    iph->protocol = IPPROTO_TCP; // TCP
    iph->saddr = inet_addr("192.168.1.2"); // Source IP address (need to be changed)
    iph->daddr = dest_addr.sin_addr.s_addr; // dst

    tcph->source = htons(SOURCE_PORT);
    tcph->dest = dest_addr.sin_port;
    tcph->doff = 5; // Data offset
    tcph->syn = 1; // SYN flag
    tcph->window = htons(DEF_WIN_SZ); // Maximum allowed window size
    tcph->check = 0; // Set to 0 before calculating checksum

    iph->check = calculate_checksum((unsigned short *)datagram, iph->tot_len);

    if (sendto(sockfd, datagram, iph->tot_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1) {
        perror("Sendto error");
        return 1;
    }

    printf("SYN packet sent.\n");

    close(sockfd);

    return 0;
}

int		main(int, char **argv) {
	return (parse(argv));
}
