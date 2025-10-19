/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   traceroute.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/18 15:22:47 by mgama             #+#    #+#             */
/*   Updated: 2025/10/19 21:59:06 by mgama            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef TRACEROUTE_H
#define TRACEROUTE_H

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

#include <netdb.h>
#include <ifaddrs.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "verbose.h"

#define TR_PREFIX "ft_traceroute"

#define TR_DEFAULT_PROBES 3
#define TR_MAX_PROBES 255
#define TR_DEFAULT_FIRST_TTL 1
#define TR_MAX_FIRST_TTL 255
#define TR_MAX_TTL 255
#define TR_DEFAULT_TIMEOUT 5
#define TR_MAX_TIMEOUT 86400
#define TR_DEFAULT_BASE_PORT 33434
#define TR_MAX_PORT 65535
#define TR_DEFAULT_PACKET_LEN 40
#define TR_MAX_PACKET_LEN 2<<14

#define TR_PROTO_UDP	1
#define TR_PROTO_ICMP	2
#define TR_PROTO_TCP	3
#define TR_PROTO_GRE	4

#define TR_FLAG_VERBOSE 0x01

struct tr_params {
	uint8_t		flags;
	uint32_t	first_ttl;
	uint32_t	max_ttl;
	uint32_t	port;
	uint32_t	nprobes;
	uint32_t	waittime;
	uint16_t	packet_len;
	int			protocol;
	uint32_t	local_addr;
};

/* Function prototypes */

void	tr_err(const char *msg);
void	tr_perr(const char *msg);
void	tr_warn(const char *msg);
void	tr_bad_value(const char *key, const char *val);

int		tr_params(const char *key, const char *val, int min, int max);

uint32_t	get_destination_ip_addr(const char *host, struct tr_params *params);
int			set_protocol(const char* proto_str);
int			create_socket(struct tr_params *params);

void	print_router_name(struct sockaddr *sa);
void	print_router_rtt(struct timespec start, struct timespec end);

uint16_t	tcp_checksum(const void *buf, size_t len);
uint16_t	icmp_checksum(const void *buf, size_t len);

int	send_probe(int send_sock, uint32_t dst_addr, uint16_t current_port, struct tr_params *params);
int	is_valid_response(struct icmp *icmp, uint32_t current_port, struct tr_params *params);

void	check_privileges(void);
int		get_max_ttl(void);

#endif /* TRACEROUTE_H */