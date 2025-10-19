/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   traceroute.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/18 15:22:47 by mgama             #+#    #+#             */
/*   Updated: 2025/10/19 15:37:21 by mgama            ###   ########.fr       */
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
};

#endif /* TRACEROUTE_H */