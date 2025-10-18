/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   traceroute.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/18 15:22:47 by mgama             #+#    #+#             */
/*   Updated: 2025/10/18 16:41:20 by mgama            ###   ########.fr       */
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

#include "verbose.h"

#define TR_DEFAULT_PROBES 3
#define TR_DEFAULT_FIRST_TTL 1
#define TR_DEFAULT_TIMEOUT 5
#define TR_DEFAULT_BASE_PORT 33434

#define TR_FLAG_VERBOSE 0x01

struct tr_addr {
	int send_sock;
	uint32_t target_ip;
};

#define invalid_addr (struct tr_addr){ -1, 0 }

#endif /* TRACEROUTE_H */