/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   debug.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/19 21:47:02 by mgama             #+#    #+#             */
/*   Updated: 2025/10/19 21:47:13 by mgama            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "traceroute.h"

void
_print_ip(uint32_t ip, const char* msg)
{
	char ip_str[INET_ADDRSTRLEN];
	(void)inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
	(void)printf("%s: %s\n", msg, ip_str);
}

void
_print_icmp(uint8_t *packet, size_t packet_size)
{
	size_t i, j;
	unsigned char *p = (unsigned char *)packet;
	(void)printf("Full ICMP packet (%zu bytes):\n", packet_size);
	for (i = 0; i < packet_size; ++i) {
		if ((i % 16) == 0)
			(void)printf("%04zx: ", i);
		(void)printf("%02x ", p[i]);
		if ((i % 16) == 15 || i == packet_size - 1) {
			/* pad hex column if line not complete */
			int pad = 15 - (i % 16);
			for (j = 0; j < pad; ++j)
				(void)printf("   ");
			(void)printf(" ");
			/* print ASCII representation */
			size_t start = i - (i % 16);
			for (j = start; j <= i; ++j) {
				unsigned char c = p[j];
				(void)printf("%c", (c >= 32 && c < 127) ? c : '.');
			}
			(void)printf("\n");
		}
	}
	(void)fflush(stdout);
}
