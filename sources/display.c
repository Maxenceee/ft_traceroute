/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   display.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/19 21:50:46 by mgama             #+#    #+#             */
/*   Updated: 2025/10/19 21:50:56 by mgama            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "traceroute.h"

void
print_router_name(struct sockaddr *sa)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	char ip_str[INET_ADDRSTRLEN];
	(void)inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, ip_str, sizeof(ip_str));

	/**
	 * Grace au rDNS (reverse DNS), on peut essayer de récupérer le nom
	 * de l'hôte à partir de son adresse IP.
	 */
	if (getnameinfo(sa, sa->sa_len, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), NI_NAMEREQD) != 0)
	{
		(void)printf("%s (%s) ", ip_str, ip_str);
	}
	else
	{
		(void)printf("%s (%s) ", hbuf, ip_str);
	}
	(void)fflush(stdout);
}

void
print_router_rtt(struct timespec start, struct timespec end)
{
	double rtt = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
	(void)printf(" %.3f ms ", rtt);
	(void)fflush(stdout);
}
