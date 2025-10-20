/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sys.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/19 21:58:38 by mgama             #+#    #+#             */
/*   Updated: 2025/10/20 11:42:02 by mgama            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "traceroute.h"

void
check_privileges(void)
{
	if (geteuid() != 0)
	{
		(void)fprintf(stderr, "This program must be run as root.\n");
		exit(1);
	}
}

int
get_max_ttl(void)
{
#ifdef __APPLE__
	int max_ttl;
	size_t len = sizeof(max_ttl);

	if (sysctlbyname("net.inet.ip.ttl", &max_ttl, &len, NULL, 0) == -1) {
		tr_perr("sysctlbyname");
		exit(1);
	}
	return (max_ttl);
#else
	return (30);
#endif /* __APPLE__ */
}
