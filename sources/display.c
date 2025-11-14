/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   display.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/19 21:50:46 by mgama             #+#    #+#             */
/*   Updated: 2025/11/14 10:43:39 by mgama            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "traceroute.h"

static const char* icmp_type_names[] = {
	"Echo Reply",
	"Reserved",
	"Reserved",
	"Dest Unreachable",
	"Source Quench",
	"Redirect Message",
	"deprecated",
	"Reserved",
	"Echo Request",
	"Router Advertisement",
	"Router Solicitation",
	"Time Exceeded",
	"Parameter Problem: Bad IP header",
	"Timestamp",
	"Timestamp Reply",
	"Information Request",
	"Information Reply",
	"Address Mask Request",
	"Address Mask Reply",
	"Reserved",
};

void
print_router_name(struct sockaddr *sa)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	char ip_str[INET_ADDRSTRLEN];
	(void)inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, ip_str, sizeof(ip_str));

#ifdef HAVE_SOCKADDR_SA_LEN
	socklen_t sa_len = sa->sa_len;
#else
	socklen_t sa_len = sizeof(struct sockaddr_in);
#endif /* __APPLE__ */

	/**
	 * Grace au rDNS (reverse DNS), on peut essayer de récupérer le nom
	 * de l'hôte à partir de son adresse IP.
	 */
	if (getnameinfo(sa, sa_len, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), NI_NAMEREQD) != 0)
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

void
print_verbose_response(uint8_t *packet, size_t packet_size)
{
	if (packet_size < sizeof(struct ip))
		return;

	struct ip *ip_hdr = (struct ip *)packet;
	int ip_header_len = ip_hdr->ip_hl * 4;

	if (packet_size < ip_header_len + sizeof(struct icmp))
		return;

	struct icmp *icmp_hdr = (struct icmp *)(packet + ip_header_len);
	uint8_t *icmp_payload = packet + ip_header_len;
	size_t icmp_len = packet_size - ip_header_len;

	char src[INET_ADDRSTRLEN];
	char dst[INET_ADDRSTRLEN];

	(void)inet_ntop(AF_INET, &ip_hdr->ip_src, src, sizeof(src));
	(void)inet_ntop(AF_INET, &ip_hdr->ip_dst, dst, sizeof(dst));

	const char *type_name = icmp_hdr->icmp_type < sizeof(icmp_type_names) ? icmp_type_names[icmp_hdr->icmp_type] : "unknown";

	(void)printf("%zd bytes from %s to %s: icmp type %d (%s) code %d\n",
		icmp_len,
		src,
		dst,
		icmp_hdr->icmp_type,
		type_name,
		icmp_hdr->icmp_code);

	size_t offset = 4; // On évite les 4 premiers octets qui contiennent l'en-tête
	while (offset < icmp_len)
	{
		(void)printf("%2zu: ", offset);
		(void)printf("x");
		for (int i = 0; i < 4 && offset + i < icmp_len; i++)
		{
			(void)printf("%02x", icmp_payload[offset + i]);
		}
		(void)printf(" ");
		for (int i = 0; i < 4 && offset + i < icmp_len; i++)
		{
			unsigned char c = icmp_payload[offset + i];
			(void)printf("%c", (c >= 32 && c < 127) ? c : '.');
		}
		(void)printf("\n");
		offset += 4;
	}
}