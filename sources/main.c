/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/18 15:23:52 by mgama             #+#    #+#             */
/*   Updated: 2025/10/19 13:56:30 by mgama            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "traceroute.h"

void
usage(void)
{
	fprintf(stderr, "Usage: traceroute [-Iv] [-f first_ttl] [-M first_ttl] [-m max_ttl]\n");
	fprintf(stderr, "        [-p port] [-q nqueries] [-w waittime] host [packetlen]\n");
	exit(64);
}

void
_print_ip(uint32_t ip, const char* msg)
{
	char ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
	printf("%s: %s\n", msg, ip_str);
}

int
isstringdigit(const char *str)
{
	while (*str)
	{
		if (!isdigit(*str))
			return (0);
		str++;
	}
	return (1);
}

void
tr_err(const char *msg)
{
	fprintf(stderr, "traceroute: %s\n", msg);
	exit(1);
}

int
tr_params(const char *key, const char *val, int min, int max)
{
	if (!isstringdigit(val)) {
		fprintf(stderr, "traceroute: \"%s\" bad value for %s\n", val, key);
		exit(1);
	}
	int pval = atoi(val);
	if (pval < min) {
		fprintf(stderr, "traceroute: %s must be > %d\n", key, min);
		exit(1);
	}
	if (pval > max) {
		fprintf(stderr, "traceroute: %s must be <= %d\n", key, max);
		exit(1);
	}
	return (pval);
}

void
check_privileges(void)
{
	if (geteuid() != 0)
	{
		fprintf(stderr, "This program must be run as root.\n");
		exit(1);
	}
}

int
get_max_ttl(void)
{
	int max_ttl;
	size_t len = sizeof(max_ttl);

	if (sysctlbyname("net.inet.ip.ttl", &max_ttl, &len, NULL, 0) == -1) {
		perror("sysctlbyname");
		exit(1);
	}
	return (max_ttl);
}

uint32_t
get_destination_ip_addr(const char *host)
{
	struct in_addr in;
	if (inet_pton(AF_INET, host, &in) == 1) {
		return (in.s_addr);
	}

	struct hostent *hostent = gethostbyname(host);
	if (hostent == NULL)
	{
		perror("gethostbyname");
		return 0;
	}
	for (char **addr = hostent->h_addr_list; *addr != NULL; addr++)
	{
		int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sock < 0)
		{
			perror("socket");
			return 0;
		}

		struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons(53);

        struct in_addr in;
        memcpy(&in, *addr, sizeof(struct in_addr));
        dst.sin_addr = in;

        _print_ip(in.s_addr, "Target IP");

		if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) < 0)
		{
			perror("connect");
			close(sock);
			continue;
		}

		struct sockaddr_in local;
		socklen_t len = sizeof(local);
		if (getsockname(sock, (struct sockaddr *)&local, &len) < 0)
		{
			perror("getsockname");
			return 0;
		}

		_print_ip(local.sin_addr.s_addr, "Default local IP");

		struct ifaddrs *ifap, *ifa;
		(void)getifaddrs(&ifap);
		for (ifa = ifap; ifa; ifa = ifa->ifa_next)
		{
			if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET)
			{
				struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
				if (sa->sin_addr.s_addr == local.sin_addr.s_addr)
					printf("Using interface: %s\n", ifa->ifa_name);
			}
		}
		freeifaddrs(ifap);
		return (*(uint32_t *)addr);
	}
	return 0;
}

void
print_router_name(struct sockaddr *sa)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	char ip_str[INET_ADDRSTRLEN];
	(void)inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, ip_str, sizeof(ip_str));

	if (getnameinfo(sa, sa->sa_len, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), NI_NAMEREQD) != 0)
	{
		printf("%s (%s) ", ip_str, ip_str);
	}
	else
	{
		printf("%s (%s) ", hbuf, ip_str);
	}
	fflush(stdout);
}

void
print_router_rtt(struct timespec start, struct timespec end)
{
	double rtt = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
	printf(" %.3f ms ", rtt);
	fflush(stdout);
}

int
trace(int recv_sock, int send_sock, uint32_t dst_addr, struct tr_params *params)
{
	uint8_t payload[TR_MAX_PACKET_LEN];

	for (int ttl = params->first_ttl; ttl <= params->max_ttl; ++ttl)
	{
		(void)setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

		printf("%2d  ", ttl);
		fflush(stdout);

		uint32_t last_addr_reached = 0;
		int dest_reached = 0;

		for (int probe = 0; probe < params->nprobes; ++probe)
		{
			struct sockaddr_in dst;
			memset(&dst, 0, sizeof(dst));
			dst.sin_family = AF_INET;

			dst.sin_addr = *(struct in_addr *)&dst_addr;

			// port UDP de destination pour la sonde
			int seq = ttl * 3 + probe;
			dst.sin_port = htons(params->port + seq);

			memset(payload, 0, params->packet_len);

			dst.sin_port = htons(params->port + ttl*params->nprobes + probe);

			struct timespec start, end;
			(void)clock_gettime(CLOCK_MONOTONIC, &start);

			(void)sendto(send_sock, payload, params->packet_len, 0, (struct sockaddr*)&dst, sizeof(dst));
			// puis attendre la réponse ICMP
			fd_set rfds;
			FD_ZERO(&rfds);
			FD_SET(recv_sock, &rfds);
			struct timeval tv = { params->waittime, 0 };
			int rv = select(recv_sock+1, &rfds, NULL, NULL, &tv);
			if (rv > 0 && FD_ISSET(recv_sock, &rfds))
			{
				char buff[1024];
				struct ip *ip;
				struct icmp *icmp;
				struct sockaddr_in from;
				socklen_t fromlen = sizeof(from);

				ssize_t n = recvfrom(recv_sock, buff, sizeof buff, 0, (struct sockaddr*)&from, &fromlen);

				(void)clock_gettime(CLOCK_MONOTONIC, &end);

				ip = (struct ip *)buff;
				int ip_header_len = ip->ip_hl * 4;
				icmp = (struct icmp *)(buff + ip_header_len);

				if (icmp->icmp_type == 11 || (icmp->icmp_type == 3 && icmp->icmp_code == 3))
				{
					if (last_addr_reached == 0)
					{
						print_router_name((struct sockaddr*)&from);
						last_addr_reached = from.sin_addr.s_addr;
					}
					else if (last_addr_reached != 0 && last_addr_reached != from.sin_addr.s_addr)
					{
						printf("%s%s", "\n", "    ");
						print_router_name((struct sockaddr*)&from);
						last_addr_reached = from.sin_addr.s_addr;
					}
					print_router_rtt(start, end);
				}
				else if (icmp->icmp_type == 0)
				{
					printf("\n");
					return (0);
				}

				if (from.sin_addr.s_addr == dst_addr)
				{
					dest_reached = 1;
				}
			}
			else
			{
				printf("* ");
				fflush(stdout);
			}
		}
		printf("\n");

		if (dest_reached)
		{
			break;
		}
	}
	return (0);
}

/**
 * Program params:
 * -f first_ttl   : Set the initial time-to-live value (default is 1).
 * -M first_ttl   : Set the initial time-to-live value (default is 1).
 * -m max_ttl     : Set the maximum time-to-live value (value of net.inet.ip.ttl).
 * -p port        : Set the destination port (default is 33434).
 * -q nqueries    : Set the number of probes per TTL (default is 3).
 * -w waittime    : Set the timeout for each probe (default is 5 seconds).
 */
int
main(int argc, char **argv)
{
	check_privileges();

	int ch;
	char* target;
	struct tr_params params;
	
	params.packet_len = TR_DEFAULT_PACKET_LEN;

	params.max_ttl = get_max_ttl();
	params.first_ttl = TR_DEFAULT_FIRST_TTL;
	params.port = TR_DEFAULT_BASE_PORT;
	params.nprobes = TR_DEFAULT_PROBES;
	params.waittime = TR_DEFAULT_TIMEOUT;

	params.flags = 0;
    while ((ch = getopt(argc, argv, "f:IM:m:p:q:vw:")) != -1) {
		switch (ch) {
			case 'I':
				printf("param: -I\n");
				break;
			case 'f':
			case 'M':
				printf("param: -f|M\n");
				params.first_ttl = tr_params("first ttl", optarg, 1, TR_MAX_FIRST_TTL);
				break;
			case 'm':
				printf("param: -m\n");
				params.max_ttl = tr_params("max ttl", optarg, 1, TR_MAX_TTL);
				break;
			case 'p':
				printf("param: -p\n");
				params.port = tr_params("port", optarg, 1, TR_MAX_PORT);
				break;
			case 'q':
				printf("param: -q\n");
				params.nprobes = tr_params("nprobes", optarg, 1, TR_MAX_PROBES);
				break;
			case 'w':
				printf("param: -w\n");
				params.waittime = tr_params("wait time", optarg, 1, TR_MAX_TIMEOUT);
				break;
			case 'v':
				printf("param: -v\n");
				params.flags |= TR_FLAG_VERBOSE;
				break;
			case '?':
            default:
				printf("Unknown option\n");
				usage();
		}
	}

	if (argc - optind > 2)
	{
		usage();
	}
	target = argv[optind];
	if (argv[optind + 1])
	{
		params.packet_len = tr_params("packet length", argv[optind + 1], 27, TR_MAX_PACKET_LEN);
	}

	uint32_t dst_addr = get_destination_ip_addr(target);

	int send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	int raw_sock  = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	char ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &dst_addr, ip_str, sizeof(ip_str));

	printf(TR_PREFIX" to %s (%s), %d hops max, %d byte packets\n", target, ip_str, params.max_ttl, params.packet_len);

	return (trace(raw_sock, send_sock, dst_addr, &params));
}