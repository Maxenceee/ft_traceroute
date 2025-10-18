/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/18 15:23:52 by mgama             #+#    #+#             */
/*   Updated: 2025/10/18 17:04:57 by mgama            ###   ########.fr       */
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

struct tr_addr
get_destination_ip_addr(const char *host)
{
	struct in_addr in;
	if (inet_pton(AF_INET, host, &in) == 1) {
		int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sock < 0) {
			perror("socket");
			return invalid_addr;
		}

		return (struct tr_addr){ sock, in.s_addr };
	}


	struct hostent *hostent = gethostbyname(host);
	if (hostent == NULL)
	{
		perror("gethostbyname");
		exit(1);
	}
	for (char **addr = hostent->h_addr_list; *addr != NULL; addr++)
	{
		int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sock < 0)
		{
			perror("socket");
			return invalid_addr;
		}

		struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons(53); // port arbitraire

        struct in_addr in;
        memcpy(&in, *addr, sizeof(struct in_addr));
        dst.sin_addr = in;

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &dst.sin_addr, ip_str, sizeof(ip_str));
        printf("Target IP: %s\n", ip_str);

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
			return invalid_addr;
		}

		char addr_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &local.sin_addr, addr_str, sizeof(addr_str));
		printf("Default local IP: %s\n", addr_str);

		struct ifaddrs *ifap, *ifa;
		getifaddrs(&ifap);
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
		return (struct tr_addr){ sock, *(uint32_t *)addr };
	}
	return invalid_addr;
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

	int bflag, ch, fd;
	char* target;

	int max_ttl = get_max_ttl();
	int first_ttl = TR_DEFAULT_FIRST_TTL;
	int port = TR_DEFAULT_BASE_PORT;
	int nprobes = TR_DEFAULT_PROBES;
	int waittime = TR_DEFAULT_TIMEOUT;

	bflag = 0;
    while ((ch = getopt(argc, argv, "f:IM:m:p:q:vw:")) != -1) {
		switch (ch) {
			case 'I':
				break;
			case 'f':
			case 'M':
				first_ttl = tr_params("first ttl", optarg, 1, 255);
				break;
			case 'm':
				max_ttl = tr_params("max ttl", optarg, 1, 255);
				break;
			case 'p':
				port = tr_params("port", optarg, 1, 65535);
				break;
			case 'q':
				nprobes = tr_params("nprobes", optarg, 1, 255);
				break;
			case 'w':
				waittime = tr_params("wait time", optarg, 1, 86400);
				break;
			case 'v':
				bflag |= TR_FLAG_VERBOSE;
				break;
			case '?':
            default:
				usage();
		}
	}

	if (argc - optind != 1)
	{
		usage();
	}
	target = argv[optind];

	printf("Default IP TTL: %d\n", max_ttl);

	struct tr_addr dst_addr = get_destination_ip_addr(target);
	int send_sock = dst_addr.send_sock;
	if (send_sock < 0)
		tr_err("Failed to create send socket");

	int raw_sock  = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	char ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &dst_addr.target_ip, ip_str, sizeof(ip_str));

	printf("ft_traceroute to %s (%s), %d hops max, %d byte packets\n", target, ip_str, max_ttl, TR_DEFAULT_PACKET_LEN);

	for (int ttl = 1; ttl <= max_ttl; ++ttl)
	{
		setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

		printf("%2d  ", ttl);
		fflush(stdout);

		// envoyer 3 probes par TTL
		for (int probe = 0; probe < nprobes; ++probe)
		{
			struct sockaddr_in dst;
			memset(&dst, 0, sizeof(dst));
			dst.sin_family = AF_INET;

			// adresse IP destination
			inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);

			// port UDP de destination pour la sonde
			int base_port = 33434;
			int seq = ttl * 3 + probe;  // exemple séquence
			dst.sin_port = htons(base_port + seq);

			unsigned char payload[TR_DEFAULT_PACKET_LEN];
			memset(payload, 0, sizeof(payload));

			dst.sin_port = htons(base_port + ttl*nprobes + probe);
			sendto(send_sock, payload, sizeof(payload), 0, (struct sockaddr*)&dst, sizeof(dst));
			// puis attendre la réponse ICMP
			fd_set rfds;
			FD_ZERO(&rfds);
			FD_SET(raw_sock, &rfds);
			struct timeval tv = { waittime, 0 };
			int rv = select(raw_sock+1, &rfds, NULL, NULL, &tv);
			if (rv > 0 && FD_ISSET(raw_sock, &rfds))
			{
				char buff[1024];
				struct ip *ip;
				struct icmp *icmp;
				struct sockaddr_in from;
				socklen_t fromlen = sizeof(from);

				ssize_t n = recvfrom(raw_sock, buff, sizeof buff, 0, (struct sockaddr*)&from, &fromlen);

				ip = (struct ip *)buff;
				int ip_header_len = ip->ip_hl * 4;
				icmp = (struct icmp *)(buff + ip_header_len);

				if (icmp->icmp_type == 11 || (icmp->icmp_type == 3 && icmp->icmp_code == 3))
				{
					char addr_str[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &from.sin_addr, addr_str, sizeof(addr_str));
					printf("%s  ", addr_str);
				}
				else if (icmp->icmp_type == 0)
				{
					return (0);
				}

				if (dst.sin_addr.s_addr == from.sin_addr.s_addr)
				{
					return (0);
				}
			}
			else
			{
				printf("* ");
				fflush(stdout);
			}
		}
		printf("\n");
	}

	return (0);
}