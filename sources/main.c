/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/18 15:23:52 by mgama             #+#    #+#             */
/*   Updated: 2025/10/19 15:07:55 by mgama            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "traceroute.h"
#include "pcolors.h"

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
	/**
	 * Si l'hôte est une adresse IP directe, on la retourne immédiatement
	 */
	if (inet_pton(AF_INET, host, &in) == 1) {
		return (in.s_addr);
	}

	struct hostent *hostent = gethostbyname(host);
	if (hostent == NULL)
	{
		perror("gethostbyname");
		return 0;
	}

	/**
	 * Le DNS peut retourner plusieurs adresses IP pour un même nom d'hôte.
	 * On essaie de se connecter à chacune d'entre elles jusqu'à trouver
	 * une adresse IP locale valide.
	 */
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
			close(sock);
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
		close(sock);
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

	/**
	 * Grace au rDNS (reverse DNS), on peut essayer de récupérer le nom
	 * de l'hôte à partir de son adresse IP.
	 */
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

static double time_diff_ms(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
}

int
trace(int recv_sock, int send_sock, uint32_t dst_addr, struct tr_params *params)
{
	uint8_t payload[TR_MAX_PACKET_LEN];

	for (int ttl = params->first_ttl; ttl <= params->max_ttl; ++ttl)
	{
		/**
		 * Définit le TTL du socket d'envoi
		 */
		(void)setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

		printf("%2d  ", ttl);

		uint32_t last_addr_reached = 0;
		int dest_reached = 0;

		for (int probe = 0; probe < params->nprobes; ++probe)
		{
			memset(payload, 0, params->packet_len);

			struct sockaddr_in dst;
			memset(&dst, 0, sizeof(dst));
			dst.sin_family = AF_INET;
			dst.sin_addr = *(struct in_addr *)&dst_addr;

			// Le port est calculé en fonction du TTL et du numéro de probe afin d'être unique
			int current_port = params->port + ttl * params->nprobes + probe;
			dst.sin_port = htons(current_port);

			int got_reply = 0;

			struct timespec start, end, now;
			(void)clock_gettime(CLOCK_MONOTONIC, &start);

			// printf("\n\t\t"B_BLUE"debug"RESET": start=%ld.%09ld\n", start.tv_sec, start.tv_nsec);

			(void)sendto(send_sock, payload, params->packet_len, 0, (struct sockaddr*)&dst, sizeof(dst));

			/**
			 * Le socket de réception étant brut il reçoit toutes les trames ICMP reçues par le système.
			 * Il faut donc filtrer les réponse pour ne garder que celles correspondant aux probes envoyées.
			 * Pour cela on lit les messages reçus jusqu'à ce qu'on trouve une réponse correspondante ou que le timeout
			 * soit atteint.
			 */
			while (!got_reply)
			{
				clock_gettime(CLOCK_MONOTONIC, &now);
				// Calcule le temps écoulé depuis l'envoi de la probe
    			double elapsed = time_diff_ms(start, now);

				// Si le temps écoulé dépasse le timeout, on arrête la réception
				if (elapsed > params->waittime * 1000.0)
					break;

				// Calcule le temps restant pour select() afin de ne pas dépasser le timeout global
				// et de désynchroniser les probes.
				double remaining = (params->waittime * 1000.0) - elapsed;
				if (remaining < 0)
					remaining = 0;

				struct timeval tv;
				tv.tv_sec = (int)(remaining / 1000);
				tv.tv_usec = (int)((remaining - tv.tv_sec * 1000) * 1000);

				fd_set rfds;
				FD_ZERO(&rfds);
				FD_SET(recv_sock, &rfds);

				int rv = select(recv_sock+1, &rfds, NULL, NULL, &tv);
				if (rv <= 0)
					break;

				char buff[1024];
				struct ip *ip;
				struct icmp *icmp;
				struct sockaddr_in from;
				socklen_t fromlen = sizeof(from);

				ssize_t n = recvfrom(recv_sock, buff, sizeof buff, 0, (struct sockaddr*)&from, &fromlen);
				if (n <= 0)
					continue;

				(void)clock_gettime(CLOCK_MONOTONIC, &end);

				ip = (struct ip *)buff;
				int ip_header_len = ip->ip_hl * 4;
				// Le contenu ICMP commence après l'en-tête IP
				icmp = (struct icmp *)(buff + ip_header_len);

				/**
				 * Lorsque le TTL expire, le routeur envoie un message ICMP de type 11 (Time Exceeded),
				 * est inclue dans le réponse ICMP la requête IP originale ayant provoqué le message ICMP,
				 * ce qui permet d'identifier la probe correspondante.
				 */
				struct ip *inner_ip = (struct ip *)(icmp->icmp_data);
				int inner_len = inner_ip->ip_hl * 4;
				// On récupère le contenu UDP de la requête originale
				struct udphdr *inner_udp = (struct udphdr *)((uint8_t *)inner_ip + inner_len);

				uint16_t dport = ntohs(inner_udp->uh_dport);

				// printf("\n\t\t"B_BLUE"debug"RESET": icmp_type=%d icmp_code=%d ip_p=%d port=%d (expected port=%d)\n",
					// icmp->icmp_type, icmp->icmp_code, inner_ip->ip_p, dport, current_port);

				// On s'assure que le protocole de la requête correspond bien à de l'UDP
				if (inner_ip->ip_p != IPPROTO_UDP)
				{
					// printf("\n\t\t"B_BLUE"debug"RESET": inner_ip->ip_p != IPPROTO_UDP (%d)\n", inner_ip->ip_p);
					continue;
				}

				// On s'assure ensuite que le port de destination correspond bien à celui de la probe envoyée
				if (dport != current_port)
				{
					// printf("\n\t\t"B_BLUE"debug"RESET": port mismatch (got %d, expected %d)\n", dport, current_port);
					continue;
				}

				got_reply = 1;

				/**
				 * Lorsque le TTL est atteint, le router envoie un message ICMP de type 11 (Time Exceeded).
				 * Lorsque la destination est atteinte, elle envoie un message ICMP de type 0 (Echo Reply)
				 * ou de type 3 (Destination Unreachable) code 3 (Port Unreachable).
				 */
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

				if (icmp->icmp_type == 0 || (icmp->icmp_type == 3 && icmp->icmp_code == 3))
            		dest_reached = 1;
			}
			if (!got_reply)
			{
				// clock_gettime(CLOCK_MONOTONIC, &now);
				// double elapsed = time_diff_ms(start, now);
				// printf("\n\t\t"B_BLUE"debug"RESET": timeout after %.3f ms\n", elapsed);
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
	if (dst_addr == 0)
	{
		fprintf(stderr, "traceroute: unknown host %s\n", target);
		return (1);
	}

	int send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (send_sock < 0)
	{
		perror("socket");
		return (1);
	}
	/**
	 * Création du socket brut pour recevoir les messages ICMP.
	 * NOTE:
	 * La création d'un socket brut, permettant de lire toutes les trames ICMP
	 * entrantes, y compris celles émises et destinées à d'autres processus, cela
	 * nécessite des privilèges d'administrateur.
	 */
	int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (raw_sock < 0)
	{
		perror("socket");
		return (1);
	}

	char ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &dst_addr, ip_str, sizeof(ip_str));

	printf(TR_PREFIX" to %s (%s), %d hops max, %d byte packets\n", target, ip_str, params.max_ttl, params.packet_len);

	return (trace(raw_sock, send_sock, dst_addr, &params));
}
