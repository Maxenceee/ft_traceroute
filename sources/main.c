/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/18 15:23:52 by mgama             #+#    #+#             */
/*   Updated: 2025/10/19 19:44:49 by mgama            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "traceroute.h"
#include "pcolors.h"

void
usage(void)
{
	(void)fprintf(stderr, "Usage: traceroute [-Iv] [-f first_ttl] [-M first_ttl] [-m max_ttl]\n");
	(void)fprintf(stderr, "        [-p port] [-q nqueries] [-w waittime] host [packetlen]\n");
	exit(64);
}

void
_print_ip(uint32_t ip, const char* msg)
{
	char ip_str[INET_ADDRSTRLEN];
	(void)inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
	(void)printf("%s: %s\n", msg, ip_str);
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
tr_perr(const char *msg)
{
	(void)fprintf(stderr, TR_PREFIX": %s: %s\n", msg, strerror(errno));
}

void
tr_warn(const char *msg)
{
	(void)fprintf(stderr, TR_PREFIX": Warning: %s\n", msg);
}

void
tr_bad_value(const char *key, const char *val)
{
	(void)fprintf(stderr, TR_PREFIX": \"%s\" bad value for %s\n", val, key);
	exit(1);
}

int
tr_params(const char *key, const char *val, int min, int max)
{
	if (!isstringdigit(val)) {
		tr_bad_value(key, val);
	}
	int pval = atoi(val);
	if (pval < min) {
		(void)fprintf(stderr, TR_PREFIX": %s must be > %d\n", key, min);
		exit(1);
	}
	if (pval > max) {
		(void)fprintf(stderr, TR_PREFIX": %s must be <= %d\n", key, max);
		exit(1);
	}
	return (pval);
}

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
	int max_ttl;
	size_t len = sizeof(max_ttl);

	if (sysctlbyname("net.inet.ip.ttl", &max_ttl, &len, NULL, 0) == -1) {
		tr_perr("sysctlbyname");
		exit(1);
	}
	return (max_ttl);
}

uint32_t
get_destination_ip_addr(const char *host, struct tr_params *params)
{
	struct in_addr in;

	/**
	 * On tente d'abord de convertir l'hôte en adresse IP directement.
	 * Si cela échoue, on effectue une résolution DNS sur le nom d'hôte.
	 */
	if (inet_pton(AF_INET, host, &in) == 0)
	{
		struct hostent *hostent = gethostbyname(host);
		if (hostent == NULL || hostent->h_addr_list[0] == NULL)
		{
			return 0;
		}

		/**
		 * L'implémentation de traceroute de BSD avertit lorsque
		 * plusieurs adresses IP sont associées à un nom d'hôte et
		 * ne prend que la première adresse.
		 */
		if (hostent->h_addr_list[1] != NULL)
		{
			char ip_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, hostent->h_addr_list[0], ip_str, sizeof(ip_str));
			fprintf(stderr, TR_PREFIX": Warning: %s has multiple addresses; using %s\n", host, ip_str);
		}

		char **addr = hostent->h_addr_list;
        memcpy(&in, *addr, sizeof(struct in_addr));
	}

	_print_ip(in.s_addr, "Target IP");

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
	{
		tr_perr("socket");
		return (0);
	}

	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port = htons(53);
	dst.sin_addr = in;

	if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) < 0)
	{
		tr_perr("connect");
		(void)close(sock);
		return (0);
	}

	struct sockaddr_in local;
	socklen_t len = sizeof(local);
	if (getsockname(sock, (struct sockaddr *)&local, &len) < 0)
	{
		tr_perr("getsockname");
		(void)close(sock);
		return 0;
	}

	params->local_addr = local.sin_addr.s_addr;

	_print_ip(params->local_addr, "Default local IP");

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
	(void)close(sock);
	return (dst.sin_addr.s_addr);
}

int
set_protocol(const char* proto_str)
{
	if (strcmp(proto_str, "udp") == 0 || strcmp(proto_str, "UDP") == 0)
		return (TR_PROTO_UDP);
	else if (strcmp(proto_str, "icmp") == 0 || strcmp(proto_str, "ICMP") == 0)
		return (TR_PROTO_ICMP);
	else if (strcmp(proto_str, "tcp") == 0 || strcmp(proto_str, "TCP") == 0)
		return (TR_PROTO_TCP);
	else if (strcmp(proto_str, "gre") == 0 || strcmp(proto_str, "GRE") == 0)
		return (TR_PROTO_GRE);

	tr_bad_value("protocol", proto_str);
	return (0);
}

int
create_socket(struct tr_params *params)
{
	/**
	 * Création du socket de réception en fonction du protocole choisi.
	 * NOTE:
	 * La création d'un socket brut, permettant de lire toutes les trames ICMP
	 * entrantes, y compris celles émises et destinées à d'autres processus, cela
	 * nécessite des privilèges d'administrateur.
	 */
	switch (params->protocol)
	{
	case TR_PROTO_UDP:
		return (socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
	case TR_PROTO_ICMP:
		return (socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
	case TR_PROTO_TCP:
		return (socket(AF_INET, SOCK_RAW, IPPROTO_TCP));
	case TR_PROTO_GRE:
		return (socket(AF_INET, SOCK_RAW, IPPROTO_GRE));
	default:
		return (-1);
	}
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

static double
time_diff_ms(struct timespec start, struct timespec end)
{
    return (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
}

int
send_probe_udp(int send_sock, uint32_t dst_addr, uint16_t current_port, struct tr_params *params)
{
	uint8_t payload[TR_MAX_PACKET_LEN];

	memset(payload, 0, params->packet_len);

	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));

	dst.sin_family = AF_INET;
	dst.sin_addr = *(struct in_addr *)&dst_addr;
	dst.sin_port = htons(current_port);

	return (sendto(send_sock, payload, params->packet_len, 0, (struct sockaddr*)&dst, sizeof(dst)));
}

static uint16_t
checksum(const void *buf, size_t len)
{
    const uint16_t *data = buf;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t *)data;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFF);
}

int
send_probe_tcp(int send_sock, uint32_t dst_addr, uint16_t current_port, struct tr_params *params)
{
	struct tcphdr tcph;
	memset(&tcph, 0, sizeof(tcph));

	srand((unsigned)time(NULL) ^ (unsigned)getpid());
	uint16_t src_port = (uint16_t)(1024 + (rand() % (65535-1024)));

	tcph.th_sport = htons(src_port);
	tcph.th_dport = htons(current_port);
	tcph.th_seq = htonl((uint32_t)rand());
	tcph.th_ack = 0;
	tcph.th_off = 5; // 5 * 4 = 20 bytes (no options)
	tcph.th_flags = TH_SYN;
	tcph.th_win = htons(64240);
	tcph.th_sum = 0;
	tcph.th_urp = 0;

	struct {
		uint32_t saddr;
		uint32_t daddr;
		uint8_t  zero;
		uint8_t  proto;
		uint16_t tcp_len;
	} psh;

	psh.saddr = params->local_addr;
	psh.daddr = dst_addr;
	psh.zero  = 0;
	psh.proto = IPPROTO_TCP;
	psh.tcp_len = htons(sizeof(struct tcphdr));

	size_t psize = sizeof(psh) + sizeof(struct tcphdr);
	uint8_t *pbuf = malloc(psize);
	if (!pbuf) {
		perror("malloc");
		return -1;
	}
	memcpy(pbuf, &psh, sizeof(psh));
	memcpy(pbuf + sizeof(psh), &tcph, sizeof(struct tcphdr));

	tcph.th_sum = checksum(pbuf, psize);
	free(pbuf);

	size_t packet_len = sizeof(struct tcphdr);
	uint8_t packet[sizeof(struct tcphdr)];
	memcpy(packet, &tcph, sizeof(struct tcphdr));

	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = dst_addr;
	dst.sin_port = tcph.th_dport;

	return (sendto(send_sock, packet, packet_len, 0, (struct sockaddr *)&dst, sizeof(dst)));
}

int
send_probe(int send_sock, uint32_t dst_addr, uint16_t current_port, struct tr_params *params)
{
	switch (params->protocol)
	{
	case TR_PROTO_UDP:
		return (send_probe_udp(send_sock, dst_addr, current_port, params));
	case TR_PROTO_TCP:
		return (send_probe_tcp(send_sock, dst_addr, current_port, params));
	}
	return (0);
}

int
trace(int send_sock, int recv_sock, uint32_t dst_addr, struct tr_params *params)
{
	for (int ttl = params->first_ttl; ttl <= params->max_ttl; ++ttl)
	{
		/**
		 * Définit le TTL du socket d'envoi
		 */
		(void)setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

		(void)printf("%2d  ", ttl);

		uint32_t last_addr_reached = 0;
		int dest_reached = 0;

		for (int probe = 0; probe < params->nprobes; ++probe)
		{
			int got_reply = 0;

			// Le port est calculé en fonction du TTL et du numéro de probe afin d'être unique
			uint16_t current_port = params->port + ttl * params->nprobes + probe;

			struct timespec start, end, now;
			(void)clock_gettime(CLOCK_MONOTONIC, &start);

			if (send_probe(send_sock, dst_addr, current_port, params) == 0)
			{
				tr_perr("failed to send probe");
				continue;
			}

			/**
			 * Le socket de réception étant brut il reçoit toutes les trames ICMP reçues par le système.
			 * Il faut donc filtrer les réponse pour ne garder que celles correspondant aux probes envoyées.
			 * Pour cela on lit les messages reçus jusqu'à ce qu'on trouve une réponse correspondante ou que le timeout
			 * soit atteint.
			 */
			while (!got_reply)
			{
				(void)clock_gettime(CLOCK_MONOTONIC, &now);
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

				/**
				 * Le packet reçu est une trame IP contenant un message ICMP, lui même
				 * contenant la requête initiale.
				 * ┌─────────────────────────────────────────┐
				 * │ IP header                               │  ← ip
				 * ├─────────────────────────────────────────┤
				 * │ ICMP header (type=X, code=X)            │  ← icmp
				 * ├─────────────────────────────────────────┤
				 * │ Inner IP header (paquet original)       │  ← inner_ip
				 * ├─────────────────────────────────────────┤
				 * │ UDP header (du paquet original)         │  ← inner_udp
				 * └─────────────────────────────────────────┘
				 */

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

				// On s'assure que le protocole de la requête correspond bien à de l'UDP
				if (inner_ip->ip_p != IPPROTO_UDP)
				{
					continue;
				}

				// On s'assure ensuite que le port de destination correspond bien à celui de la probe envoyée
				if (dport != current_port)
				{
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
						(void)printf("%s%s", "\n", "    ");
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
    			(void)printf("* ");
				(void)fflush(stdout);
			}
		}
		(void)printf("\n");

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
	params.protocol = TR_PROTO_UDP;

	params.flags = 0;
    while ((ch = getopt(argc, argv, "f:IM:m:P:p:q:vw:")) != -1) {
		switch (ch) {
			case 'I':
				params.protocol = TR_PROTO_ICMP;
				break;
			case 'f':
			case 'M':
				params.first_ttl = tr_params("first ttl", optarg, 1, TR_MAX_FIRST_TTL);
				break;
			case 'm':
				params.max_ttl = tr_params("max ttl", optarg, 1, TR_MAX_TTL);
				break;
			case 'P':
				params.protocol = set_protocol(optarg);
				break;
			case 'p':
				params.port = tr_params("port", optarg, 1, TR_MAX_PORT);
				break;
			case 'q':
				params.nprobes = tr_params("nprobes", optarg, 1, TR_MAX_PROBES);
				break;
			case 'w':
				params.waittime = tr_params("wait time", optarg, 1, TR_MAX_TIMEOUT);
				break;
			case 'v':
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

	uint32_t dst_addr = get_destination_ip_addr(target, &params);
	if (dst_addr == 0)
	{
		(void)fprintf(stderr, "traceroute: unknown host %s\n", target);
		return (1);
	}

	int send_sock = create_socket(&params);
	if (send_sock < 0)
	{
		tr_perr("socket");
		return (1);
	}
	
	int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (recv_sock < 0)
	{
		tr_perr("socket");
		return (1);
	}

	char ip_str[INET_ADDRSTRLEN];
	(void)inet_ntop(AF_INET, &dst_addr, ip_str, sizeof(ip_str));

	(void)printf(TR_PREFIX" to %s (%s), %d hops max, %d byte packets\n", target, ip_str, params.max_ttl, params.packet_len);

	return (trace(send_sock, recv_sock, dst_addr, &params));
}
