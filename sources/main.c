/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/18 15:23:52 by mgama             #+#    #+#             */
/*   Updated: 2025/10/20 11:16:57 by mgama            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "traceroute.h"
#include "pcolors.h"
#include "debug.h"

void
usage(void)
{
	(void)fprintf(stderr, "Usage: traceroute [-ISv] [-f first_ttl] [-M first_ttl] [-m max_ttl]\n");
	(void)fprintf(stderr, "        [-p port] [-q nqueries] [-w waittime] host [packetlen]\n");
	exit(64);
}

static double
time_diff_ms(struct timespec start, struct timespec end)
{
	return (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
}

int
trace(int send_sock, int recv_sock, uint32_t dst_addr, struct tr_params *params)
{
	for (uint32_t ttl = params->first_ttl; ttl <= params->max_ttl; ++ttl)
	{
		/**
		 * Définit le TTL du socket d'envoi
		 */
		(void)setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

		(void)printf("%2d  ", ttl);

		uint32_t last_addr_reached = 0;
		int dest_reached = 0;
		size_t sent = 0;
		uint32_t losses = 0;

		for (uint32_t probe = 0; probe < params->nprobes; ++probe)
		{
			int got_reply = 0;

			// Le port est calculé en fonction du TTL et du numéro de probe afin d'être unique
			uint16_t current_port = params->port + ttl * params->nprobes + probe;

			struct timespec start, end, now;
			(void)clock_gettime(CLOCK_MONOTONIC, &start);

			if ((sent = send_probe(send_sock, dst_addr, current_port, params)) <= 0)
			{
				printf(TR_PREFIX": wrote %s %u chars, ret=%zu", params->dest_host, params->packet_len, sent);
				fflush(stdout);
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
				 * │ Proto header (paquet original)          │  ← inner_udp
				 * └─────────────────────────────────────────┘
				 */

				ip = (struct ip *)buff;
				int ip_header_len = ip->ip_hl * 4;
				// Le contenu ICMP commence après l'en-tête IP
				icmp = (struct icmp *)(buff + ip_header_len);

				/**
				 * Application du filtre de validation des réponses ICMP reçues
				 * en fonction du protocole utilisé pour envoyer les probes.
				 */
				if (!is_valid_response(icmp, current_port, params))
				{
					if (verbose(params->flags))
					{
						print_verbose_response((uint8_t *)ip, n);
					}
					continue;
				}

				got_reply = 1;

				/**
				 * Lorsque le TTL est atteint, le router envoie un message ICMP de type 11 (Time Exceeded).
				 * Lorsque la destination est atteinte, elle envoie un message ICMP de type 0 (Echo Reply)
				 * ou de type 3 (Destination Unreachable) code 3 (Port Unreachable).
				 */
				if (icmp->icmp_type == ICMP_TIMXCEED
					|| (icmp->icmp_type == ICMP_UNREACH && icmp->icmp_code == ICMP_UNREACH_PORT)
					|| icmp->icmp_type == ICMP_ECHOREPLY)
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

				if (icmp->icmp_type == ICMP_ECHOREPLY || (icmp->icmp_type == ICMP_UNREACH && icmp->icmp_code == ICMP_UNREACH_PORT))
					dest_reached = 1;
			}
			if (!got_reply)
			{
				(void)printf("* ");
				(void)fflush(stdout);
				losses++;
			}
		}
		if (summary(params->flags))
		{
			double loss_percent = ((double)losses / (double)params->nprobes) * 100.0;
			(void)printf("(%.0f%% loss)", loss_percent);
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
 * -I             : Use ICMP Echo Request as the probe protocol instead of UDP (-P icmp).
 * -M first_ttl   : Set the initial time-to-live value (default is 1).
 * -m max_ttl     : Set the maximum time-to-live value (value of net.inet.ip.ttl).
 * -P protocol    : Set the protocol (udp, icmp, tcp, gre) (default is udp).
 * -p port        : Set the destination port (default is 33434).
 * -q nqueries    : Set the number of probes per TTL (default is 3).
 * -S             : Enable summary mode.
 * -v             : Enable verbose output.
 * -w waittime    : Set the timeout for each probe (default is 5 seconds).
 */
int
main(int argc, char **argv)
{
	check_privileges();

	int ch;
	char* target;
	struct tr_params params;

	memset(&params, 0, sizeof(params));
	
	params.packet_len = TR_DEFAULT_PACKET_LEN;
	params.max_ttl = get_max_ttl();
	params.first_ttl = TR_DEFAULT_FIRST_TTL;
	params.port = TR_DEFAULT_BASE_PORT;
	params.nprobes = TR_DEFAULT_PROBES;
	params.waittime = TR_DEFAULT_TIMEOUT;
	params.protocol = TR_PROTO_UDP;

	while ((ch = getopt(argc, argv, "f:IM:m:P:p:q:Svw:")) != -1) {
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
				if ((params.protocol = set_protocol(optarg)) == 0)
					return (1);
				break;
			case 'p':
				params.port = tr_params("port", optarg, 1, TR_MAX_PORT);
				break;
			case 'q':
				params.nprobes = tr_params("nprobes", optarg, 1, TR_MAX_PROBES);
				break;
			case 'S':
				params.flags |= TR_FLAG_SUMMARY;
				break;
			case 'v':
				params.flags |= TR_FLAG_VERBOSE;
				break;
			case 'w':
				params.waittime = tr_params("wait time", optarg, 1, TR_MAX_TIMEOUT);
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
	if (optind + 1 < argc && argv[optind + 1])
	{
		params.packet_len = tr_params("packet length", argv[optind + 1], 27, TR_MAX_PACKET_LEN);
	}

	int send_sock = create_socket(&params);
	if (send_sock < 0)
	{
		tr_perr("socket");
		return (1);
	}

	uint32_t dst_addr = get_destination_ip_addr(target, &params);
	if (dst_addr == 0)
	{
		(void)fprintf(stderr, "traceroute: unknown host %s\n", target);
		return (1);
	}

	if (assign_iface(send_sock, dst_addr, &params))
	{
		(void)close(send_sock);
		return (0);
	}
	
	int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (recv_sock < 0)
	{
		tr_perr("socket");
		(void)close(send_sock);
		(void)close(recv_sock);
		return (1);
	}

	(void)printf(TR_PREFIX" to %s (%s), %d hops max, %d byte packets\n", target, params.dest_host, params.max_ttl, params.packet_len);

	int res = trace(send_sock, recv_sock, dst_addr, &params);
	(void)close(send_sock);
	(void)close(recv_sock);
	return (res);
}
