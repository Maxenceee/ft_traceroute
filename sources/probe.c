/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   probe.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/19 21:52:32 by mgama             #+#    #+#             */
/*   Updated: 2025/10/19 23:06:56 by mgama            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "traceroute.h"

static int
send_probe_udp(int send_sock, uint32_t dst_addr, uint16_t current_port, struct tr_params *params)
{
	/**
	 * Les trames UDP suivent la structure suivante :
	 * ┌────────────────────────────┐
	 * │ IP header                  │  ← struct ip
	 * ├────────────────────────────┤
	 * │ UDP header                 │  ← struct udphdr
	 * ├────────────────────────────┤
	 * │ payload (données)          │
	 * └────────────────────────────┘
	 */
	uint8_t payload[TR_MAX_PACKET_LEN];

	memset(payload, 0, params->packet_len);

	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));

	dst.sin_family = AF_INET;
	dst.sin_addr = *(struct in_addr *)&dst_addr;
	dst.sin_port = htons(current_port);

	return (sendto(send_sock, payload, params->packet_len, 0, (struct sockaddr*)&dst, sizeof(dst)));
}

static int
send_probe_tcp(int send_sock, uint32_t dst_addr, uint16_t current_port, struct tr_params *params)
{
	/**
	 * INFO:
	 * Cette fonction est un test d'une implémentation basique d'envoi de paquets TCP SYN
	 */

	struct tcphdr tcph;
	memset(&tcph, 0, sizeof(tcph));

	srand((unsigned)time(NULL) ^ (unsigned)getpid());
	// Génère un port source aléatoire entre 1024 et 65535
	uint16_t src_port = (uint16_t)(1024 + (rand() % (65535-1024)));

	tcph.th_sport = htons(src_port);
    tcph.th_dport = htons(current_port);
    tcph.th_seq   = htonl((uint32_t)rand());
    tcph.th_ack   = 0;
    tcph.th_off   = sizeof(struct tcphdr) / 4; // data offset in 32-bit words
    tcph.th_flags = TH_SYN;                    // SYN flag
    tcph.th_win   = htons(64240);
    tcph.th_urp   = 0;
    tcph.th_sum   = 0;

	/**
	 * Le pseudo-header inclut des informations de l'en-tête IP
	 * nécessaires pour le calcul de la checksum TCP.
	 */
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
	uint8_t pbuf[sizeof(psh) + sizeof(struct tcphdr)];

	memcpy(pbuf, &psh, sizeof(psh));
	memcpy(pbuf + sizeof(psh), &tcph, sizeof(struct tcphdr));

	tcph.th_sum = tcp_checksum(pbuf, psize);

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

static int
send_probe_icmp(int send_sock, uint32_t dst_addr, uint16_t current_port, struct tr_params *params)
{
	(void)current_port;
	(void)params;

	/**
	 * Les trames ICMP suivent la structure suivante :
	 * ┌────────────────────────────┐
	 * │ IP header                  │  ← struct ip
	 * ├────────────────────────────┤
	 * │ ICMP header                │  ← struct icmp
	 * │   type = 8 (Echo Request)  │
	 * │   code = 0                 │
	 * │   checksum                 │
	 * │   id                       │
	 * │   seq                      │
	 * ├────────────────────────────┤
	 * │ payload (facultatif)       │
	 * └────────────────────────────┘
	 */
	struct icmp icmp_hdr;
	memset(&icmp_hdr, 0, sizeof(icmp_hdr));

	icmp_hdr.icmp_type = ICMP_ECHO;
	icmp_hdr.icmp_code = 0;
	icmp_hdr.icmp_id   = htons(getpid() & 0xFFFF);
	icmp_hdr.icmp_seq  = htons(current_port);

	char payload[32] = "ICMP traceroute probe";
	size_t packet_size = sizeof(icmp_hdr) + sizeof(payload);
	unsigned char packet[sizeof(icmp_hdr) + sizeof(payload)];
	memcpy(packet, &icmp_hdr, sizeof(icmp_hdr));
	memcpy(packet + sizeof(icmp_hdr), payload, sizeof(payload));

	struct icmp *icmp_packet = (struct icmp *)packet;
    icmp_packet->icmp_cksum = icmp_checksum(packet, packet_size);

	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));

	dst.sin_family = AF_INET;
	dst.sin_addr = *(struct in_addr *)&dst_addr;

    return (sendto(send_sock, packet, packet_size, 0, (struct sockaddr *)&dst, sizeof(dst)));
}

static int
send_probe_gre(int send_sock, uint32_t dst_addr, uint16_t current_port, struct tr_params *params)
{
	(void)send_sock;
	(void)dst_addr;
	(void)current_port;
	(void)params;
	
	/**
	 * INFO:
	 * Le protocole GRE permet d'encapsuler divers protocoles réseau.
	 */
	return (0);
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
	case TR_PROTO_ICMP:
		return (send_probe_icmp(send_sock, dst_addr, current_port, params));
	case TR_PROTO_GRE:
		return (send_probe_gre(send_sock, dst_addr, current_port, params));
	}
	return (0);
}
