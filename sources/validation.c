/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   validation.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/19 21:54:07 by mgama             #+#    #+#             */
/*   Updated: 2025/10/19 22:17:02 by mgama            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "traceroute.h"
#include "debug.h"

static int
is_valid_udp_response(struct icmp *icmp, uint32_t current_port, struct tr_params *params)
{
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
	if (params->protocol == TR_PROTO_UDP && inner_ip->ip_p != IPPROTO_UDP)
	{
		return (0);
	}

	// On s'assure ensuite que le port de destination correspond bien à celui de la probe envoyée
	if (dport != current_port)
	{
		return (0);
	}

	return (1);
}

static int
is_valid_icmp_response(struct icmp *icmp, uint32_t current_port, struct tr_params *params)
{
	if (icmp->icmp_type == ICMP_ECHOREPLY)
	{
		/**
		 * Lorsque la destination est atteinte, elle envoie un message ICMP de type 0 (Echo Reply).
		 * On s'assure que les informations contenues dans trame ICMP recues correspondent à la probe envoyée
		 * en comparant les identifiants et les numéros de séquence.
		 */

		if (icmp->icmp_id != htons(getpid() & 0xFFFF))
			return (0);

        if (icmp->icmp_seq != htons(current_port))
			return (0);

        return (1);
	}
	else if (icmp->icmp_type == ICMP_TIMXCEED)
	{
		/**
		 * Lorsque le TTL expire, le routeur envoie un message ICMP de type 11 (Time Exceeded),
		 * est inclue dans le réponse ICMP la requête IP originale ayant provoqué le message ICMP,
		 * ce qui permet d'identifier la probe correspondante.
		 */
		struct ip *inner_ip = (struct ip *)(icmp->icmp_data);
		int inner_len = inner_ip->ip_hl * 4;

		// Extraction de la trame ICMP originale renvoyée par le routeur
		struct icmp *inner_icmp = (struct icmp *)((uint8_t *)inner_ip + inner_len);
		
		// On s'assure que les informations contenues dans trame ICMP recues correspondent à la probe envoyée

		if (inner_icmp->icmp_type != ICMP_ECHO)
			return (0);

		if (inner_icmp->icmp_id != htons(getpid() & 0xFFFF))
			return (0);

		if (inner_icmp->icmp_seq != htons(current_port))
			return (0);	

		return (1);
	}

	return (0);
}

int
is_valid_response(struct icmp *icmp, uint32_t current_port, struct tr_params *params)
{
	switch (params->protocol)
	{
	case TR_PROTO_UDP:
		return (is_valid_udp_response(icmp, current_port, params));
	case TR_PROTO_ICMP:
		return (is_valid_icmp_response(icmp, current_port, params));
	case TR_PROTO_TCP:
	case TR_PROTO_GRE:
		tr_err("protocol response validation not implemented");
		return (0);
	}
	return (0);
}