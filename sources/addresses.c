/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   addresses.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/19 21:57:01 by mgama             #+#    #+#             */
/*   Updated: 2025/10/19 23:45:09 by mgama            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "traceroute.h"
#include "debug.h"

int
assign_iface(int sock, struct tr_params *params)
{
	struct ifaddrs *ifap, *ifa, *curr, *assigned = NULL;

	(void)getifaddrs(&ifap);
	for (ifa = ifap; ifa; ifa = ifa->ifa_next)
	{
		if (params->ifname != NULL && (ifa->ifa_flags & IFF_UP) && strcmp(ifa->ifa_name, params->ifname) == 0)
		{
			assigned = ifa;
		}
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET)
		{
			struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
			_print_ip(sa->sin_addr.s_addr, ifa->ifa_name);
			if (sa->sin_addr.s_addr == params->local_addr)
				curr = ifa;
		}
	}

	if (curr == NULL)
	{
		tr_err("Can't find current interface");
		freeifaddrs(ifap);
		return (0);
	}

	if (params->ifname != NULL && assigned == NULL)
	{
		(void)fprintf(stderr, TR_PREFIX": Can't find interface %s\n", params->ifname);
		freeifaddrs(ifap);
		return (0);
	}
	else if (params->ifname != NULL && assigned != NULL)
	{
		if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, params->ifname, strlen(params->ifname)) < 0)
		{
			tr_perr("setsockopt");
			freeifaddrs(ifap);
			return (0);
		}
		curr = assigned;
	}

	if (verbose(params->flags))
	{
		printf("Using interface: %s\n", curr->ifa_name);
	}

	freeifaddrs(ifap);
	return (1);
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
			(void)inet_ntop(AF_INET, hostent->h_addr_list[0], ip_str, sizeof(ip_str));
			(void)fprintf(stderr, TR_PREFIX": Warning: %s has multiple addresses; using %s\n", host, ip_str);
		}

		char **addr = hostent->h_addr_list;
        memcpy(&in, *addr, sizeof(struct in_addr));
	}

	/**
	 * Notre programme nécessite de connaître l'adresse IP locale utilisée
	 * pour envoyer des paquets vers la destination, afin de construire
	 * des en-têtes IP appropriés.
	 * 
	 * Pour cela, on crée un socket UDP temporaire et on se connecte
	 * à l'adresse de destination. Cela permet au système d'exploitation
	 * de déterminer l'adresse IP locale à utiliser pour l'envoi des paquets
	 * ainsi que l'interface réseau correspondante.
	 */

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
	{
		tr_perr("socket");
		return (0);
	}

	if (params->ifname != NULL && setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, params->ifname, strlen(params->ifname)) < 0)
	{
		tr_perr("setsockopt");
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
		return (0);
	}

	params->local_addr = local.sin_addr.s_addr;

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
	{
		tr_err("TCP protocol not implemented");
		return (0);
	}
	else if (strcmp(proto_str, "gre") == 0 || strcmp(proto_str, "GRE") == 0)
	{
		tr_err("GRE protocol not implemented");
		return (0);
	}

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
