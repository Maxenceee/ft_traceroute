/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   addresses.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/19 21:57:01 by mgama             #+#    #+#             */
/*   Updated: 2025/10/20 12:15:52 by mgama            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "traceroute.h"
#include "debug.h"

int
_assign_iface(int sock, struct tr_params *params)
{
	if (params->ifname == NULL)
		return (1);

	struct ifaddrs *ifap, *ifa;

	(void)getifaddrs(&ifap);
	for (ifa = ifap; ifa; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr->sa_family == AF_INET && (ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING) && strcmp(ifa->ifa_name, params->ifname) == 0)
		{
			break;
		}
	}
	if (!ifa)
	{
		tr_err("Can't find current interface");
		freeifaddrs(ifap);
		return (1);
	}

	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, params->ifname, strlen(params->ifname)) < 0)
	{
		tr_perr("setsockopt");
		return (1);
	}

	struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
	params->local_addr = sa->sin_addr.s_addr;

	freeifaddrs(ifap);
	return (0);
}

int
assign_iface(int sock, uint32_t dst_addr, struct tr_params *params)
{
	struct ifaddrs *ifap, *ifa;

	if (params->ifname && _assign_iface(sock, params))
	{
		return (1);
	}
	else if (!params->ifname)
	{
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

		struct sockaddr_in dst;
		memset(&dst, 0, sizeof(dst));
		dst.sin_family = AF_INET;
		dst.sin_port = htons(53);
		dst.sin_addr.s_addr = dst_addr;

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
	}

	/**
	 * Afin de récupérer le nom de l'interface réseau utilisée pour atteindre
	 * la destination, nous parcourons la liste des interfaces réseau et on compare
	 * l'adresse IP locale obtenue précédemment.
	 */

	if (verbose(params->flags))
	{
		(void)getifaddrs(&ifap);
		for (ifa = ifap; ifa; ifa = ifa->ifa_next)
		{
			if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET)
			{
				struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
				if (sa->sin_addr.s_addr == params->local_addr)
				{
					printf("Using interface: %s\n", ifa->ifa_name);
				}
			}
		}
	
		freeifaddrs(ifap);
	}

	return (0);
}

uint32_t
get_destination_ip_addr(const char *host, struct tr_params *params)
{
	(void)params;

	struct in_addr in;

	// Sauvegarde le nom d'hôte dans les paramètres
	params->dest_host = host;

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

		// Conversion de l'adresse IP binaire en chaîne de caractères
		(void)inet_ntop(AF_INET, hostent->h_addr_list[0], params->dest_ip_str, sizeof(params->dest_ip_str));

		/**
		 * L'implémentation de traceroute de BSD avertit lorsque
		 * plusieurs adresses IP sont associées à un nom d'hôte et
		 * ne prend que la première adresse.
		 */
		if (hostent->h_addr_list[1] != NULL)
		{
			(void)fprintf(stderr, TR_PREFIX": Warning: %s has multiple addresses; using %s\n", host, params->dest_ip_str);
		}

		char **addr = hostent->h_addr_list;
		memcpy(&in, *addr, sizeof(struct in_addr));
	}

	return (in.s_addr);
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
