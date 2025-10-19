/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   debug.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/19 21:47:41 by mgama             #+#    #+#             */
/*   Updated: 2025/10/19 22:04:44 by mgama            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <stdint.h>

void _print_ip(uint32_t ip, const char* msg);
void _print_icmp(uint8_t *packet, size_t packet_size);
void _print_icmp_header(struct icmp *icmp);

#endif /* DEBUG_H */