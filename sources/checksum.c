/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   checksum.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/19 21:51:42 by mgama             #+#    #+#             */
/*   Updated: 2025/10/19 21:52:01 by mgama            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "traceroute.h"

uint16_t
tcp_checksum(const void *buf, size_t len)
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

uint16_t
icmp_checksum(const void *data, size_t len)
{
    const uint16_t *ptr = data;
    uint32_t sum = 0;
    size_t nleft = len;

    while (nleft > 1) {
        sum += *ptr++;
        nleft -= 2;
    }

    if (nleft == 1) {
        uint16_t odd_byte = 0;
        *(uint8_t *)&odd_byte = *(const uint8_t *)ptr;
        sum += odd_byte;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum);
}
