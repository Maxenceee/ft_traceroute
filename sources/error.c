/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   error.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/19 21:48:57 by mgama             #+#    #+#             */
/*   Updated: 2025/10/20 00:24:08 by mgama            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "traceroute.h"

void
tr_err(const char *msg)
{
	(void)fprintf(stderr, TR_PREFIX": %s\n", msg);
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
