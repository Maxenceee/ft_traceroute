/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mgama <mgama@student.42lyon.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/10/19 21:49:54 by mgama             #+#    #+#             */
/*   Updated: 2025/10/19 21:50:18 by mgama            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "traceroute.h"

static int
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
