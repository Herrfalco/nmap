/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thrds.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/11 20:28:46 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/11 20:56:00 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef THRDS_H
#define THRDS_H

#include "packet.h"

typedef struct	job_s {
	uint64_t	idx;
	uint64_t	nb;
}				job_t;

extern int		SEND_SOCK;

#endif // THRDS_H
