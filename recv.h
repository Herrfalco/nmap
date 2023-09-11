/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   recv.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/11 10:05:19 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/11 10:13:51 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef RECV_H
#define RECV_H

#include "includes.h"

typedef enum			result_e {
	R_NONE,
	R_OPEN,
	R_CLOSE,
	R_FILTERED,
}						result_t;

typedef result_t		assess_t[MAX_IPS][MAX_PORTS][SCANS_NB];

assess_t				ASS;

#endif // RECV_H
