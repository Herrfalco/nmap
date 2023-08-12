/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   includes.h                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/08/12 15:00:44 by fcadet            #+#    #+#             */
/*   Updated: 2023/08/12 15:01:19 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef INCLUDES_H
#define INCLUDES_H

#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#define				MAX_PORTS		1024
#define				MAX_PORT_VAL	65535
#define				MAX_IPS			512
#define				MAX_IP_SZ		15
#define				FILE_SZ			((MAX_IP_SZ + 1) * MAX_IPS)
#define				MAX_THRDS		250
#define				FLAGS_NB		6
#define				SCANS_NB		6

#endif // INCLUDES_H
