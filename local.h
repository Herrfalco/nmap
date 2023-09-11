/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   local.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fcadet <fcadet@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/11 14:54:38 by fcadet            #+#    #+#             */
/*   Updated: 2023/09/11 15:38:35 by fcadet           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LOCAL_H
#define LOCAL_H

#include "parse.h"

typedef struct			local_s {
	char				dev_name[BUFF_SZ];
	struct sockaddr_in	addr;
}						local_t;

extern local_t			LOCAL;

#endif // LOCAL_H