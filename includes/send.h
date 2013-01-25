/*
** Copyright (C) 2010 Yves LE PROVOST
** $Id$
** 
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with This program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
** 
** Additional permission under GNU GPL version 3 section 7
**
** If you modify this program, or any covered work, by linking or
** combining it with the OpenSSL project's OpenSSL library (or a
** modified version of that library), containing parts covered by the
** terms of the OpenSSL or SSLeay licenses, the Free Software Foundation
** grants you additional permission to convey the resulting work.
** Corresponding Source for a non-source form of such a combination
** shall include the source code for the parts of OpenSSL used as well
** as that of the covered work.  
*/

#ifndef H_SEND
#define H_SEND

#include "options.h"
#include "fuzz.h"
#include "resp.h"
#include "ssl.h"

#define MAX_SIZE_READ 4096 
#define MAX_SIZE_URL	1024
#define DEBUG 0

int parse_response(char *, int, unsigned int, t_response *, t_options *, char *, char *);
int opensock(t_datathread *);
int sendfuzz(t_datathread *, char **, char **, int, SSL *);
int iosocket(int, char *, char **, t_options, SSL *, unsigned int*);
#endif 
