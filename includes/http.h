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

#ifndef H_HTTP
#define H_HTTP

#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "send.h"
#include "error.h"
#include "options.h"

#ifndef    __bool_true_false_are_defined
#   define   bool   int
#   define   true    1
#   define   false   0
#   define __bool_true_false_are_defined
#endif

unsigned int get_contentlength(char *, int);
unsigned int get_effective_length(char *, int);
int get(char **, t_datathread *, char **, char **);
int post(char **, t_datathread *, char *, char *);
int basic_auth(char **, t_datathread *, char *, char *);
int headers(char **, t_datathread *, char *, char *);
void disp_cookies(t_cookies);
void new_cookie(t_cookies *, char *, unsigned int);
bool get_cookie(char *, int, t_options *);
bool get_connectionclose(char *, int);
bool get_chunked(char *, int);
bool end_chunck(char *, int);
bool get_location(char *,char *, int);
bool detect_header(char *, int);
bool checkhost(s_headers, char*);
char *basic_authent(char *, char *);
bool proxy_connect(char **, t_datathread *);
bool chk_connect(char *);
void prepare_connect(t_datathread *, int);
void add_proxy_header(t_datathread *, char *);
#endif 
