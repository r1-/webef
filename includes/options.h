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

#ifndef H_OPTIONS
#define H_OPTIONS

#include <sys/types.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>

#ifndef    __bool_true_false_are_defined
#   define   bool   int
#   define   true    1
#   define   false   0
#   define __bool_true_false_are_defined
#endif

typedef struct {
          char *mid;
          char *end;
} s_headers;

typedef struct s_cookies {
          char *cookie;
          struct s_cookies *next_cook;
} s_cookies;

typedef s_cookies *t_cookies;


#define TYPE_FUZZ_FILE 1
#define TYPE_FUZZ_RANGE 2

typedef struct s_options {
          unsigned int type_fuzz; /* 1=file 2=range 3 ... */
          unsigned int thread;

          struct {
                    char *host;
                    char *url_pre;
                    char *url_mid;
                    char *url_end;
                    bool ssl;
                    unsigned short port;
                    char ch_port[6];
          } url;

          /* struct hostent *dns_host; */
		    char *dns_host;
		    char ip_host[INET6_ADDRSTRLEN+1];

          char *file1;
          unsigned int line_file1;
          unsigned int line_file2;
          char *file2;
          char *range;
          char *range2;
          char *method;

          bool urlfuzz;
          bool headfuzz;
          bool quiet;
          bool onefuzz;
          bool twofuzz;
          bool inj;
          bool debug;
          unsigned int url_length;
          bool agressive;
          unsigned int wait;
          short encod;
          char *cert;
          char *key;
          short ssl_version;
          char *location;
          SSL_CTX *ctx;

          t_cookies cookies;

          struct {
                    char *post_pre;
                    char *post_mid;
                    char *post_end;
          } post;

          struct {
                    char *user;
                    char *pass;
                    int type; //1=basic
          } auth;

          s_headers head;

          struct {
                    char *ip;
                    unsigned short port;
			      char ch_port[6]; 
          } proxy;

          char *headers;

          char *hide;
          int size_down;
          int size_up;
          unsigned long count;
          unsigned int error;
} t_options;

void usage(char* );
void init_options(t_options *);
void get_options(int, char **, t_options *);
int parse_url(char*, t_options *);
void parse_post(char*, t_options *);
void parse_proxy(char*, t_options *);
bool parse_headers(char*, t_options *);
void parse_range_size(char*, t_options *);
void parse_cert(char *, t_options *);
void parse_key(char *, t_options *);
bool parse_auth(char *, t_options *);
bool fuzz_headers(t_options *);
void add_headers(char *, t_options *);
void add_file(char*, t_options *, int);
#endif
