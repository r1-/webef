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

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>

#include "options.h"
#include "error.h"

void initssl()
{
          CRYPTO_malloc_init();
          SSL_library_init();
          SSL_load_error_strings();
}

SSL *opensocks(int sock, t_options *data)
{
          int ret_sslconnect=0;
          SSL *ssl;
          X509            *server_cert;

          ssl=SSL_new(data->ctx);
          EXIT_IFNULL(ssl, "SSL error ssl context");

          if (!SSL_set_fd(ssl,sock))
                    EXIT_IFNULL(ssl, "SSL error set sock");

          ret_sslconnect = SSL_connect(ssl);
          EXIT_SSL(ret_sslconnect, "SSL handshake error");

          server_cert = SSL_get_peer_certificate(ssl);
          X509_free(server_cert);

          return(ssl);
}

void closesocks(SSL **ssl, int sock)
{
          int ret;
          SSL_set_shutdown(*ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
          ret = SSL_shutdown(*ssl);
          if(ret == 0) {
                    ret = SSL_shutdown(*ssl);
                    printf("\n %i \n",SSL_get_error(*ssl, ret));
          }
          EXIT_SSL(ret, "SSL shutdown error");
          SSL_free(*ssl);
          close(sock);
}

