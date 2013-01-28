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

#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <time.h>

#include "options.h"
#include "fuzz.h"
#include "error.h"

void the_end(t_options *opt, int error)
{
          FREE_BUF(opt->hide);
          FREE_BUF(opt->url.host);
          FREE_BUF(opt->file1);
          FREE_BUF(opt->file2);
// TODO : clean struct cookies
          EVP_cleanup();
          ERR_free_strings();
          CRYPTO_cleanup_all_ex_data();
          ERR_remove_state(0);
          CONF_modules_unload(1);

          printf("                                                                                       \
				 \n");
          if(error)
                    printf("Error : %i\n", error);
}

int main(int argc, char** argv)
{
          t_options opt;
          int ret = -1;
	  time_t start_time, end_time;
	  unsigned long execution_time = -1;

	  memset(&opt, 0, sizeof(t_options));
	  start_time = end_time = (time_t) -1;
	  
          get_options(argc, argv, &opt);
	  start_time = time(NULL);
          ret=fuzz(opt);
	  end_time = time(NULL);

	  if (start_time != (time_t) -1 && end_time != (time_t) -1 ) {
		    execution_time = end_time - start_time;
		    printf("\n");
		    printf("Execution time was : %ld sec\n", execution_time);
	  }
	  
          the_end(&opt, ret);
          return (0);
}
