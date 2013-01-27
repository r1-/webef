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

#ifndef H_FUZZ
#define H_FUZZ

#include "options.h"
#include "resp.h"
#include "file.h"

typedef struct s_datathread {
          t_options opt;
          char **tabword;
          unsigned int tabsize;
} t_datathread;

typedef struct s_thread_info {
          pthread_t thread_id;
          unsigned int       thread_num;
          t_datathread *data;
} thread_info;

int fuzz(t_options);
int fuzz_file(t_options);
void entete(t_options);
void thread_setup();
unsigned long pthreads_thread_id(void);
void pthreads_locking_callback(int, int, char *, int);
void pthread_cleanup();
#endif
