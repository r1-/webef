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
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "fuzz.h"
#include "file.h"
#include "http.h"
#include "options.h"
#include "send.h"
#include "error.h"
#include "ssl.h"
#include "inject.h"

static pthread_mutex_t *lock_cs;
static long *lock_count;

int fuzz(t_options options)
{
	int ret;

	if(options.inj)
		sock4cookie(&options);

	if(options.type_fuzz == 1) /* type dictionary file*/
	{
		ret=fuzz_file(options);
	}
	return (ret);
}

static void *fuzzthread(void *arg)
{
	thread_info *tinfo = (thread_info *) arg;
	t_datathread *data = tinfo->data;
	unsigned int jump=data->opt.thread;
	unsigned int start=tinfo->thread_num, i;
	unsigned int end=data->tabsize;
	int sock;
	int ret;
	SSL *ssl= NULL;
	FILE *fic2;
	char *word2;

	if(data->opt.agressive)
	{
		sock=opensock(data);

		if(data->opt.url.ssl && data->opt.proxy.ip != NULL)
		{
			prepare_connect(data, sock);
			ssl=opensocks(sock, &data->opt);
		}
		else
			if(data->opt.url.ssl)
				ssl=opensocks(sock, &data->opt);
	}

	for(i=start;i<end;i=i+jump)
	{
		if(data->opt.twofuzz)
		{
			if(!(fic2= openfile(data->opt.file2)))
			{
				perror("open file");
				exit(0);
			}

			while(getword(fic2, &word2))
			{
				ret=sendfuzz(data, &(data->tabword[i]), &word2, sock, ssl);
				FREE_BUF(word2);

				if(ret==-2)
				{
					data->opt.error++;
					fprintf(stderr, "URL error %i\r", data->opt.error);
					if(data->opt.debug)
						printf("\n");
				}
				if(data->opt.agressive)
				{
					if(ret==-1)
					{
						if(data->opt.url.ssl)
						{
							closesocks(&ssl, sock);
							sock=opensock(data);
							if(data->opt.proxy.ip != NULL)
								prepare_connect(data, sock);
							ssl=opensocks(sock, &data->opt);
	
						}
						else
						{
							close(sock);
							sock=opensock(data);
							RETURN_NULL_IFNEG(sock);
						}
					}
				}
			}
			fclose(fic2);
		}
		else
		{
			ret=sendfuzz(data, &data->tabword[i], NULL, sock, ssl);
			if(ret==-2)
			{
				data->opt.error++;
				fprintf(stderr, "URL error %i\r", data->opt.error);
				if(data->opt.debug)
					fprintf(stderr, "\n");
			}
			if(data->opt.agressive)
			{
				if(ret==-1)
				{
					if(data->opt.url.ssl)
					{
						closesocks(&ssl, sock);
						sock=opensock(data);
						if(data->opt.proxy.ip != NULL)
								prepare_connect(data, sock);
						ssl=opensocks(sock, &data->opt);
					}
					else
					{
						close(sock);
						sock=opensock(data);
						RETURN_NULL_IFNEG(sock);
					}
				}
			}
		}
		FREE_BUF(data->tabword[i]);
	}
	
	if(data->opt.agressive)
	{
		if(data->opt.url.ssl)
			closesocks(&ssl, sock);
		else
			close(sock);
	}
	return NULL;
}

int fuzz_file(t_options options) 
{
	FILE *fic;
	t_datathread data;
	unsigned int i=0;
	char *buf[MAX_FILE];
	unsigned int bufsize=0;
	int error=0;
	thread_info *tinfo;

	if(!(fic= openfile(options.file1)))
	{
		fprintf(stderr, "File error\n");
		return (-1);
	}	
	entete(options);
	data.opt=options;
	
	tinfo = calloc(options.thread, sizeof(thread_info));
	RETURN_IFNULL(tinfo);
	data.opt.count=1;

	while(loadfile(fic, buf, &bufsize)) 
	{
		data.tabword=buf;
		data.tabsize=bufsize;

		if(options.url.ssl)
			thread_setup();
		else
			options.ctx=NULL;

		for(i=0; i< options.thread;i++)
		{
			tinfo[i].thread_num = i ;
			tinfo[i].data=&data;
			
			pthread_create( &tinfo[i].thread_id, NULL, fuzzthread, (void *) &tinfo[i]);
		}

		for(i=0; i<options.thread; i++)
			pthread_join(tinfo[i].thread_id, NULL);

		if(options.url.ssl)
			pthread_cleanup();
	}
	fclose(fic);
	
	SSL_CTX_free(options.ctx);
	error=data.opt.error;
	FREE_BUF(tinfo);
	return (error);
}

void entete(t_options opt)
{
	unsigned long count=opt.line_file1;

	if(opt.twofuzz)
		count = 	opt.line_file1 * opt.line_file2;
	
	if(opt.quiet == 1 ) 
	{
		printf("\nTarget: http%s://%s:%d%sFUZZ%s%s\n",
			(opt.url.ssl == 1 ? "s" : ""),
			opt.url.host, opt.url.port, opt.url.url_pre,
			(opt.url.url_mid ? opt.url.url_mid : ""),
			(opt.url.url_end ? opt.url.url_end : "") );
   } 
	else 
	{
		printf(" __    __     _           __ ");
		printf("\n/ / /\\ \\ \\___| |__   ___ / _|");
		printf("\n\\ \\/  \\/ / _ \\ '_ \\ / _ \\ |_ ");
		printf("\n \\  /\\  /  __/ |_) |  __/  _|");
		printf("\n  \\/  \\/ \\___|_.__/ \\___|_| ");
		printf("\n");
		printf("\n- Web fuzzer");
		printf("\n- Target Hostame: %s", opt.url.host);
		printf("\n- Target Port: %i", opt.url.port); 
		printf("\n- Use SSL : ");
		if(opt.url.ssl==1)
			printf("Yes");
		else
			printf("No");
		printf("\n- Fuzz Type : ");
		switch(opt.type_fuzz)
		{
			case 1: printf("file"); break;
			case 2: printf("range"); break;
		}
		if(opt.proxy.ip != NULL)
		{
			printf("\n- Use Proxy : %s", opt.proxy.ip);
			if(opt.proxy.port!=0)
				printf(":%i", opt.proxy.port);
		}	
		printf("\n- Size : %ld", count);
		printf("\n____________________________________________________________________\n");
		if(opt.inj)
			printf("\n Code \t\t   size \t delay \t\t\t     FUZZ");
		else
			printf("\n Code \t\t   size \t\t\t     FUZZ");
		if(opt.twofuzz)
			printf("/FUZ2Z");
		printf("\n____________________________________________________________________\n");
	}
}

void thread_setup(void)
{
	int i;

	lock_cs=OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	lock_count=OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
	for (i=0; i<CRYPTO_num_locks(); i++)
	{
		lock_count[i]=0;
		pthread_mutex_init(&(lock_cs[i]),NULL); 
	}

	CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
	CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);
}

unsigned long pthreads_thread_id(void)
{
	unsigned long ret;
	ret=(unsigned long)pthread_self();
	return(ret);
}

void pthreads_locking_callback(int mode, int type, char *file, int line)
{
	if (mode & CRYPTO_LOCK)
	{
		pthread_mutex_lock(&(lock_cs[type]));
		lock_count[type]++;
	}
	else
		pthread_mutex_unlock(&(lock_cs[type]));
}	

void pthread_cleanup(void)
{
	int i;
	CRYPTO_set_locking_callback(NULL);

	for (i=0; i<CRYPTO_num_locks(); i++)
		pthread_mutex_destroy(&(lock_cs[i]));

	OPENSSL_free(lock_cs);
	OPENSSL_free(lock_count);
}

