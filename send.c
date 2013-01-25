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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/err.h>

#include "send.h"
#include "options.h"
#include "error.h"
#include "http.h"
#include "ssl.h"
#include "inject.h"

static pthread_mutex_t mutex_print = PTHREAD_MUTEX_INITIALIZER;

int parse_response(
	char *buf, 
	int size_buf, 
	unsigned int size, 
	t_response *resp, 
	t_options *opt, 
	char *w1, 
	char *w2)
{
	unsigned int i=9;
	char *p;
	int error=1;
	bool display=true;

	if(strncmp(buf, "HTTP/1.",7))
		error=-1;
	else
	{
		while(buf[i]==' ' && i<size_buf)
			i++;

		p=&(buf)[i];		
		strncpy(resp->code, p, 3);
		resp->code[3]='\0';
		resp->size=size_buf;	
	}

	pthread_mutex_lock(&mutex_print);

		if(opt->location !=NULL && get_location(opt->location, buf, strlen(buf)))
			display=false;
		
		if(strstr(opt->hide, resp->code))
			display=false;

		if( (opt->size_down != -1) &&   // if -n is set
			 ( (opt->size_down == size && opt->size_up == -1) ||  // AND if -n contain one single number 
				(opt->size_down <= size && opt->size_up != -1 && opt->size_up >= size) // OR if -n contain range numbers
			 ))
					display=false;

		printf("*%4ld ", opt->count);
		opt->count++;

		if(display)
		{
			printf("[%s]", resp->code);
			if(size == -1)
			{
				if(opt->agressive)
					printf("\t%7d ", size_buf);
				else
					printf("\t%7d* ", size_buf);
			}
			else
				printf("\t%7d ", size);

			printf("\t %24s", w1);
			if(opt->twofuzz)
				printf("/%s", w2);
			printf("\n");
		}
		else
			printf("\r");
	pthread_mutex_unlock(&mutex_print);

	return (error);
}

int opensock(t_datathread *data)
{
	struct hostent *hostent;
	int sock_cli;
	struct sockaddr_in sin;
	in_addr_t addr;
	hostent=data->opt.dns_host;	
	memcpy(&addr, *hostent->h_addr_list, sizeof(addr));

	RETURN_ERR(sock_cli=socket(PF_INET, SOCK_STREAM, 0), "socket error");

	sin.sin_addr.s_addr = addr;
	sin.sin_family = AF_INET;

	if(data->opt.proxy.ip != NULL)
		sin.sin_port = htons(data->opt.proxy.port);
	else	
		sin.sin_port = htons(data->opt.url.port);

	EXIT_IFNEG(connect(sock_cli, &sin, sizeof(sin)), "connect error");

	return sock_cli;
}

int sendfuzz(
	t_datathread *data, 
	char **word1, char **word2, 
	int sock_cli, 
	SSL *ssl)
{
	char *url=NULL;
	char *receive=NULL;
	int ret, size, prep;
	unsigned int  contentsize;
	t_response response;

	if (!data->opt.agressive)
	{
		if((sock_cli=opensock(data)) == -1)
		{
			data->opt.error++;
			if(data->opt.debug)
				fprintf(stderr, "\n");
		}
		if(data->opt.url.ssl && data->opt.proxy.ip != NULL)
		{
			prepare_connect(data, sock_cli);
			ssl=opensocks(sock_cli, &data->opt);
		}
		else
			if(data->opt.url.ssl)
				ssl=opensocks(sock_cli, &data->opt);
	}

	strcpy(response.code,"000");

	if(data->opt.inj)
	{
		prep=inject_header(&(url), data, *word1, sock_cli, ssl );
		EXIT_IFNEG(prep, "Too long url");

		//return -3 due to specific processing in mod
		return(-3);
	}
	else 
	{
		if(data->opt.auth.type==1 && (data->opt.auth.user==NULL || data->opt.auth.pass==NULL))
		{
			if(word2==NULL)
				prep=basic_auth(&(url), data, *word1, NULL);
			else
				prep=basic_auth(&(url), data, *word1, *word2);
		}
		else
		{
			if(data->opt.headfuzz)
			{
				if(word2==NULL)
					prep=headers(&(url), data, *word1, NULL);
				else
					prep=headers(&(url), data, *word1, *word2);
			}
			else
			{	
				if( data->opt.urlfuzz )
					prep=get(&(url), data, word1, word2);
				else
				{
					if(word2==NULL)
						prep=post(&(url), data, *word1, NULL);
					else
						prep=post(&(url), data, *word1, *word2);
				}
			}
		}
	}
	if(prep!=-2)
	{
		size = iosocket(sock_cli, url, &receive, data->opt, ssl, &contentsize);
		if(size == -1)
			if(data->opt.debug)
				fprintf(stderr, "\n");
		RETURN_NEG_IFNEG(size);

		if(word2==NULL)
			ret=parse_response(receive, size, contentsize, &response, &(data->opt), *word1, NULL);
		else
			ret=parse_response(receive, size, contentsize, &response, &(data->opt), *word1, *word2);
		sleep(data->opt.wait);	
	}
	
	if(!data->opt.agressive)
	{
		if(data->opt.url.ssl)
			closesocks(&ssl, sock_cli);
		else
			close(sock_cli);
	}

	free(url);

	if(prep == -2)
		return(-2);

	if(get_connectionclose(receive, size))
	{
		FREE_BUF(receive);
		return (-1);
	}

	FREE_BUF(receive);
	return (ret);		

}

int iosocket(
	int sock, 
	char *buf, 
	char **receipt, 
	t_options opt, 
	SSL *ssl, 
	unsigned int *content_length)
{
	char tmp_buf[MAX_SIZE_READ];
	memset(tmp_buf, 0, MAX_SIZE_READ);
	unsigned int effective_length, size_read;
	int count=0;
	char *recv=NULL;	
	bool chk=false, chunk;

if(opt.debug) printf("\n***send*** %s",buf);

	if(opt.url.ssl)
	{
		EXIT_IFNEG(SSL_write(ssl, buf, strlen(buf)),"SSL_write error");
		do
			count = SSL_read(ssl, tmp_buf, MAX_SIZE_READ-1);
		while ( (count <= -1) 
         && ((SSL_get_error (ssl, count) == SSL_ERROR_SYSCALL
         && errno == EINTR) ||
			(SSL_get_error (ssl, count) == SSL_ERROR_SSL)));
		EXIT_IFNEG(count, "SSL_read error");
if(opt.debug) printf("\n %s",tmp_buf);
	}	
	else
	{
		send(sock, buf, strlen(buf), 0);
		count = read(sock, tmp_buf, MAX_SIZE_READ-1);
	}
	RETURN_ERR(count, "Fail to read on socket");

	recv = malloc(count+1);
	memset(recv, 0, count+1);
	strncpy(recv, tmp_buf, count);
	size_read = count;
	*content_length = get_contentlength(recv, count);

	if(opt.agressive)
	{
		if( opt.method != NULL && strcmp(opt.method, "HEAD") == 0)
		{
			while(!detect_header(recv,count))
			{
				memset(tmp_buf, 0, MAX_SIZE_READ);
				count = read(sock, tmp_buf, MAX_SIZE_READ-1);
				recv = realloc(recv, size_read + count + 1);
				EXIT_IFNULL(recv, "Memory error");
printf("\n %s",tmp_buf);
				strncat(recv, tmp_buf, count);
				size_read += count;
			}
			*receipt = recv;
			return (size_read);
		}
		chunk = get_chunked(recv, count);
		if(chunk)
		{
			chk=end_chunck(tmp_buf, count);
			while(!chk)
			{
				memset(tmp_buf, 0, MAX_SIZE_READ);

				if(opt.url.ssl)
				{
					do
						count = SSL_read(ssl, tmp_buf, MAX_SIZE_READ-1);
					while ( (count <= -1) 
						&& ((SSL_get_error (ssl, count) == SSL_ERROR_SYSCALL
						&& errno == EINTR) ||
						(SSL_get_error (ssl, count) == SSL_ERROR_SSL)));
					EXIT_IFNEG(count, "SSL_read error");
				}
				else
					count = read(sock, tmp_buf, MAX_SIZE_READ-1);

				chk = end_chunck(tmp_buf, count);
				effective_length += count;
				recv = realloc(recv, size_read + count + 1);
				EXIT_IFNULL(recv, "Memory error");
				strncat(recv, tmp_buf, count);
				size_read += count;
			}
		}
		else
		{
			effective_length = get_effective_length(recv,count);
			while(effective_length < *content_length)
			{
				memset(tmp_buf, 0, MAX_SIZE_READ);
				if(opt.url.ssl)
				{
					do
						count = SSL_read(ssl, tmp_buf, MAX_SIZE_READ-1);
					while ( (count <= -1) 
						&& ((SSL_get_error (ssl, count) == SSL_ERROR_SYSCALL
						&& errno == EINTR) ||
						(SSL_get_error (ssl, count) == SSL_ERROR_SSL)));
					EXIT_IFNEG(count, "SSL_read error");
				}
				else
					count = read(sock, tmp_buf, MAX_SIZE_READ-1);

				effective_length += count;
				recv = realloc(recv, size_read + count + 1);
				EXIT_IFNULL(recv, "Memory error");
				strncat(recv, tmp_buf, count);
				size_read += count;
			}
		}
	}
	*receipt = recv;
	return (size_read);
}

