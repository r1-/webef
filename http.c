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

#include <string.h>
#include <stdio.h>

#include "send.h"
#include "error.h"
#include "http.h"
#include "encodage.h"

unsigned int get_contentlength(char *buf, int size)
{
	char * tmp=NULL;
	unsigned int i=15,j=0;
	char charlength[16];

	tmp = strcasestr(buf, "Content-Length: ");
	if(tmp == NULL)
		return 0;
	
	while(tmp[i] == ' ' && i < size)
		i++;

	while(((int) tmp[i])> 47 && ((int) tmp[i])< 58 && j<15 && i < size  )
	{
		charlength[j++]=tmp[i]; 	
		i++;	
	}

	charlength[j]='\0';

	if(DEBUG)
		printf("Content-Length : %i\n", atoi(charlength));

	return (unsigned int) atoi(charlength);
}

/*void disp_cookies(t_cookies cook)
{
		while(cook!=NULL)
		{
			printf("\n cookie : %s", cook->cookie);
			cook=cook->next_cook;
		} 
}*/

void new_cookie(t_cookies *l_cookies, char *cook, unsigned int length)
{
	s_cookies *c=malloc(sizeof(s_cookies));
	EXIT_IFNULL(c, "Memory Error");

	c->cookie=calloc(length+1,1);
	EXIT_IFNULL(c->cookie, "Memory Error");
	strncpy(c->cookie, cook, length);

	c->next_cook=*l_cookies;
	*l_cookies=c;
}

/*char *pop_cookie(t_cookies *cook)
{
	t_cookies tmp = *cook;
	if(tmp == NULL)
		return NULL;

	*cook=tmp->next_cook;
	return tmp->cookie;
}*/

bool get_cookie(char *buf, int size, t_options *opt)
{

	char *tmp=NULL;
	char *end_cook=NULL;
	char *end_value=NULL;
	unsigned int i = 11;
	unsigned int length;
	unsigned int lengthva;
	t_cookies cookies=NULL;
	
	while((tmp=strcasestr(buf, "Set-Cookie: "))!=NULL)
	{
		while(tmp[i] == ' ' && i < size)
			i++;

		end_cook=strstr(tmp+i, "\r\n");
		length = (unsigned int) ((unsigned long) end_cook - ((unsigned long) (tmp+i)) +1); 
		end_value=strchr(tmp+i, ';');
		if(end_value == NULL || end_value > end_cook)
			lengthva=length;
		else
			lengthva= (unsigned int) ((unsigned long) end_value - ((unsigned long) (tmp+i))); 

		new_cookie(&cookies, tmp+i, lengthva);	
		buf=tmp+i+length;
		i=11;
	}
	opt->cookies=cookies;

	if(cookies==NULL)
		return false;
	else
		return true;
}

bool get_connectionclose(char *buf, int size)
{
	char * tmp=NULL;
	unsigned int i=11;
	
	tmp = strcasestr(buf, "Connection:");
	if(tmp == NULL)
		return false;

	while(tmp[i] == ' ' && i < size)
		i++;

	if(strncasecmp(tmp+i, "close", 5)==0)
		return true;

	return false;

}

bool get_chunked(char *buf, int size)
{

	char *tmp=NULL;
	unsigned int i=18;
	
	if(strlen(buf) < 18)
		return false;	
	tmp = strcasestr(buf, "Transfer-Encoding:");
	if(tmp == NULL)
		return false;

	while(tmp[i] == ' ' && i < size)
		i++;

	if(strncasecmp(tmp+i, "chunked", 7)==0)
		return true;

	return false;
}

bool get_location(char *search, char *buf, int size)
{

	char *tmp=NULL;
	char *p=NULL;
	char *loc=NULL;
	unsigned length;
	unsigned int i=10;
	
	if(strlen(buf) < 10)
		return false;	
	tmp = strcasestr(buf, "Location:");
	if(tmp == NULL)
		return false;

	while(tmp[i] == ' ' && i < size)
		i++;

	p=strstr(tmp+i, "\r\n");
	length = (unsigned int) ((unsigned long) p - ((unsigned long) (tmp+i)) +1); 

	//loc= calloc(length+1,1);
	loc= alloca(length+1);
	strncpy(loc, tmp+i, length);

	if(strstr(loc, search)!=NULL)
		return true;
	else
		return false;
}

bool end_chunck(char *buf, int size)
{
	char *tmp=NULL;
	if(!strncmp(buf, "0\r\n",3))
		return true;	

	tmp = strcasestr(buf, "\r\n0\r\n");
	if(tmp == NULL)
		return false;

	return true;
}

unsigned int get_effective_length(char * buf, int size)
{
	char *tmp;
	unsigned int i;
	tmp = memmem(buf, size, "\r\n\r\n", 4);
	if(tmp==NULL)	
		return(0);

	if(DEBUG)
		printf("Less head : %s\n", tmp);
	i = (unsigned int) ((unsigned long) size - (((unsigned long) tmp) - ((unsigned long) buf) + 4));
	return i;
}

bool detect_header(char *buf, int size)
{
	if(memmem(buf, size, "\r\n\r\n",4) != NULL)
		return true;
	return false;
}

int post(
	char **ressource, 
	t_datathread *data, 
	char *word1, 
	char *word2)
{
	char url[MAX_SIZE_URL] = { 0, };
	int size;
	char length[4] = { 0, };
	char *auth=NULL;

	if(data->opt.method != NULL && strlen(data->opt.method)< (MAX_SIZE_URL-2) )
	{
		strncpy(url, data->opt.method, strlen(data->opt.method));
		url[strlen(data->opt.method)]=' ';
		url[strlen(data->opt.method)+1]='\0';
	}
	else
	{
		strncpy(url, "POST ", 5);
		url[5]='\0';
	}

	add_proxy_header(data, url);

	if( (strlen(url)+strlen(data->opt.url.url_pre) + 1)>MAX_SIZE_URL)
		return(-2);

	strncat(url,data->opt.url.url_pre, strlen(data->opt.url.url_pre));

	if(!checkhost(data->opt.head, data->opt.headers))
	{
		if( (strlen(url) + 17 + strlen(data->opt.url.host) + 2 + 1)> MAX_SIZE_URL)
			return(-2);

		strncat(url," HTTP/1.1\r\nHost: ", 17);
		strncat(url,data->opt.url.host, strlen(data->opt.url.host));
		strncat(url,"\r\n", 2);
	}
	else
	{
		if((strlen(url) + 12) > MAX_SIZE_URL)
			return(-2);
		strncat(url," HTTP/1.1\r\n", 11);
	}
	
	if(data->opt.agressive)
	{
		if( (strlen(url) + 22 + 2 + 1)> MAX_SIZE_URL)
			return(-2);
		strncat(url,"Connection: Keep-alive",22); 
		strncat(url,"\r\n", 2);
	}

	if(data->opt.headers != NULL)
	{
		if( (strlen(url) + strlen(data->opt.headers) + 1 ) > MAX_SIZE_URL)
			return(-2);
		strncat(url, data->opt.headers, strlen(data->opt.headers));
	}

	size=strlen(data->opt.post.post_pre);
	if(data->opt.post.post_mid != NULL)
		size+=strlen(data->opt.post.post_mid);
	if(data->opt.post.post_end != NULL)
		size+=strlen(data->opt.post.post_end);
	if(word1!=NULL)
		size+=strlen(word1);
	if(word2!=NULL && data->opt.twofuzz)
		size+=strlen(word2);

	if(size<1000)
		sprintf(length, "%i", size);
	else
		exit(0);

	if( (strlen(url) + 16 + strlen(length) + 1 ) > MAX_SIZE_URL)
		return(-2);

	strncat(url, "Content-length: ",16);
	strncat(url, length, strlen(length));

	if ( (strlen(url) +3) > MAX_SIZE_URL)
		return(-2);

	strncat(url,"\r\n", 2);

	if(data->opt.auth.user!=NULL && data->opt.auth.pass!=NULL)
	{
		auth=basic_authent(data->opt.auth.user, data->opt.auth.pass);
		if( (strlen(url) +21+ strlen(auth) +2+1 ) > MAX_SIZE_URL)
			return(-2);
		strcat(url, "Authorization: Basic ");
		strcat(url, auth);
		strcat(url, "\r\n");
		FREE_BUF(auth);
	}

	if ( (strlen(url) +3) > MAX_SIZE_URL)
		return(-2);

	strncat(url,"\r\n", 2);

	if( (strlen(url)+strlen(data->opt.post.post_pre))>MAX_SIZE_URL)
		return(-2);

	strncat(url,data->opt.post.post_pre, strlen(data->opt.post.post_pre));

	if((strlen(url)+strlen(word1)+1)>MAX_SIZE_URL)
		return(-2);

	strncat(url,word1, strlen(word1));

	if(data->opt.post.post_mid!=NULL)
	{
		if( (strlen(url)+strlen(data->opt.post.post_mid)+1 > MAX_SIZE_URL))
			return (-2);
		strncat(url, data->opt.post.post_mid, strlen(data->opt.post.post_mid));
	}

	if(data->opt.twofuzz)
	{
		if( (strlen(url)+strlen(word2)+1>MAX_SIZE_URL))
			return(-2);

		strncat(url,word2, strlen(word2));
	}

	if(data->opt.post.post_end!=NULL)
	{
		if( (strlen(url)+strlen(data->opt.post.post_end)+1)>MAX_SIZE_URL)
			return (-2);
	
		strncat(url, data->opt.post.post_end, strlen(data->opt.post.post_end));
	}

	//*ressource = calloc(strlen(url),1);
	*ressource = malloc(strlen(url) + 1);
	memset(*ressource, 0, strlen(url)+1);
	EXIT_IFNULL(*ressource, "Memory Error");

	strncpy(*ressource, url, strlen(url));

	return(1);
}

void add_proxy_header(t_datathread *data, char url[])
{
	if( data->opt.url.ssl == 0 && data->opt.proxy.ip!= NULL && ((strlen(url) + strlen(data->opt.url.host) +8)< MAX_SIZE_URL))
	{
		strcat(url, "http://");
		strncat(url, data->opt.url.host, strlen(data->opt.url.host));
		if(data->opt.url.port != 80 && ((strlen(url) + strlen(data->opt.url.ch_port)+2) < MAX_SIZE_URL))
		{
			strcat(url, ":");
			strcat(url, data->opt.url.ch_port);
		}
	} 
}

int get(
	char **ressource, 
	t_datathread *data, 
	char **word1, 
	char **word2)
{
	char url[MAX_SIZE_URL] = { 0, };
	char *auth=NULL;
	size_t ressource_length = 0; // added by hugsy ??

	if(data->opt.method != NULL && strlen(data->opt.method)< (MAX_SIZE_URL-2))
	{
		strncpy(url, data->opt.method, strlen(data->opt.method));
		url[strlen(data->opt.method)]=' ';
		url[strlen(data->opt.method)+1]='\0';
	}
	else
	{
		strncpy(url, "GET ", 4);
		url[4]='\0';
	}

	add_proxy_header(data, url);

	if( (strlen(url)+strlen(data->opt.url.url_pre))>MAX_SIZE_URL)
		return(-2);

	strncat(url,data->opt.url.url_pre, strlen(data->opt.url.url_pre));
	
	if(data->opt.urlfuzz)
	{
		if(*word1 == NULL)
			return(-2);
		if(data->opt.encod != 0)
			urlencode(*word1, word1, strlen(*word1), data->opt.encod);

		if((strlen(url)+strlen(*word1)+1)>MAX_SIZE_URL)
			return(-2);

		strncat(url,*word1, strlen(*word1));
	}

	if(data->opt.url.url_mid!=NULL)
	{
		if( (strlen(url)+strlen(data->opt.url.url_mid)+1 > MAX_SIZE_URL))
			return (-2);
		strncat(url, data->opt.url.url_mid, strlen(data->opt.url.url_mid));
	}

	if(data->opt.twofuzz)
	{
		if(data->opt.encod != 0)
			urlencode(*word2, word2, strlen(*word2), data->opt.encod);

		if( (strlen(url)+strlen(*word2)+1>MAX_SIZE_URL))
			return(-2);

		strncat(url,*word2, strlen(*word2));
	}	

	if(data->opt.url.url_end!=NULL)
	{
		if( (strlen(url)+strlen(data->opt.url.url_end)+1)>MAX_SIZE_URL)
			return (-2);
	
		strncat(url, data->opt.url.url_end, strlen(data->opt.url.url_end));
	}

	if(!checkhost(data->opt.head, data->opt.headers))
	{
		if( (strlen(url) + 17 + strlen(data->opt.url.host) + 2 + 1)> MAX_SIZE_URL)
			return(-2);

		strncat(url," HTTP/1.1\r\nHost: ", 17);
		strncat(url,data->opt.url.host, strlen(data->opt.url.host));
		strncat(url,"\r\n", 2);
	}
	else
	{
		if((strlen(url) + 12)> MAX_SIZE_URL)
			return(-2);
		strncat(url," HTTP/1.1\r\n", 11);
	}

	if(data->opt.agressive)
	{
		if( (strlen(url) + 22 + 2 + 1)> MAX_SIZE_URL)
			return(-2);
		strncat(url,"Connection: Keep-alive",22); 
		strncat(url,"\r\n", 2);
	}

	if(data->opt.headers != NULL)
	{
		if( (strlen(url) + strlen(data->opt.headers) + 1 ) > MAX_SIZE_URL)
			return(-2);
		strncat(url, data->opt.headers, strlen(data->opt.headers));
	}

	if(data->opt.auth.user!=NULL && data->opt.auth.pass!=NULL)
	{
		auth=basic_authent(data->opt.auth.user, data->opt.auth.pass);
		if( (strlen(url) +21+ strlen(auth) +2+1 ) > MAX_SIZE_URL)
			return(-2);
		strcat(url, "Authorization: Basic ");
		strcat(url, auth);
		strcat(url, "\r\n");
		FREE_BUF(auth);	
	}

	if ( (strlen(url) +3) > MAX_SIZE_URL)
		return(-2);

	strncat(url,"\r\n", 2);

	ressource_length = strlen(url + 1);
	*ressource = calloc(ressource_length, 1);
	memset(*ressource, 0, ressource_length);
	EXIT_IFNULL(*ressource, "Memory Error");

	strncpy(*ressource, url, ressource_length -1);

	return(1);
}

char *basic_authent(char *user, char *pass)
{
	char *plain=NULL;
	char *encod=NULL;
	unsigned int input_size=0;

	plain=alloca(strlen(user)+strlen(pass)+2);
	strcpy(plain, user);
	strcat(plain, ":");
	strcat(plain, pass);
	input_size=strlen(plain);
	encod=calloc(((input_size * 4) / 3) + ((input_size % 3) ? (4 - (input_size % 3)) : 0) +1, 1);
	base64encod(plain, encod, input_size);
	return encod;
}

bool proxy_connect(char **ressource, t_datathread *data)
{
	char url[MAX_SIZE_URL] = {0, };
	
	strcpy(url, "CONNECT ");
	if((strlen(data->opt.url.host) * 2+strlen(data->opt.url.ch_port) + 57 )> MAX_SIZE_URL)
		return(false);	
	strcat(url, data->opt.url.host);
	strcat (url, ":");
	strcat(url, data->opt.url.ch_port);
	strcat(url, " HTTP/1.1\r\nProxy-Connection: keep-alive\r\nHost: ");
	strcat(url, data->opt.url.host);
	strcat(url, "\r\n\r\n");

	*ressource = calloc(strlen(url),1);
	EXIT_IFNULL(*ressource, "Memory Error");
	strncpy(*ressource, url, strlen(url));

	return(true);
}

bool chk_connect(char *response)
{
	if(strcasestr(response, "200 Connection established"))
		return (true);
	else
		return (false);
}

void prepare_connect(t_datathread *data, int sock)
{
	char *buf;
	char tmp_buf[MAX_SIZE_READ];

	EXIT_IFZERO(proxy_connect (&buf, data), "Url Proxy error");
	send(sock, buf, strlen(buf), 0);
	EXIT_IFNEG(read(sock, tmp_buf, MAX_SIZE_READ-1), "Fail to read on socket");
	EXIT_IFZERO(chk_connect(tmp_buf), "CONNECT error");
}

bool checkhost(s_headers head, char *headers)
{
	if( headers != NULL && strcasestr(headers, "Host:") != NULL  )
		return true;

	if(head.mid==NULL)
		return false;
	else 
		if(strcasestr(head.mid, "Host:") !=NULL) 
			return true;

	if(head.end == NULL )
		return false;
	else
		if( strcasestr(head.end, "Host:") !=NULL )
			return true;

		return false;
}

int headers(
	char **ressource, 
	t_datathread *data, 
	char *word1, 
	char *word2)
{

	char url[MAX_SIZE_URL] = {0, };
	char *auth=NULL;

	if(data->opt.method != NULL && strlen(data->opt.method)< (MAX_SIZE_URL-2))
	{
		strncpy(url, data->opt.method, strlen(data->opt.method));
		url[strlen(data->opt.method)]=' ';
		url[strlen(data->opt.method)+1]='\0';
	}
	else
	{
		strncpy(url, "GET ", 4);
		url[4]='\0';
	}

	if(data->opt.headers == NULL)
		return (-2);

	add_proxy_header(data, url);

	if( (strlen(url)+strlen(data->opt.url.url_pre) + 1)>MAX_SIZE_URL)
		return(-2);

	strncat(url,data->opt.url.url_pre, strlen(data->opt.url.url_pre));

	if(!checkhost(data->opt.head, data->opt.headers))
	{
		if( (strlen(url) + 17 + strlen(data->opt.url.host) + 2 + 1)> MAX_SIZE_URL)
			return(-2);
		strncat(url," HTTP/1.1\r\nHost: ", 17);
		strncat(url,data->opt.url.host, strlen(data->opt.url.host));
		strncat(url,"\r\n", 2);
	}
	else
	{
		if( (strlen(url) + 11 + strlen(data->opt.url.host) + 1)> MAX_SIZE_URL)
			return(-2);
		strncat(url," HTTP/1.1\r\n", 11);
	}

	if(data->opt.agressive)
	{
		if( (strlen(url) + 22 + 2 + 1)> MAX_SIZE_URL)
			return(-2);
		strncat(url,"Connection: Keep-alive",22); 
		strncat(url,"\r\n", 2);
	}
	
	if( word1==NULL || ((strlen(url) + strlen(data->opt.headers) + strlen(word1)+ 1 ) > MAX_SIZE_URL))
		return(-2);
	strncat(url, data->opt.headers, strlen(data->opt.headers));
	strncat(url, word1, strlen(word1));

	if(data->opt.head.mid!=NULL)
	{
		if( (strlen(url)+strlen(data->opt.head.mid)+1)>MAX_SIZE_URL)
			return(-2);
		strncat(url, data->opt.head.mid, strlen(data->opt.head.mid));
	}

	if(data->opt.twofuzz)
	{
		if( (strlen(url)+strlen(word2)+1>MAX_SIZE_URL))
			return(2);

		strncat(url, word2, strlen(word2));
	}

	if(data->opt.head.end!=NULL)
	{
		if( (strlen(url) + strlen(data->opt.head.end)+1)>MAX_SIZE_URL)	
			return(-2);
	
		strncat(url, data->opt.head.end, strlen(data->opt.head.end));
	}
	
	if(data->opt.auth.user!=NULL && data->opt.auth.pass!=NULL)
	{
		auth=basic_authent(data->opt.auth.user, data->opt.auth.pass);
		if( (strlen(url) +21+ strlen(auth) +2+1 ) > MAX_SIZE_URL)
			return(-2);
		strcat(url, "Authorization: Basic ");
		strcat(url, auth);
		strcat(url, "\r\n");
		FREE_BUF(auth);
	}

	if ( (strlen(url) +3) > MAX_SIZE_URL)
		return(-2);

	strncat(url,"\r\n", 2);

	*ressource = calloc(strlen(url),1);
	EXIT_IFNULL(*ressource, "Memory Error");

	strncpy(*ressource, url, strlen(url));
	return(1);
}

int basic_auth(
	char **ressource, 
	t_datathread *data, 
	char *word1, 
	char *word2)
{
	char url[MAX_SIZE_URL] = {0, };
	char *auth=NULL;
	size_t ressource_length = 0;

	if(data->opt.method != NULL && strlen(data->opt.method)< (MAX_SIZE_URL-2))
	{
		strncpy(url, data->opt.method, strlen(data->opt.method));
		url[strlen(data->opt.method)]=' ';
		// url[strlen(data->opt.method)+1]='\0';
	}
	else
	{
		strncpy(url, "GET ", 4);
		// url[4]='\0';
	}

	add_proxy_header(data, url);

	if( (strlen(url)+strlen(data->opt.url.url_pre))>MAX_SIZE_URL)
		return(-2);

	strncat(url,data->opt.url.url_pre, strlen(data->opt.url.url_pre));
	
	if(!checkhost(data->opt.head, data->opt.headers))
	{
		if( (strlen(url) + 17 + strlen(data->opt.url.host) + 2 + 1)> MAX_SIZE_URL)
			return(-2);

		strncat(url," HTTP/1.1\r\nHost: ", 17);
		strncat(url,data->opt.url.host, strlen(data->opt.url.host));
		strncat(url,"\r\n", 2);
	}
	else
	{
		if((strlen(url) + 12) > MAX_SIZE_URL)
			return(-2);
		strncat(url," HTTP/1.1\r\n", 11);
	}

	if(data->opt.agressive)
	{
		if( (strlen(url) + 22 + 2 + 1)> MAX_SIZE_URL)
			return(-2);
		strncat(url,"Connection: Keep-alive",22); 
		strncat(url,"\r\n", 2);
	}

	if(data->opt.headers != NULL)
	{
		if( (strlen(url) + strlen(data->opt.headers) + 1 ) > MAX_SIZE_URL)
			return(-2);
		strncat(url, data->opt.headers, strlen(data->opt.headers));
	}

	if(data->opt.auth.user==NULL && data->opt.auth.pass==NULL)
		auth=basic_authent(word1, word2);
	if(data->opt.auth.user!=NULL && data->opt.auth.pass==NULL)
		auth=basic_authent(data->opt.auth.user, word1);
	if(data->opt.auth.user==NULL && data->opt.auth.pass!=NULL)
		auth=basic_authent(word1, data->opt.auth.pass);
	
	if( (strlen(url) +21+ strlen(auth) +2+1 ) > MAX_SIZE_URL)
			return(-2);
	strcat(url, "Authorization: Basic ");
	strcat(url, auth);
	strcat(url, "\r\n");
	FREE_BUF(auth);	

	if ( (strlen(url) +3) > MAX_SIZE_URL)
		return(-2);

	strncat(url,"\r\n", 2);

	ressource_length = strlen(url) + 1;
	*ressource = calloc(ressource_length,1);
	memset(*ressource, 0, sizeof(*ressource));
	EXIT_IFNULL(*ressource, "Memory Error");

	strncpy(*ressource, url, ressource_length - 1);

	return(1);
}

