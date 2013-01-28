#include <pthread.h>
#include <time.h>
#include "inject.h"
#include "http.h"

static pthread_mutex_t mutex_print = PTHREAD_MUTEX_INITIALIZER;

void sock4cookie(t_options *opt)
{
	char* url=NULL;
	char *receive=NULL;
	unsigned int contentsize;
	int size;
	t_datathread *data=NULL;
	int sock;
	SSL *ssl= NULL;

	data=malloc(sizeof(t_datathread));
	EXIT_IFNULL(data, "Memory Error");
	data->opt=*opt;

	sock=opensock(data);

	EXIT_IFNEG(sock, "Socket error");
	if(data->opt.url.ssl && data->opt.proxy.ip != NULL)
	{
		prepare_connect(data, sock);
		ssl=opensocks(sock, &data->opt);
	}
	else
	{
		if(data->opt.url.ssl)
			ssl=opensocks(sock, &data->opt);
	}

	EXIT_IFNEG(catch_cookie(&url, data), "Too long url");

	size = iosocket(sock, url, &receive, data->opt, ssl, &contentsize);
	if(size == -1)
		if(data->opt.debug)
			fprintf(stderr, "\n");
	EXIT_IFNEG(size, "can't read on socket");

	get_cookie(receive, size, &data->opt);
	*opt=data->opt;

	if(data->opt.url.ssl)
		closesocks(&ssl, sock);
	else
		close(sock);

	FREE_BUF(data);
	FREE_BUF(url);
	FREE_BUF(receive);
}

int catch_cookie(char **ressource , t_datathread *data)
{

	char url[MAX_SIZE_URL] = {0, };
	char *auth=NULL;
	size_t ressource_length = -1;

	strncpy(url, "GET ", 4);
	url[4]='\0';

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
		if((strlen(url) + 12)> MAX_SIZE_URL)
			return(-2);
		strncat(url," HTTP/1.1\r\n", 11);
	}
	if(data->opt.headers != NULL)
	{
		if( (strlen(url) + strlen(data->opt.headers) + 3 ) > MAX_SIZE_URL)
			return(-2);
		strncat(url, data->opt.headers, strlen(data->opt.headers));
		strncat(url, "\r\n", 2);
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

	ressource_length = strlen(url) +1;
	*ressource = calloc(ressource_length,1);
	memset(*ressource, 0, ressource_length);
	EXIT_IFNULL(*ressource, "Memory Error");

	strncpy(*ressource, url, ressource_length-1);
	return(1);
}

int inject_header(
   char **ressource, 
	t_datathread *data, 
	char *word1, 
	int sock, 
	SSL *ssl)
{
	char url[MAX_SIZE_URL];
	memset(url, 0, MAX_SIZE_URL);
	char *auth=NULL;
	char *receive=NULL;
	unsigned int cl;
	int i=0, size;
	time_t start_time, stop_time;
	int delay;
	t_response response;
	t_cookies local_cook=data->opt.cookies;
	bool dontup=false;
	const char *Header[]= { "Cookie", "Host", "User-Agent", "Accept", "Accept-Language", 
					 "Accept-Encoding", "Accept-Charset", "Keep-Alive", 
					 "Connection", "Referer", NULL};

	while(Header[i] != NULL || local_cook!=NULL)
	{
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

		if(!checkhost(data->opt.head, data->opt.headers) && strcasecmp(Header[i],"Host")!=0)
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

		if(data->opt.headers != NULL)
		{
			if( (strlen(url) + strlen(data->opt.headers) + 1 ) > MAX_SIZE_URL)
				return(-2);
			strncat(url, data->opt.headers, strlen(data->opt.headers));
		}

		if( (strlen(url) + strlen(Header[i]) + 5 +strlen(word1)) > MAX_SIZE_URL)
			return(-2);

		strcat(url, Header[i]);
		strcat(url, ": ");

		if(local_cook!=NULL)
		{
			if( (strlen(url) + strlen(local_cook->cookie) +3+strlen(word1)) > MAX_SIZE_URL)
				return(-2);
			strcat(url, local_cook->cookie);
			local_cook=local_cook->next_cook;
			dontup=true;
		}
		else
			dontup=false;

		if(strcasecmp(Header[i], "Host") ==0 
			&& (strlen(url) + strlen(data->opt.url.host) )<MAX_SIZE_URL)
				strcat(url, data->opt.url.host);

		strncat(url, word1, strlen(word1));
		strcat(url, "\r\n");

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

		start_time=time(NULL);
		size = iosocket(sock, url, &receive, data->opt, ssl, &cl);
		stop_time=time(NULL);
		delay= stop_time-start_time;

		if(size == -1)
		{
			if(data->opt.debug)
				fprintf(stderr, "\n Read on socket ");
			continue;
		}

		response_inject(receive, size, cl, &response, &(data->opt), Header[i], word1, delay);
		memset(url, 0, MAX_SIZE_URL);
		sleep(data->opt.wait);

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
		}
		if(!dontup)
			i++;
	}
	FREE_BUF(receive);
	
	return(1);
}

void response_inject(
	char *buf, 
	int size_buf, 
	unsigned int size, 
	t_response *resp, 
	t_options *opt, 
	const char *head,
	char *w, 
	int delay)
{
	unsigned int i=9;
	char *p;
	bool display=true;

	if(strncmp(buf, "HTTP/1.",7))
		printf("\n error");
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

		if(delay < 5)
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
				printf("\t%7d* ", size_buf);
			else
				printf("\t%7d ", size);

			printf("\t %i", delay);

			printf("\t %s : %24s", head, w);
			printf("\n");
		}
		else
			printf("\r");
	pthread_mutex_unlock(&mutex_print);
}

