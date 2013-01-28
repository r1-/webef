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
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>

#include "options.h"
#include "version.h"
#include "error.h"
#include "file.h"
#include "ssl.h"

void usage(char* name)
{
	fprintf(stderr, 
			"webfuzzer v%s (http://%s)\n"
			"Usage : %s [options] -f file [-f file2] <URL> \n "
			"or\t%s [options] -r range [-f range2] URL (not implemented yet) \n"
			"url : http://www.site.com[:port]/directory/file[?param=value]\n"
			"or    https://www.site.com[:port]/directory/file[?param=value]\n"
			"Options\n"
			"\t-t : number of threads (10 by default) \n"
			"\t-H : \"Header1: value1\" (multiple Headers are accepted) \n"
			"\t-P : Post data : \"Data=FUZZ&Data2=FUZ2Z\"\n"
			"\t-i : use header fuzzing to detect SQL injection in headers \n"
			"\t-m : method to use : -m \"PUT\"\n"
			"\t-p : use proxy : -p \"ip[:port]\"\n"
			"\t-e : hide this error number \n"
			"\t-n : hide this page size : xxx or xxx-yyy for range\n"
			"\t-E : use encoding for FUZZ ( 1 : url encode, 2 : query encode)\n"
			"\t-q : quiet (little banner) \n"
			"\t-s : number of seconds between requests\n"
			"\t-c : client certificate file to use (PEM format) with https\n"
			"\t-k : private key file to use with certificate\n"
			"\t-A : agressive mode \n"
			"\t-B : basic authentication fuzzing : -B \"user=FUZZ&pass=FUZ2Z\"\n"
			"\t-R : redirect filtering : -R \"redirect.hmlt\" : Hide response if redirect (Location header) contains redirect.html\"\n"
			"\t-d : debug\n"
			"\t-v : print version number\n"
			"\t-h : show this help \n"
			" ex : %s -f dico.txt http://www.test.com/FUZZ.php?arg=FUZ2Z\n",
			VERSION,URL,name,name,name);
	exit(0);
}

void init_options(t_options *opt)
{
	opt->type_fuzz=0;
	opt->url_length=0;
	opt->thread=10;
	opt->file1=NULL;
	opt->file2=NULL;
	opt->range=NULL;
	opt->range2=NULL;
	opt->headers=NULL;
	opt->quiet=0;
	opt->inj=false;
	opt->line_file2=1;
	opt->wait=0;
	opt->urlfuzz=false;
	opt->twofuzz=false;
	opt->size_down=-1;
	opt->size_up=-1;
	opt->hide=calloc(4,1);
	opt->ctx=NULL;
	opt->cert=NULL;
	opt->key=NULL;
	opt->onefuzz=false;
	opt->auth.user=NULL;
	opt->head.mid=NULL;
	opt->head.end=NULL;
	opt->headfuzz=false;
	opt->debug=false;
	opt->location=NULL;
	opt->error=0;
	opt->method=NULL;
	opt->ssl_version=0; 
	opt->encod=0;
	opt->proxy.ip=NULL;
	opt->proxy.port=0;
	opt->cookies=NULL;
	opt->agressive=false;
}

void get_options(int argc, char **argv, t_options *opt)
{
	int c;
	init_options(opt);	

	if(argc<2)
		usage(argv[0]);

	while( (c = getopt(argc,argv,"f:r:t:n:s:H:B:m:p:P:E:e:c:k:R:qhviAd23")) != -1 )
	{
		switch ( c )
		{
			case 'f' : if(opt->type_fuzz == TYPE_FUZZ_FILE)
								add_file(optarg, opt, 2);
						  else
						  {						
								opt->type_fuzz=1; 
								add_file(optarg, opt, 1);
						  }
						  break;
			case 'r' : opt->type_fuzz=TYPE_FUZZ_RANGE; break;
			case 't' : opt->thread = atoi(optarg); break;
			case 's' : opt->wait = (unsigned int) atoi(optarg); break;
			case 'n' : parse_range_size(optarg, opt); break;
			case 'E' : opt->encod=(short)atoi(optarg); break;
			case 'H' :  if(opt->headers==NULL)
							{
								if(!parse_headers(optarg, opt))
								{
									usage(argv[0]);
									exit(0);
								}
							}
							else
								add_headers(optarg, opt);
							 break;
			case 'P' : parse_post(optarg, opt); break;
			case 'p' : parse_proxy(optarg, opt); break;
			case 'm' : opt->method = calloc(strlen(optarg)+1,1);
						  EXIT_IFNULL(opt->method, "Memory error");
						  strcpy(opt->method, optarg);
						  break;
			case 'i' : opt->inj=true; 
							opt->method=calloc(5, 1);
							EXIT_IFNULL(opt->method, "Memory error");
							strcpy(opt->method, "HEAD");
							opt->agressive=false;
							break;
			case 'c' : parse_cert(optarg, opt);break;
			case 'k' : parse_key(optarg, opt); break;
			case '2' : opt->ssl_version=2; break;
			case '3' : opt->ssl_version=3; break;
			case 'q' : opt->quiet=1; break;
			case 'e' : free(opt->hide);
						opt->hide = calloc(strlen(optarg)+1,1);
						EXIT_IFNULL(opt->hide, "Memory error");
						strcpy(opt->hide, optarg); 
						break;
			case 'v' : fprintf(stderr,"webfuzzer v%s (http://%s)\n",VERSION, URL); 
							exit(0); 
							break;
			case 'A' :  if(!opt->inj)
								opt->agressive=true;
							break;
			case 'd' : opt->debug=true;
							break;
			case 'R' : opt->location = calloc(strlen(optarg)+1,1);
							EXIT_IFNULL(opt->location, "Memory error");
							strcpy(opt->location, optarg);
							break;
			case 'B' : if(!parse_auth(optarg, opt))
						  {
								usage(argv[0]); 
								exit(0);
							}
							opt->auth.type=1;
							break;
			case 'h' :
			case '?' :
			default : 
				usage(argv[0]);
		}	
	}	

	if(opt->headers!=NULL && (strstr(opt->headers, "FUZZ") || strstr(opt->headers, "FUZ2Z")))
		if(!fuzz_headers(opt))
		{
			usage(argv[0]);
			exit(0);
		}

	if (optind < argc )
   {
		if(parse_url(argv[optind++], opt ) ==-1)
		{
			fprintf(stderr, "Error : Bad url\n\n");
			usage(argv[0]);		
		}			
		if(opt->url.ssl)
		{
			switch (opt->ssl_version)
			{
				case '2':
					opt->ctx=SSL_CTX_new(SSLv2_method()); break;
				case '3' :
					opt->ctx=SSL_CTX_new(SSLv3_method()); break;
				case '0' :
				default :
					opt->ctx=SSL_CTX_new(SSLv23_method());	break;
			}
			EXIT_IFNULL(opt->ctx, "Error creating SSL conext");
			SSL_CTX_set_verify(opt->ctx, SSL_VERIFY_NONE, NULL);

			if(opt->cert != NULL)
				EXIT_IFZERO(SSL_CTX_use_certificate_chain_file(opt->ctx, opt->cert), "Certificate error");

			if(opt->key != NULL)
				EXIT_IFZERO(SSL_CTX_use_PrivateKey_file(opt->ctx, opt->key, SSL_FILETYPE_PEM), "Key file error");
				
			SSL_CTX_set_mode(opt->ctx, SSL_MODE_AUTO_RETRY);
		}
   }
	else
	{
		fprintf(stderr, "Error : Bad url\n\n");
		usage(argv[0]);		
	}			

	if(opt->proxy.ip != NULL)
		//opt->dns_host = gethostbyname(opt->proxy.ip);
		opt->dns_host = opt->proxy.ip;
	else
		//opt->dns_host = gethostbyname(opt->url.host);
		opt->dns_host = opt->url.host;

	if(opt->dns_host==NULL && h_errno == TRY_AGAIN)
	{
		if(opt->proxy.ip != NULL)
			//opt->dns_host = gethostbyname(opt->proxy.ip);
			opt->dns_host = opt->proxy.ip;
		else
			//opt->dns_host = gethostbyname(opt->url.host);
			opt->dns_host = opt->url.host;

		EXIT_IFNULL(opt->dns_host, "DNS error");
	}
	else
		EXIT_IFNULL(opt->dns_host, "DNS error");

	if(opt->type_fuzz==0 || opt->url_length==0)
		usage(argv[0]);
	if(!opt->onefuzz && !opt->inj)
	{
		printf("Error : one FUZZ is needed\n\n");
		usage(argv[0]);
	}
}

void parse_range_size(char *range, t_options *opt)
{
	char *p = strchr(range, '-');

	if(p)
	{
		*p = 0;
		opt->size_down= atoi(range);
		opt->size_up= atoi(p+1);
	
		if(opt->size_down > opt->size_up)
		{
			printf("\nmmmmmhhhh, maybe you should learn to count\n");
			exit(0);
		}
	}
	else
		opt->size_down= atoi(range);

}

void parse_proxy(char *prox, t_options *opt)
{
	char *p;

	p=strchr(prox, ':');
	if(p)
	{
		*p=0;
		opt->proxy.ip=prox;
		opt->proxy.port=atoi(p+1);
		snprintf(opt->proxy.ch_port, 5, "%hu", opt->proxy.port);
	}
	else
	{
		opt->proxy.ip=prox;
		opt->proxy.ip=NULL;
	}
}

bool parse_headers(char *head, t_options *opt_file)
{
	if(strlen(head)==0)
		return 0;

	opt_file->headers = calloc(strlen(head)+3, 1);
	EXIT_IFNULL(opt_file->headers, "Memory error");
	strncpy(opt_file->headers, head, strlen(head));
	strcat(opt_file->headers, "\r\n");
	return 1;
}

void add_headers(char *head, t_options *opt_file)
{

	opt_file->headers = realloc(opt_file->headers,strlen(opt_file->headers)+strlen(head)+3);
	EXIT_IFNULL(opt_file->headers, "Memory error");
	strncat(opt_file->headers, head, strlen(head));
	strcat(opt_file->headers, "\r\n");

}

bool fuzz_headers(t_options *opt)
{
	char *p;

	p = strstr(opt->headers, "FUZZ");
	if(!p)
		return 0;

	*p=0;
	opt->headfuzz=true;		
	opt->onefuzz=true;

	if(*(p+4)==0)
		return 1;

	p=p+4;
	opt->head.mid=p;
	
	p=strstr(opt->head.mid,"FUZ2Z");
	
	if(!p)	
		return 1;

	*p=0;
	opt->head.end=p+5;
	opt->twofuzz=true;

	return 1;

}

void parse_cert(char *cert, t_options *opt_cert)
{
	FILE *f_cert;
	if(!(f_cert = fopen(cert, "r")))
	{
		fprintf(stderr, "Can not openning certificate file\n");
		exit(0);
	}
	opt_cert->cert=malloc(strlen(cert)+1);
	strcpy(opt_cert->cert, cert);		
	fclose(f_cert);
}

void parse_key(char *key, t_options *opt_key)
{
	FILE *f_key;
	if(!(f_key = fopen(key, "r")))
	{
		fprintf(stderr, "Can not openning key file\n");
		exit(0);
	}
	opt_key->key=malloc(strlen(key)+1);
	strcpy(opt_key->key, key);		
	fclose(f_key);
}

void add_file(char *file, t_options *opt_file, int num)
{
	if(num==1)
	{
		opt_file->file1 = calloc(strlen(file)+1, 1);
		EXIT_IFNULL(opt_file->file1, "Memory error");
		strcpy(opt_file->file1,file);
		opt_file->line_file1=nblines(file);
		EXIT_IFZERO(opt_file->line_file1, "File 1 error");
		return;
	}

	opt_file->file2 = calloc(strlen(file)+1, 1);
	EXIT_IFNULL(opt_file->file2, "Memory error");
	strcpy(opt_file->file2,file);
	opt_file->line_file2=nblines(file);
	EXIT_IFZERO(opt_file->line_file2, "File 2 error");

}

int parse_url(char* url, t_options *url_parsed)
{
	int i=0,j=0;
	int http=0,https=0;
	int port=0;
	char buf[255];
	char *host;
	char *slash="/";
	char *p;

	memset(buf, 0, sizeof(buf));

	url_parsed->url_length=strlen(url);
	
	http=strncmp(url,"http://",7);
	https=strncmp(url,"https://",8);

	if(http!=0 && https!=0)
		return(-1);

	if(https==0)
	{	
		url_parsed->url.port=443;
		strcpy(url_parsed->url.ch_port, "443");
		url_parsed->url.ssl=true;
		initssl();
		i=8;
	}
	else
	{
		url_parsed->url.port=80;
		strcpy(url_parsed->url.ch_port, "80");
		url_parsed->url.ssl=false;
		i=7;
	}

	while( url[i]!='/' && url[i]!=':' && url[i]!='\0' && j<255)
		buf[j++]=url[i++];

	buf[j]='\0';
	host=calloc(j+1, 1);
	EXIT_IFNULL(host, "Memory error");

	strcpy(host, buf);
	url_parsed->url.host=host;
	if(url[i]=='\0')
	{
				url_parsed->url.url_pre=slash;
				url_parsed->url.url_mid=NULL;
				url_parsed->url.url_end=NULL;	
				return 1;
	}	

	j=0;
	memset(buf, 0, sizeof(buf));

	if(url[i]==':')
	{
			i++;	
			while( url[i]!='/' && url[i]!='\0' && j<255)
				buf[j++]=url[i++];
			buf[j]='\0';	
			port=atoi(buf);
			if((port<= 0) || (port > 0xffff))
			{
				fprintf(stderr, "Port error\n");
				return (-1);
			}
			url_parsed->url.port=atoi(buf);
			strcpy(url_parsed->url.ch_port, buf);
			
			if(url[i] =='\0')
			{
				url_parsed->url.url_pre=slash;
				url_parsed->url.url_mid=NULL;
				url_parsed->url.url_end=NULL;	
				return (1);
			}
	}
	url_parsed->url.url_pre=url+i;

   p = strstr(url, "FUZZ");
   if (p)
   {
		url_parsed->urlfuzz=true;
		url_parsed->onefuzz=true;
      *p = 0;
		if(*(p+4)==0)
		{ 
			url_parsed->url.url_mid=NULL;
			url_parsed->url.url_end=NULL;	
			return 1;
		}
		else	
			url_parsed->url.url_mid=p+4;
   }
	else
	{
		url_parsed->url.url_mid=NULL;
		url_parsed->url.url_end=NULL;	
		return 1;
	}

	p=strstr(url_parsed->url.url_mid, "FUZ2Z");
	
	if(p)
	{
		EXIT_IFNULL(url_parsed->file2, "FUZ2Z defined without 2nde source FUZZ (range or file)");

		*p=0;
		url_parsed->twofuzz=true;
		url_parsed->url.url_end=p+5;
	}
	else
		url_parsed->url.url_end=NULL;
	
	return (1);

}

void parse_post(char* data, t_options *post_parsed)
{
	char *p;

	post_parsed->post.post_pre=data;
	post_parsed->post.post_mid=NULL;
	post_parsed->post.post_end=NULL;	

   p = strstr(data, "FUZZ");
   if (p)
   {
      *p = 0;
		post_parsed->onefuzz=true;
		if(*(p+4)==0)
			return;
		else	
			post_parsed->post.post_mid=p+4;
   }
	else
		return;

	p=strstr(post_parsed->post.post_mid, "FUZ2Z");
	if(p)
	{
		EXIT_IFNULL(post_parsed->file2, "FUZ2Z defined without 2nde source FUZZ (range or file)");

		*p=0;
		post_parsed->twofuzz=true;
		post_parsed->post.post_end=p+5;
	}
}

bool parse_auth(char *auth, t_options *auth_parsed)
{
	unsigned int size=0;
	char *p=strstr(auth, "&pass=");

	if(strncmp(auth, "user=",5)!=0 || !p)
	{
		fprintf(stderr, "Error in authentication parameters\n\n");
		return false;	
	}
	
	if(strncmp(auth, "user=FUZZ&pass=",15)==0)
	{
		auth_parsed->onefuzz=true;	
		auth_parsed->auth.user=NULL;

		if(strncmp(p+6, "FUZ2Z",5)==0)
		{
			auth_parsed->auth.pass=NULL;	
			auth_parsed->twofuzz=true;
			EXIT_IFNULL(auth_parsed->file2, "FUZ2Z defined without 2nde source FUZZ (range or file)");
		}
		else
		{
			auth_parsed->auth.pass=calloc(strlen(p+6)+1,1);
			EXIT_IFNULL(auth_parsed->auth.pass, "Memory error");
			strcpy(auth_parsed->auth.pass, p+6);
		}
		return true;
	}
	else
	{
		size=(unsigned int) ((unsigned long) p - (unsigned long) (auth+5));
		auth_parsed->auth.user=calloc(size+1,1);
		strncpy(auth_parsed->auth.user, auth+5, size);

		if( strncmp((p+6), "FUZZ", 4) == 0 )
		{
			auth_parsed->auth.pass=NULL;
			auth_parsed->onefuzz=true;	
		}
		else
		{
			auth_parsed->auth.pass=calloc(strlen(p+6)+1,1);
			EXIT_IFNULL(auth_parsed->auth.pass, "Memory error");
			strcpy(auth_parsed->auth.pass, p+6);
		}

		return true;
	}	
}

