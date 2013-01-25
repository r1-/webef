#include "encodage.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_SIZE_ENC	2048

void base64encod(char *src, char *dst, unsigned int size)
{
	unsigned char triplet[3];
	uint8_t  cartriplet;
	unsigned char valcode[4];
	unsigned int pos_src, pos_dst;
	char valcar[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

	pos_src = 0;
	pos_dst = 0;

	while (pos_src < size)
	{
		cartriplet = 0;

		do
			triplet [cartriplet++] = src[pos_src++];
		while (cartriplet < 3 && pos_src < size);

		valcode[0] = triplet[0] >> 2;
		valcode[1] = (triplet[0] & 3) << 4;

		if (cartriplet > 1)
		{
			valcode[1] = valcode[1] | (triplet[1] >> 4);
			valcode[2] = (triplet[1] & 0x0F) << 2;
		}
		else
			valcode[2] = 64;

		if (cartriplet == 3)
		{
			valcode[2] = valcode[2] | (triplet[2] >> 6);
			valcode[3] = triplet[2] & 0x3F;
		}
		else
			valcode [3] = 64;

		dst[pos_dst++] = valcar[valcode [0]];
		dst[pos_dst++] = valcar[valcode [1]];
		dst[pos_dst++] = valcar[valcode [2]];
		dst[pos_dst++] = valcar[valcode [3]];
	}
	dst[pos_dst] = '\0';
}

unsigned int base64decode(char *buffer)
{
	uint8_t car, i;
	char valcar[4];
	unsigned int  pos_src, pos_dst;

	pos_src = 0;
	pos_dst = 0;

	while (buffer[pos_src] > ' ' && buffer[pos_src] != '=')
	{
		for (i = 0; i < 4 && buffer[pos_src] != '='; i++)
		{
			car = buffer[pos_src++];

			if ('A' <= car && car <= 'Z')
				valcar[i] = car - 'A';
			else if ('a' <= car && car <= 'z')
				valcar[i] = car + 26 - 'a';
			else if ('0' <= car && car <= '9')
				valcar[i] = car + 52 - '0';
			else if (car == '+')
				valcar[i] = 62;
			else if (car == '/')
				valcar[i] = 63;
		}

		buffer[pos_dst++] = (valcar[0] << 2) | (valcar[1] >> 4);

		if (i > 2)
		{
			buffer[pos_dst++] = (valcar[1] << 4) | (valcar[2] >> 2);

			if (i > 3)
				buffer[pos_dst++] = (valcar[2] << 6) | (valcar[3]);
		}
	}
	buffer[pos_dst] = '\0';

	return (pos_dst);
}

void urlencode( char *src, char **dst, unsigned int size, int type )
{
	unsigned int i,j=0;
	unsigned char c;
	char newchar[4];
	char newdst[MAX_SIZE_ENC];

	if(type > ENC_QUERY)
		return;

	for(i=0; i< size && j<(MAX_SIZE_ENC-1); i++)
	{
		c=src[i];
		if( (c < 48 ) || (c> 57 && c< 65) || (c > 90 && c < 97) || (c > 122 && c < 128))
		{
			if(type==ENC_QUERY && c==32)
			{
				newdst[j++]='+';
			}
			else
			{
				sprintf(newchar,"\%%%2x",c);
				newdst[j]=newchar[0];
				newdst[j+1]=newchar[1];
				newdst[j+2]=newchar[2];
				j=j+3;
			}
		}
		else
		{
			newdst[j]=c;
			j++;
		}
	}
	if(j<(MAX_SIZE_ENC-1))
		newdst[j]='\0';
	else
		newdst[j-1]='\0';

	*dst=realloc(*dst, strlen(newdst)+1);
//fixme
if(*dst==NULL)
{
	printf("\n Realloc failed \n");
	exit(0);
}
//
	strcpy(*dst,newdst);	
}

