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
#include <errno.h>
#include <stdlib.h>

#include "file.h"
#include "error.h"

FILE *openfile(char *file)
{
          FILE *my_file;

          if(!(my_file = fopen(file, "r"))) {
                    fprintf(stderr, "Can not openning file\n");
                    return 0;
          }
          return my_file;
}

void delnewline(char *string)
{
          char *p = strchr(string, '\r');

          if (p)
                    *p = 0;

          else
                    p = strchr(string, '\n');

          if(p)
                    *p = 0;
}

bool getword(FILE *wordlist, char **word)
{
          char buffer[MAX_LINE_LENGTH];
          memset(buffer, 0, sizeof(buffer));

          if(fgets(buffer, MAX_LINE_LENGTH-1, wordlist) == NULL)
                    return (false);
          while(buffer[0] == '#') {
                    if(fgets(buffer, MAX_LINE_LENGTH-1, wordlist) == NULL)
                              return (false);
          }

          delnewline(buffer);
          (*word) = calloc(strlen(buffer)+1, sizeof(char));
          EXIT_IFNULL(*word, "Memory Error");

          strcpy(*word, buffer);
          return (true);
}

bool loadfile(FILE *wordlist, char *buf[MAX_FILE],unsigned int *size)
{
          unsigned int i=0;

          while(i< MAX_FILE && getword(wordlist, &buf[i]))
                    i++;
          (*size)=i;

          if(i==0)
                    return (false);
          return (true);
}

unsigned int nblines(char *fic)
{
          unsigned int count = 0;
          FILE *file;
          int c;

          RETURN_IFNULL((file = fopen(fic,"r")));

          while((c = fgetc(file)) != EOF) {
                    if(c == '\n')
                              ++count;
          }

          fclose(file);
          return count;
}

