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

#ifndef H_ERROR
#define H_ERROR

#define RETURN_ERR(err,s) if((err)==-1) { fprintf(stderr, "%s\r",s); return(-1); }
#define RETURN_IFNULL(err) if((err)==NULL) { return(-1); }
#define RETURN_NEG_IFNEG(err) if((err) < 0) { return(-1); }
#define RETURN_NULL_IFNEG(err) if((err) < 0 ) { return NULL; }

#define EXIT_IFNULL(err,s) if((err)==NULL) { fprintf(stderr, "\n%s\n",s); exit(1); }
#define EXIT_IFNEG(err,s) if((err)<0) { fprintf(stderr, "\n%s\n",s); exit(1); }
#define EXIT_SSL(err,s) if((err)<0) { fprintf(stderr, "\n%s\n",s); exit(1); }
#define EXIT_IFZERO(err,s) if((err) ==0) { fprintf(stderr, "\n%s\n",s); exit(1); }
#define FREE_BUF(buf)	if(buf != NULL) { free(buf); buf=NULL; }

#endif
