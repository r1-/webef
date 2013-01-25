webef
=====

webef is a web bruteforcer. It is designed to find directories or files in a web server using a wordlist brute force.
It supports multithreading, Post data bruteforcing, headers adding, HTTP 1.1
requests, HTTPS, client certificate file, Proxy, url and querystring encoding.
It is possible to hide results, depending on their HTTP response code or 
response size.
Two wordlist files are allowed.
A module is available in order to detect sql injection in headers, based on
delay response.

platforms
---------

webef 0.5 was compiled and more or less successfully tested under the
following operating systems:

Debian lenny/sid on amd64, kernel 2.6.32
Debian lenny/sid on x86
Fedora 14
Ubuntu 10.04

install
-------

Get the tarball and extract it:

	tar xvfz webef.tgz
  
	cd webef/
	
	make

For compiling webef, gcc is recommended.
If you want to use webef in HTTPS, you will need to have the OpenSSL library. 

How does it work ?
------------------

webef build a HTTP request to a server and replace the FUZZ and FUZ2Z 
words by every word contained in the wordlist files given. 


Examples
---------

simplest example :
webef -f wordlist http://host/FUZZ

with another TCP port : 
webef -f wordlist http://host:8080/FUZZ

with https :
webef -f wordlist https://host/FUZZ

with https and client certificate with private key :
webef -f wordlist -c SSL_cert.crt -k SSL_key.key https://host/FUZZ

with another wordlist file (extension fuzzing as an example) :
webef -f wordlist1,wordlist2 http://host/FUZZ.FUZ2Z

Change the number of thread (10 by default)
webef -f wordlist -t 5 http://host/FUZZ

Add a waiting time between two requests (2 seconds) :
webef -f wordlist -s 2 http://host/FUZZ

Agressive mode uses HTTP 1.1 and persistent connections. It is more efficient
with HTTPS (less handshake phases) and faster :
webef -f wordlist -A http://host/FUZZ

Agressive mode can be used with the HEAD method to improve performance.
webef -f wordlist -m HEAD -A http://host/FUZZ

Post data bruteforcing :
webef -f wordlist -P "data=FUZZ&content=1&id=FUZ2Z" http://host/url

Use proxy :
webef -f wordlist -p "192.168.1.1:3128" http://host/FUZZ

Use url encoding for FUZZ words :
webef -f wordlist -E 1 http://host/FUZZ

Adding headers :
webef -f wordlist -H "User-agent=blah" http://host/FUZZ

Hide response following HTTP return code :
webef -f wordlist -e 404 http://host/FUZZ

Hide response following HTTP redirect :
webef -f wordlist -R "http://host/redirect.html" http://host/FUZZ

Basic authentifcation bruteforcing :
webef -f user.txt -f pass.txt -B "user=FUZZ&pass=FUZ2Z" -e 401 http://host/url

Detect Sql injection in headers (a delay for response up to 5s is suspicious): 
webef -f wordlist/injections.txt -i http://host/page.php

Debug : -d option

