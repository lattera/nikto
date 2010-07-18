# LASTMOD: 01.07.2002
# Readme for Nikto
# http://www.cirt.net/
# For Version: 1.015

### ----------------------------------------------------------------------------------------- ###
1.	Overview/Features/Important Notes
2. 	Requirements
		PERL
		SSL
		PLATFORMS
3.	Usage
		COMMAND LINE OPTIONS
		PROXY SETUP
		DATABASE CHECK
		DATABASE UPDATE
		EXAMPLES
		ERRORS
4.	Plugins (IMPORTANT WARNING, PLEASE READ)
5.	Whatever/Info
		NIKTO?
		CREDITS
		LIBWHISKER
		SOURCES
6.	Items to Complete
7.	Versions/Changes

### ----------------------------------------------------------------------------------------- ###
1.	Overview/Features/Important Notes
Nikto is a web server scanner.  It is based on and inspired by Whisker 1.4 scanner
(www.wiretrip.net).  Whisker is a great scanner.  However, it lacks
some basic functionality that is often needed: proxy support, host authentication, SSL, and to
have often and easily updated checks.  

This software uses RFP's LibWhisker (PR4) as a base for all network funtionality (no sense
reinventing the wheel), and creates an easy to use scanner (I
hope). This may not be as fast, or have as many features, as the awaited Whisker 2, but this is here
now and I hope it is useful. 

Nikto is not designed as a stealthy uber-hax0r tool.  It does not have IDS evasion, slow scanning
or distributed scanning.  It will beat the hell out of a web server in the shortest timespan
possible, and will leave multiple traces that it did so.

Not EVERY check is a security problem, though.  There are a few items that "info only" type checks
that look for items that may not have a security flaw, but the webmaster or security person may
not know are present on the server. These items are usually marked appropriately in the
information
printed.

If an item reports "This may be interesting..." it means I found the check somewhere, but do not
know what the flaw is (or it just might have an interesting name, like "password.txt"). If you see
one of these and know the flaw, please send me the details.

NIKTO LEAVES A DISTINCT FOOTPRINT ON THE SERVER IT SCANS--it checks for a 404 by getting a file
named "Nikto-ver-randnumber.htm" (ver is actual version,
randnumber is a 4 digit random number). This can be EASILY CHANGED at the top of Nikto.pl (around
line 66), so no complaining.

Here are some of the main features:
- Automatic update of databases, notification of updated code (only with CLI option)
- Main scan database in CSV format for easy updates
- Determines "OK" vs "NOT FOUND" responses for each server, if possible
- Determines CGI directories for each server, if possible
- Switch HTTP versions as needed so that the server understands requests properly
- SSL Support (with OpenSSL installed on *nix, or ActiveState's compiled Net:SSL module)
- Output to file in plain text
- Output to file in HTML (with links back to server)
- Generic and "server type" specific checks
- Plugin support (standard PERL)
- Checks for outdated server software 
- Proxy support (with authentication)
- Host authentication
- Watches for "bogus" OK responses
- Captures/prints any Cookies received
- PERL, so you can read the source & don't have to wonder what evil things may  be happening to
your system with compiled code

### ------------------------------------------------------------------ ###
2. 	Requirements
PERL
http://www.cpan.org/

SSL
To use SSL on *nix platforms, you need OpenSSL and the SSLeay Perl module:
OpenSSL - http://www.openssl.org/
NET::SSLeay - http://www.cpan.org/

To use SSL on Windows platforms, you need ActiveState's ActivePerl and also the Net::SSL
module.
http://www.activestate.com/

PLATFORMS
Tested on: Solaris 2.7/2.8, RedHat 7.1/7.2, Windows 2000 (Activestate PERL, non-SSL)

- Nikto should run on any platform that supports standard PERL.
- SSL is verified to work on *nix platforms, but has not (yet) been confirmed on Windows.


### ------------------------------------------------------------------ ###
3.	Usage
COMMAND LINE OPTIONS
Here are the command line options for using Nikto, with a more in-depth definition. Items with a
'*' are required for Nikto to run. Items with a '+'
require an argument if they are used.  Any item can be abbreviated to the first character of the
item name, i.e. -s instead of -ssl.

	-verbose    Outputs info on each check as it performs it
	-debug		Tons of output is sent to STDOUT
	-ssl	    Use SSL connection to target. Must be specified even for port 443...
	-generic    Force a scan with the full DB, not just a "trimmed" database based on host
	-allcgi     Use all CGI directories to check (don't limit to found directories)
	-nolookup   Skip the name lookup on host
	-output+    Write the output to this file (as well as STDOUT)
	-web 	    Writes the output (-o) in HTML format instead of plain text
	-id+        host authentication to use, format is "userid:password"
	-port+      Port to target. Defaults to port 80 if not specified.
	-host*+     Host to target. Can be a name or an IP address.
	-debug      Print LOTS of info to STDOUT. Use cautiously.
	-timeout	Delay/timeout for assuming a host is not responding, default is 10 seconds.

There is also an option "dbcheck", which if used ONLY checks for duplicates and syntax of
scan_database.db, outdated.db and versions.db.  Also, "update" will update the local .db files and
notify of updated plugins or software.

Note that if you use -d or -v with the output to file option (-o), the extended output will NOT be
written to the output file. This is in case you'd like
to have lots of info sent to STDOUT but only actual results saved to the file. If you want
everything to a file, just use a > redirect to a text file.

PROXY SETUP
To use a proxy with Nikto, you must edit nikto.pl itself.  At line 77 you should find these 4
lines:
  #$request{'whisker'}->{'proxy_host'}='proxy.target.com';
  #$request{'whisker'}->{'proxy_port'}='8080';
  #$AUTH{proxyid}="";
  #$AUTH{proxypw}="";
To enabled proxy usage, uncomment the first two (remove the #), and change 'proxy.target.com' and
'8080' to the appropriate server and port number. If the
proxy requires authentication, uncomment the next two and add your proxy ID and password.  This
should (and will) move to a config file or command line
option in a future release.

Please note:  if you use a proxy in a browser setup but are scanning an 'internal' host (local network
where proxy is not required), the proxy will usually tell the browser not to use the proxy. With this
software, Nikto will continue to use the proxy to scan the host, which may add unnecessary time to
the scan, load on the proxy, and perhaps skew results.

DATABASE CHECK
There is a database check option which checks the syntax of the .db files and looks for duplicates
in them. To run this option (only needed if you update the db files yourself), just run:
	shell> nikto.pl dbcheck
And you will be warned of any duplicates or invalid syntax in the .db files.

DATABASE UPDATE
If Nikto is executed with the option "update", it will contact www.cirt.net and retrieve a listing
of the current Nikto, database and plugin versions. If updated database files are found, it will
download and store them in the plugin directory, replacing the older versions.  Because the
plugins contain actual PERL code, Nikto will not automatically download plugins.  The "update"
option will, however, notify you if there are new plugins or a new version of Nikto available so
that you can look at the source yourself before running the code.

Please note that under no circumstances does Nikto attempt to contact cirt.net or any other host
(except those you specify during a check) unless you run the "update" option."

To update Nikto:
	shell> nikto.pl update

EXAMPLES:
Simple:
	shell> nikto.pl -h 10.10.10.100

Simple, w/SSL:
	shell> nikto.pl -h 10.10.10.100 -p 443 -s

Every check against host, debug and verbose output, SSL, authenticate to host and saved to an HTML
file :)
	shell> nikto.pl -h 10.10.10.100 -p 443 -s -i admin:password -a -g -v -d -w -o results.html

ERRORS
a) Can't locate plugins/libwhisker.pm in @INC
 Don't execute Niko like this:
  shell> perl /home/mydir/nikto.pl
 as it can't then figure out where the plugins directory is. Instead, use:
  shell> /home/mydir/nikto.pl

b) ./nikto.pl:  not found
 If you executed as "./nikto.pl", change the first line "#!/usr/bin/perl" to point to the actual location of your perl binary.
  
### ----------------------------------------------------------------------------------------- ###
4.	Plugins
Plugins are written in PERL.  To write a plugin, see the guide on CIRT.net.

IMPORTANT NOTE:
Plugins are standard PERL, which means you should use the same caution running them as you do
running any untrusted code.  It is generally a good idea to
review all downloaded/untrusted PERL code before running it, but please don't assume that because
it is "just a plugin" it is harmless--it has full access
to all of PERL.

I will review any contributed plugin before I distribute it with the Nikto package or on CIRT.net,
but that does not mean you should trust me or that
CIRT.net has not been compromised and someone did not insert a dangerous plugin.

### ----------------------------------------------------------------------------------------- ###
5.	Whatever/Info
NIKTO?
Why the name?
	Short answer: "The Day the Earth Stood Still" & "Army of Darkness"
	Long answer: see http://www.blather.net/archives2/issue2no21.html
	
CREDITS
More info: 	http://www.cirt.net/
Author:		Chris Sullo ( sq@cirt.net )
Thanks:		Rain Forest Puppy (Whisker, LibWhisker)
       		Paul Darby (testing, comments, and bad music)
       		Steve Valdez (testing, comments, adding himself to the Admin group)
       		Steve Saady (testing, comments)

LIBWHISKER
The libwhisker.pm is the standard PR4 release available on www.wiretrip.net except for one thing:
 - To fix an SSL initialization error on Solaris, the randomize() function had to be called
specifically at line 52.
No other changes to Libwhisker.pm PR4 have been made.

SOURCES
Data for the scan_database.db/server_msgs.db checks came from many sources for the v1 build. 
Ongoing additions will come from new flaws/vuls found,
mailing list posts, advisories, community submissions, etc.

Some v1 check sources:
	Nessus 1.0.9 - http://www.nessus.org/
	Whisker 1.4  - http://www.wiretrip.net/
	CgiChk 2.60  - http://sourceforge.net/projects/cgichk/

Outdated.db sources are from everyone--software sites, modules.apache.org, etc. If someone knows
an easy way to pull all the Apache module versions, PLEASE TELL ME.

### ----------------------------------------------------------------------------------------- ###
6.  Items to Complete
- Combining of CLI options, (i.e. -agvd instead of -a -g -v -d)
- Proxy set up on CLI or config file
- Catch other 'interesting' responses from server (i.e., if 200 is expected, but we get a 408 we
should warn)
- Check HTTP methods allowed
- Somehow safety check the plugins
- Really simple web interface for submitting new checks (and for me to manage)

### ----------------------------------------------------------------------------------------- ###
7.  Changes
Here are the version changes for Nikto.pl (this does not include plugins or databases)
Ver   	Date		Note
1.00	12.27.2001	Finalized beta version for partial release
1.01  	12.31.2001	Added regex to remove comments from scan_database.db in case they ever exist
			Fixed extra 'Host:' line being sent to server (duh).
			Fixed non 'GET' request data posting (duh).
			Added -timeout option
1.011	01.02.2002	Added proxy auth for db update requests (oops).
			Started .xxx version numbering scheme to make life easier
			Fixed href tags in HTM output (< and > encoding and target host/ip)
			Added "caseless" WWW-Authenticate finding (for iPlanet Proxy)
1.012	01.03.2002	Added extended output for scan archival reasons (suggested by Steve Saady)
			Changed host auth failure to a warning, not stoppage
			Added "data" portion to scan_database.db
			Added @IP and @HOSTNAME substitutions for scan_database.db checks (will be replaced by actual IP/hostname)
				in case they are needed in the future.
			Added JUNK() to scan_database.db checks to facilitate future buffer-overflows (non-DoS), and future DoS plugins
			Added Proxy-agent as valid the same as Server result strings
			Changed -l to -n ("nolookup") to be more accurate
1.013	01.06.2002	Made major globabl variable changes, moved tons of them to hashes
			Wrote some basic plugin writing documentation & added 'docs' directory
1.014	01.07.2002	Removed comment filtering from lines in scan_database.db to accommodate SSI includes
			Fixed quoting removal for data portions in checks (so " is valid).
1.015	01.08.2002	Fixed a bug (?) in Libwhisker PR4 (will check v1 code...)
                        Corrected an error which caused a few false-positives (404 really IS not found :)

