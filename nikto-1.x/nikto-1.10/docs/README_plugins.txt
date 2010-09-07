# LASTMOD: 02.23.2002
# Readme for Nikto
# http://www.cirt.net/
# For Version: 1.018

THIS DOCUMENT HAS NOT BEEN UPDATED FOR VERSION 1.1BETA_1, SO A FEW OPTIONS MAY HAVE
CHANGED.

### ----------------------------------------------------------------------------------------- ###
1. Plugin Overview
2. Warnings
3. Nikto functions available
4. Nikto variables available
5. Required file/function naming conventions
6. Source Inclusion Procedure
7. LibWhisker variables
### ----------------------------------------------------------------------------------------- ###

### ----------------------------------------------------------------------------------------- ###
1. Plugin Overview
Nikto allows the usage of plugins through a very simple plugin interface.  This interface looks in
the 'plugins' directory, and then loads files that are named appropriately.  The plugin files
contain standard PERL, and for this reason are flexible about what they can check.

Many of Nikto's internal functions and variables are available to a plugin, and they should be
reused rather than creating new ones if the same data or procedure is required.  External
resources such as command line utilities (either *nix or Windows) should not be used as they may
not be available on all systems. This includes non-standard PERL modules.

If external PERL resources are required for a plugin, consider including the relevant source in
the plugin itself.  Requiring additional PERL modules (besides Net::SSLeay) should be avoided if
it can be helped.  Email sq@cirt.net if you need any help.

### ----------------------------------------------------------------------------------------- ###
2. Warnings/Methodology
Plugins are PERL, which means they can be dangerous. Don't modify global Nikto variables. Don't
create function names that already exist.  Make sure the code properly scopes local variables.  Do
your best to make it 'message' free when using PERL's WARN and TAINT. Always test as easily and
quickly as possible to (if you can) to determine if the rest of the check should be done, i.e.,
checking the server name. I reserve the right to do anything to a plugin's source (including
removing the whole thing) at my sole discretion--deal with it.

### ----------------------------------------------------------------------------------------- ###
3. Nikto functions available
Below are the globally accessible, and usable, Nikto functions. There are other functions, but others are
called automatically or should not be used in a plugin.  For more advanced and complicated checks, the
Libwhisker.pm library has some advanced options/functions which should be studied directly (see the
README_libwhisker.txt written by FRP for more information).

dprint
	Arguments: text (STRING)
	Returns: nothing
	Prints passed 'text' only if the -d (debug) option is used.

fetch
	Arguments: uri (STRING), method (STRING optional), data (STRING optional)
	Returns: httpres (STRING), content (STRING)
	Requests the 'uri' using the method 'method', and posting 'data' (if defined) from . Method "GET" is
	assumed if it is not defined.  The return 'httpres' is the actual HTTP response (i.e., "200"), 
	and content is the page content (including headers) return from the request. This function should
	be used to make any request to the target server.
	
fprint
	Arguments: text (STRING)
	Returns: nothing
	Prints passed 'text' and also adds it to the @PRINT array for file printing at the end. This 
	should always be used over a standard print() or printf() call.

junk
	Arguments: number (INTEGER)
	Returns: STRING
	Junk returns a string of the 'x' character which is as long as 'number' passed to it.  So,
	calling junk(10) will return "xxxxxxxxxx". Useful for keeping checks simple looking.
	
parse_csv 
	Arguments: csvdata (STRING)
	Returns: ARRAY
	Turns CSV (Comma Separated Values) 'csvdata' into an array, returns the array.
	
vprint
	Arguments: text (STRING)
	Returns: nothing
	Prints passed 'text' only if the -v (verbose) option is used.

### ----------------------------------------------------------------------------------------- ###
4. Nikto variables available
Below are a list of globally available Nikto variables. If the variable is not listed here, it is unlikely
that you will need to use it in your plugin.  Do not change values of any of the global variables.

@CGIDIRS   - array of all CGI directories found to be valid on the target system
$CONTENT   - generic variable used to house the content returned from a fetch() call
@COOKIES   - all the cookies retrieved during the scan. Items in each array slice are sparated by '--=--'
@PRINT     - array items where fprint() stores data to be written to the output file
%request   - generic Whisker request element, see README_libwhisker for extra %request options.
%result    - generic Whisker request result element, see README_libwhisker for extra %result options.

%SERVER  - hash items below all represent items on the target server
	$SERVER{category}   - generic category assumed based on servertype. See scan_database.db.
	$SERVER{found}      - server's OK response (usually "200", but not necessarily)
	$SERVER{hostname}   - hostname (or IP, if hostname could not be found)
	$SERVER{ip}         - IP address in dot notation
	$SERVER{notfound}   - server's 404 response, could be text like "not found", or the entire content
	$SERVER{port}       - port number
	$SERVER{servertype} - text from the "Server:" string
	$SERVER{ssl}        - true if server is using ssl on 'port'
	$SERVER{forcegen}   - true if server is being checked as generic instead of 'category'
	$SERVER{forcecgi}   - true if all possible CGI directories are being used

%OUTPUT  - hash items representing anything to do with output. you should use the wrapper functions instead
           of referencing these things directly (most likely), like vprint, fprint, etc.
    $OUTPUT{extended}   - true if extended output (for archival reasons) is being used. 
    $OUTPUT{html}       - true if HTML output is being saved to 'file'
    $OUTPUT{file}       - output file to be written. use fprint() if you need to write to this file.
    $OUTPUT{verbose}    - true if -v (verbose) was used. If printing, use vprint() instead
    $OUTPUT{debug}      - true if -d (debug) was used. If printing, use dprint() instead

%STATS - hash to keep track of (potentially) useful information, you should increment these if necessary
	$STATS{okay}        - total number of OK (usually "200") responses
	$STATS{moved}       - total number of moved (usually "302") responses
	$STATS{requests}    - total actual requests made to server (incremented by fetch)
	
%AUTH  - hash keeps authentication information
	$AUTH{hostid}       - ID for host authentication
	$AUTH{hostpw}       - Password for host authentication
	$AUTH{proxyid}      - ID for proxy authentication
	$AUTH{proxypw}      - Password for proxy authentication
	$AUTH(hoststring}   - Encoded "Authorization:" string
	$AUTH(proxystring}  - Encoded "Proxy-authorization" string

%NIKTO - hash keeps general Nikto information (probably won't use)
    $NIKTO{version}     - Nikto version
    $NIKTO{name}        - Nikto name, sort of redundant...
    $NIKTO{fingerprint} - 'fingerprint' file Nikto uses to get a 404 not found message
    $NIKTO{plugindir}   - full path to the plugins directory, use this if you need to open a .db file.

%FILES - hash keeps file names and full paths handy
	$FILES{dbfile}      - location of scan_database.db
    
### ----------------------------------------------------------------------------------------- ###
5. Required file/function naming conventions
Plugin files must have a name which starts with "nikto_" and end in ".pl".  Anything goes in
between, but it should be short but descriptive.

The 'main' portion of code (the part of code which will be called), must be the same as the file
name without the ".pl" ending.

For example, a plugin file could be called "nikto_testplugin.pl", and it would contain a function
called "nikto_testplugin" which will be called when the plugin starts up.  If this convention is
not used, the plugin will not run properly and may terminate the scanner abruptly.

### ----------------------------------------------------------------------------------------- ###
6. Source Inclusion Procedure
If you  have a plugin which is working properly, send it to sq@cirt.net for review. If the plugin
meets some basic criteria, it will be added to the distribution. The criteria includes whether it
actually works or not, if the code is relatively clean and fast, it is platform independent and
that it is easily understood
(to ensure it is not performing some other nefarious function). So called "obfuscated" code will
not be included.
### ----------------------------------------------------------------------------------------- ###
7. Libwhisker variables (for LW version PR4)

This file describes all the various special values of the {'whisker'} anonymous hash.  All values 
are for the request (hin) hash, unless otherwise noted.


==== Standard configuration ====

{'whisker'}->{'host'}
	- What host you want to connect to.  Default is 'localhost'.

{'whisker'}->{'port'}
	- Port to connect to for HTTP host (not proxy).  Default is 80.

{'whisker'}->{'proxy_host'}
	- The proxy host to use while attemping to make the HTTP request 
	to the specified host.  Note that libwhisker will go into proxy
	mode if proxy_host is defined, so be sure to delete it from the
	hash if you don't want to use a proxy.  By default it is not
	defined.

{'whisker'}->{'proxy_port'}
	- The port of the proxy server to connect to.

{'whisker'}->{'method'}
	- The HTTP method to use.  Default is 'GET'.

{'whisker'}->{'uri'}
	- The actual URL desired.

{'whisker'}->{'http_ver'}
	- In the request (hin) hash, this tells libwhisker what HTTP 
	version request to perform.  Recognized values are '0.9', '1.0',
	and '1.1'.  Default is '1.1'.  In the result (hout) hash, this
	is the HTTP version response of the result.

{'whisker'}->{'ssl'}
	- If set to 1, libwhisker will use SSL for the connection.  
	Default is 0.

{'whisker'}->{'error'}
	- Only applicable in result (hout) hash; this contains the error
	message if any errors occured (it's empty otherwise).

{'whisker'}->{'data'}
	- In request (hin) hash, this is additional data to send to the 
	server (for example, via POST or PUT).  libwhisker will 
	automatically calculate the 'Content-Length' header if you haven't
	already done so.  In result (hout) hash, this is the HTML/data 
	sent from the server.

{'whisker'}->{'http_resp'}
	- Only applicable in result (hout) hash; this tells you the HTTP
	response code of the result.

{'whisker'}->{'http_resp_message'}
	- Only applicable in result (hout) hash; this tells you the HTTP
	response message of the request.


==== Advanced configuration ====

{'whisker'}->{'ignore_duplicate_headers'}
	- If a server sends the same header (potentially with different 
	values) twice, this will only save the result of the last header
	value.  If set to 0, it will actually make an anonymous array 
	under that header name in the hash, and push all the values into
	the array--this means you have to test every header result to see
	if it's an ARRAY REF (using ref() function) before you can use it.
	Default is 1 (ignore duplicates).

{'whisker'}->{'normalize_incoming_headers'}
	- If set to 1, libwhisker will 'normalize' the header names in an 
	attempt to be more standard.  The normalization will make the 
	first character, and any character after the '-' uppercase.  So
	"Content-length" and "blah-blah-blah" will become "Content-Length"
	and "Blah-Blah-Blah".  The 'lowercase_incoming_headers' option
	will override this option.  The default value is 1.

{'whisker'}->{'lowercase_incoming_headers'}
	- If set to 1, libwhisker will lowercase the names of all incoming
	headers before putting them into the header hash.  The default is 
	0.

{'whisker'}->{'ids_session_splice'}
	- If set to 1, this will cause libwhisker to trickle the initial 
	HTTP request a few characters at a time, in an attempt to bypass
	network IDS systems that don't do stream reassembly.


{'whisker'}->{'timeout'}
	- This is the amount of time, in seconds, that libwhisker will
	wait for data from a webserver before aborting.  The default is 
	10 (seconds).

==== HTTP request specifics ====

(Note: 	for the specifics of how all these elements compose the HTTP 
	request, check the lw::http_req2line function)

{'whisker'}->{'method_postfix'}
	- Stuff to add after the method, before the spacer between the 
	method and URI.  Default is empty.

{'whisker'}->{'req_spacer'}
	- This value is placed between the method and uri in the HTTP 
	request.  Default is ' ', a single space.

{'whisker'}->{'uri_prefix'}
	- This value is placed before the actual uri.  The default
	value is empty.

{'whisker'}->{'uri_user'}
	- An optional username to put into the uri (note: this is not
	related to the HTTP Authentication header).  Default is empty.

{'whisker'}->{'uri_password'}
	- An optional password to put into the uri (note: this is not
	related to the HTTP Authentication header).  Default is empty.

{'whisker'}->{'uri_postfix'}
	- This value is placed after the actual uri.  The default
	value is empty.

{'whisker'}->{'uri_param_sep'}
	- What to separate parameters with.  Default is '?'.

{'whisker'}->{'uri_param'}
	- URL parameters.  If not empty, then uri_param_sep will be 
	placed between uri and uri_param.

{'whisker'}->{'req_spacer2'}
	- This value is placed between the uri and HTTP version in the 
	HTTP request.  Default is ' ', a single space.

{'whisker'}->{'http_req_trailer'}
	- This value is placed after the HTTP version, but before the
	end of the request line.  Default is empty.

{'whisker'}->{'http_eol'}
	- The terminating header line character.  Defaults to '\r\n'.

{'whisker'}->{'include_host_in_uri'}
	- If set to 1, this will include the host in the HTTP request, in 
	the form of http://host:port/uri.  This is typically needed for
	proxies.

{'whisker'}->{'full_request_override'}
	- If this entry is not empty, this value will be sent instead of
	the constructed HTTP request line.

{'whisker'}->{'raw_header_data'}
	- If this entry is not empty, it will be inserted into the HTTP
	request stream after the initial HTTP request and headers, but 
	before the final blank line.  This lets you specify arbitrary
	headers or other wackiness in the request.

==== Miscellaneous ====

{'whisker'}->{'stats_reqs'}
	- Only applicable in result (hout) hash; this tells how many 
	requests have been made to that host (total).

{'whisker'}->{'stats_syns'}
	- Only applicable in result (hout) hash; this tells how many 
	socket connections have been made to that host (total).

{'whisker'}->{'sockstate'}
	- Only applicable in result (hout) hash; this tells you if the 
	socket was open or closed on lw::http_do_request completion.

{'whisker'}->{'INITIAL_MAGIC'}
	- This is a special value (31337, heh), which is set by
	lw::http_init_request, to make sure some default values are set.  
	You can set it yourself on a raw hash, but you may break 
	lw::http_do_request, because it makes assumptions concerning the
	existance of some elements in the hash.

{'whisker'}->{'cookies'}
	- This is obsolete.  Do not use.  It only existed in 
	libwhisker <= pr3.
