# LASTMOD: 01.06.2002
# Readme for Nikto
# http://www.cirt.net/
# For Version: 1.013

### ----------------------------------------------------------------------------------------- ###
1. Plugin Overview
2. Warnings
3. Nikto functions available
4. Nikto variables available
5. Required file/function naming conventions
6. Source Inclusion Procedure
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
