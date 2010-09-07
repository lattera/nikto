libwhisker
------------------------------------------------------------------------------

This text file describes all the various special values of the {'whisker'} 
anonymous hash.  All values are for the request (hin) hash, unless 
otherwise noted.

------------------------------------------------------------------------------


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
