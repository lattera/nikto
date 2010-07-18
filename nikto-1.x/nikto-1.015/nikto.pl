#!/usr/bin/perl
use IO::Socket;
use Getopt::Long;
$|=1;
# last update: 01.08.2002

# --------------------------------------------------------------------#
#                               Nikto                                 #
# --------------------------------------------------------------------#
# This copyright applies to all code except that contained in the libwhisker.pm
# file, which is subject to the copyright contained in libwhisker.pm or as specified
# by Rain Forest Puppy (www.wiretrip.net).
#
# Copyright (C) 2001, 2002 CIRT.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
# Contact Information:
#  Chris Sullo 
#  sq@cirt.net
#  http://www.cirt.net
# --------------------------------------------------------------------#
# This is styled after Rain Forest Puppy's excellent "whisker"
# and uses rfp's libwhisker.pm library for the HTTP and socket functionality
#
# See the README.txt and/or help files for more information on how to use & config
#
# See the LICENSE.txt file for more information on the License Nikto
# is distributed under.
#
# This program is intended for use in an authorized manner only, and the author
# can not be held liable for anything done with this program, code, or items
# discovered with this program's use.
# --------------------------------------------------------------------#

#######################################################################
# global var/definitions
use vars qw/$URI $SKIPLOOKUP $CONTENT $ITEMCOUNT $CLIOPTS $TIME $EXECDIR @PRINT @CGIDIRS @COOKIES %FILES/;
use vars qw/%STATS %NIKTO %AUTH %OUTPUT %ROOTS %METHD %FILES %RESPS %INFOS %SERVER %request %result %JAR %DATAS/;
my ($HOST, $HOSTAUTH, $OKTRAP) = "";
$NIKTO{version}="1.015";
$NIKTO{name}="Nikto";
my $rstring=rand(4);
#######################################################################
# CONFIGURE
# here's the fingerprint -- this should always be something which will NOT be found on the server!
 $NIKTO{fingerprint}="$NIKTO{name}-$NIKTO{version}-$rstring.htm";

# CGI Directories - will attempt to figure out which are 'right' unless we are forced to check all
  @CGIDIRS=qw(/bin/ /cgi/ /cgi-bin/ /cgi-sys/ /cgi-local/ /htbin/ /cgibin/ /cgis/ /scripts/ /cgi-win/);

# Plugin/db/lib stuff
  # get the correct path to nikto.pl
  $EXECDIR=$ENV{_};
  chomp($EXECDIR);
  $EXECDIR =~ s/nikto.pl$//;
  if ($EXECDIR =~ /(perl|perl\.exe)$/) { $EXECDIR=""; }  # executed as 'perl nikto.pl' ...
  $NIKTO{plugindir}="$EXECDIR\plugins";
  $FILES{dbfile}="$NIKTO{plugindir}/scan_database.db";
  require "$NIKTO{plugindir}/libwhisker.pm";
  lw::http_init_request(\%request);

# this stuff should all move to CLI options or config file...
  #$request{'whisker'}->{'proxy_host'}="";
  #$request{'whisker'}->{'proxy_port'}='';
  #$AUTH{proxyid}="";
  #$AUTH{proxypw}="";
#######################################################################

if ($ARGV[0] eq "dbcheck") { &dbcheck; }   # just check the scan_database.db for duplicates
elsif ($ARGV[0] eq "update") { &check_updates; }  

$NIKTO{suppressauth}=$OUTPUT{html}=$OUTPUT{verbose}=$SKIPLOOKUP=$STATS{moved}=$STATS{okay}=$STATS{requests}=$ITEMCOUNT=0;
$OKTRAP=1;
my $STARTTIME= localtime();
$CLIOPTS="
       -verbose      		verbose mode
       -debug   			debug mode (tons of output)
       -ssl         		use ssl (must specify even if port is 443)
       -generic       		force full (generic) scan
       -allcgi       		force scan of all possible CGI directories
       -nolookup       		skip name lookup
       -output+       		also write output to this file
       -web (format)  		write to file in web HTML format
       -extended (output)	write all CLI switches & options used to output file
       -id+          		host authentication to use, format is userid:password
       -port+       		port to use (default 80)
       -host*+       		target host
       -timeout	     		timeout (default is 10 seconds)
       
   * required argument, + requires a value
   All items can be abbreviated (i.e., -s for -ssl)
";

#######################################################################
my @OPTS=@ARGV;
GetOptions("verbose"  => \$OUTPUT{verbose},
           "debug"    => \$OUTPUT{debug},
           "ssl"      => \$SERVER{ssl},
           "nolookup" => \$SKIPLOOKUP,
           "gener"    => \$SERVER{forcegen},
           "allcgi"   => \$SERVER{forcecgi},
           "output=s" => \$OUTPUT{file},
           "web"      => \$OUTPUT{html},
           "extended" => \$OUTPUT{extended},
           "id=s"     => \$HOSTAUTH,
           "port=s"   => \$SERVER{port},
           "timeout=s"=> \$TIME,
           "host=s"   => \$HOST);
#######################################################################
# check CLI options & setup host info
if ($HOST eq "") { &help; }   # if no target
elsif ($HOST =~ /[^0-9\.]/)   # if hostname
   {
    $SERVER{hostname}=$HOST;
    my $ip=gethostbyname($SERVER{hostname});
    if ($ip eq "") 
     { 
      fprint("+ ERROR: Could not resolve hostname\n");
      if ($request{'whisker'}->{'proxy_host'} ne "") 
       {   
        fprint ("+ Relying on proxy to resolve IP\n"); 
        $SERVER{ip}=$SERVER{hostname};
       }
      else { exit; }
     }
    else { $SERVER{ip}=inet_ntoa($ip); }
   }
else                          # if IP
   {
    $SERVER{ip}=$HOST;
    if (!$SKIPLOOKUP) { my $ip=inet_aton($SERVER{ip}); $SERVER{hostname}=gethostbyaddr($ip,AF_INET); }
   }

 if (($SERVER{ip} !~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/) && ($SERVER{ip} ne $SERVER{hostname})) # trap for proxy...
 { 
  fprint("+ ERROR: Invalid IP '$SERVER{ip}'\n");
  exit;
 }

if ($SERVER{port} eq "") { $SERVER{port}=80; }

# libwhisker default stuff
if ($SERVER{ssl}) {  $request{'whisker'}->{'ssl'}="1"; }
$request{'whisker'}->{'http_ver'}="1.1";   # default, can perform auto-switch if server doesn't understand
$request{'whisker'}->{'port'}= $SERVER{port} || 80;
$request{'whisker'}->{'host'}="$SERVER{ip}";
$request{'whisker'}->{'timeout'}=$TIME || 10;

if ($HOSTAUTH ne "")
{
 my @t=split(/:/,$HOSTAUTH);
 if (($#t ne 1) || ($t[0] eq ""))
  { fprint("+ ERROR: '$HOSTAUTH' (-i option) syntax is 'user:password' for host authentication.\n")  }
 $AUTH{hostid}=$t[0];
 $AUTH{hostpw}=$t[1];
}

#######################################################################
# test connection to remote host & get server type
 fprint("-------------------------------------------------------------------------------------\n");
 fprint("-  $NIKTO{name} v$NIKTO{version}\n");
 fprint("-------------------------------------------------------------------------------------\n");
 if ($SERVER{ip} =~ /[a-z]/i) { fprint("+ Target IP:       ?? (proxied)\n"); }
  else { fprint("+ Target IP:       $SERVER{ip}\n"); }
 if ($SERVER{hostname} ne "") { fprint("+ Target Hostname: $SERVER{hostname}\n"); }
  else { fprint("+ Target Hostname: ?? (unable to resolve)\n"); }
 fprint("+ Target Port:     $SERVER{port}\n");
 fprint("- Date:            $STARTTIME\n");
 if ($request{'whisker'}->{'proxy_host'} ne "") 
  { fprint("- Proxy:           $request{'whisker'}->{'proxy_host'}:$request{'whisker'}->{'proxy_port'}\n"); }
 if ($SERVER{ssl}) { fprint("- SSL is enabled\n"); }
 if ($HOSTAUTH ne "") { vprint("- Host Auth:       $AUTH{hostid}/$AUTH{hostpw}\n"); }
 fprint("-------------------------------------------------------------------------------------\n");

 $request{'whisker'}->{'method'}="HEAD";
 $request{'whisker'}->{'uri'}="/";

 &proxy_check;

 lw::http_fixup_request(\%request);
 if(lw::http_do_request(\%request,\%result)) 
    { 
      my $t=$result{'whisker'}->{'error'}; 
      fprint("ERROR: $t\n"); 
      exit; 
    } 
 else 
  { 
   $SERVER{servertype}=$result{'Server'}||$result{'server'}||$result{'Proxy-agent'}; 
   if ($result{'Set-Cookie'} ne "") { push(@COOKIES,"/--=--$result{'Set-Cookie'}"); }
   if ($result{'whisker'}->{'http_resp'} eq "401") { &auth_check; }
  }

 # connection details
if ($OUTPUT{debug}) {
 dprint("- Initial Connection Details:\n");
 foreach my $item (sort keys %result) { if ($item eq "whisker") { next; } dprint("- $item \t$result{$item}\n"); }
 foreach my $item (sort keys %{$result{'whisker'}}) { dprint("- $item \t$result{'whisker'}->{$item}\n"); }
}

 if ($SERVER{servertype} ne "") { fprint("+ Server: $SERVER{servertype}\n"); }
 else { fprint("+ Server ID string not present\n"); }

# get 200/404 responses from server
&check_responses;

# check CGI directories
if (!$SERVER{forcecgi}) { @CGIDIRS=&check_cgi; }

# load scan database
&load_scan_db;

# load/run plugins
&run_plugins;

#######################################################################
# run scan
# this is the looped code for all the checks
#######################################################################
 for (my $CHECKID=1;$CHECKID<=$ITEMCOUNT;$CHECKID++)
  {
   $URI = "$ROOTS{$CHECKID}$FILES{$CHECKID}";
   if ($URI eq "//") { $URI="/"; } # right???
   (my $RES, $CONTENT) = fetch($URI,$METHD{$CHECKID},$DATAS{$CHECKID});
   vprint("- $RES for $METHD{$CHECKID}:\t$URI\n");

   if ($RESPS{$CHECKID} =~ /[^0-9]/)   # response has text to match--before response code, just in case
    {
     $RESPS{$CHECKID} =~ s/([^a-zA-Z0-9\s])/\\$1/g;
     if ($CONTENT =~ /$RESPS{$CHECKID}/) { iprint($CHECKID); $STATS{okay}++; }
    }
   # is response 200 or 'found' response, and not match notfound message? or matches checkid response?
   elsif ((($RES eq ("200" || $SERVER{found})) && ($RES !~ /$SERVER{notfound}/i)) || ($RES eq $RESPS{$CHECKID}))
    {  iprint($CHECKID); $STATS{okay}++; }
   elsif ($RES eq "302")
    {
     my $R=$result{'Location'};
     fprint("+ $URI Redirects to '$R', $INFOS{$CHECKID}\n");
     $STATS{moved}++;
    }
   elsif (($RES eq "401") && !($NIKTO{suppressauth}))
    {
     my $R=$result{'WWW-Authenticate'};
     $R =~ s/^Basic //i;
     $R =~ s/realm=//i;
     fprint("+ $URI Needs Auth: (realm $R)\n");
    }

 # verify we're not getting bogus 200/302 messages
 if ($OKTRAP) 
  {
   if ($STATS{okay} > 30)
    { 
     $OKTRAP=0;
     fprint("\n+ Over 30 \"OK\" messages so far, this may be a by-product of the
            +     server answering all requests with a \"200 OK\" message. You should
            +     manually verify your results.\n");
    }
   elsif ($STATS{moved} > 30)
    {
     $OKTRAP=0;
     fprint("\n+ Over 30 \"Moved\" messages so far, this may be a by-product of the
            +     server answering all requests with a \"302\" Moved message. You should
            +     manually verify your results.\n");
    }
  }

 # end check loop
 }

#######################################################################
# print Cookies
foreach my $cookie (@COOKIES)
{
 $cookie =~ s/\n/ /g;
 my @C=split(/--=--/,$cookie);
 fprint("+ Got Cookie on file '$C[0]' with value '$C[1]'\n");
}

fprint("- $ITEMCOUNT items checked on remote host\n");

#######################################################################
# output to file?
my $linkhost=$SERVER{hostname} || $SERVER{ip};
if ($OUTPUT{file} ne "")
  {
   open(OUT,">>$OUTPUT{file}") || die print "ERROR: Unable to open '$OUTPUT{file}' for write: $!\n";
   if ($OUTPUT{html}) { print OUT "<html>\n<body bgcolor=white>\n"; }
   if ($OUTPUT{extended}) 
   {  
     my $t=join(" ",@OPTS);
     if ($OUTPUT{html}) 
      { 
       push(@PRINT,"<br>CLI Options Executed: $t<br>Explanation of options:");
       $CLIOPTS=~s/\n/<br>\n\&nbsp\;/g;
      }
     else { push(@PRINT,"\nCLI Options Executed: $t\nExplanation of options:"); }
     push(@PRINT,$CLIOPTS);
   }
   
   foreach my $line (@PRINT)
    {
     chomp($line);
     if ($OUTPUT{html})   
     { 
      $line .= "<br>"; 
      if ($line =~ /---------/) { $line="<hr>"; }
      elsif ($line =~ /$NIKTO{name} v/)   { $line=~s/$NIKTO{name}/\<a href=\"http:\/\/www.cirt.net\/\">$NIKTO{name}\<\/a\>/;
                                     $line ="<center><font size=+1>$line</font></center>\n"; }
      elsif ($line =~ /^(\+|\-) Target IP/)  
        { $line =~ s/$SERVER{ip}/<a href=\"http:\/\/$SERVER{ip}:$SERVER{port}\/\">$SERVER{ip}<\/a>/; }
      elsif ($line =~ /^(\+|\-) Target Host/)  
        { $line =~ s/$SERVER{hostname}/<a href=\"http:\/\/$SERVER{hostname}:$SERVER{port}\/\">$SERVER{hostname}<\/a>/; }
      elsif ($line =~ /^\+ \//) # item
       {
       if ($line =~ /\(GET\)/) {
        my @TEMP=split(/ /,$line);
        my $r=$TEMP[1];
        $r =~ s/^\///;
        my $disp=$r;
        $disp =~ s/\</\&lt\;/g;
        $disp =~ s/\>/\&gt\;/g;
        $TEMP[1] =~ s/([^a-zA-Z0-9\s])/\\$1/g;
        $line =~ s/$TEMP[1]/<a href=\"http:\/\/$linkhost:$SERVER{port}\/$r\">$disp<\/a>/;
        }
        # make a link for CVE identifiers, like CVE-1999-0346 or CAN-1999-0346
        $line =~ s/((cve|can)\-[0-9]{4}-[0-9]{4})/<a href=\"http:\/\/icat.nist.gov\/icat.cfm\?cvename=$1\">$1<\/a>/gi;
       }
     $line =~ s/^\- /<li>/;
     $line =~ s/^\+ /<li>/;
     }
     print OUT "$line\n";
    }
   if ($OUTPUT{html}) { print OUT "<!-- generated by $NIKTO{name} v$NIKTO{version}\n     http://www.cirt.net/ -->\n<br>\n<hr>\n</html>\n"; }
   close(OUT);
  }

exit;

#################################################################################
# FUNCTIONS
#################################################################################

#################################################################################
# run_plugins
# load plugins  & run them
# this ugly, and potentially dangerous if untrusted plugins are present
#################################################################################
sub run_plugins
{
 my @PLUGINFILES=dirlist($NIKTO{plugindir},"^nikto");
 foreach my $PIFILE (@PLUGINFILES)
 {
  require "$NIKTO{plugindir}/$PIFILE";
  vprint("- Calling plugin:$PIFILE\n");
  $PIFILE =~ s/\.pl$//;
  # just call it...hope it works right...grrr...should be better...
  &$PIFILE();
 }
return;
}
#################################################################################
# check_updates
#################################################################################
sub check_updates
{
 my (%REMOTE, %LOCAL) = ();
 my ($pluginmsg) = "";
 $request{'whisker'}->{'http_ver'}="1.0";
 $request{'whisker'}->{'port'}=80;
 if ($AUTH{proxyid} ne "") {
   $AUTH{proxystring}='Basic '.&lw::encode_base64($AUTH{proxyid}.':'.$AUTH{proxypw},'');
   $request{'whisker'}->{'http_req_trailer'}="\nProxy-authorization: $AUTH{proxystring}\n";
 }

 my  $ip=gethostbyname("www.cirt.net");
 if ($ip ne "") { $request{'whisker'}->{'host'}= inet_ntoa($ip); }
 else { $request{'whisker'}->{'host'}="www.cirt.net"; }

 # retrieve versions file
 (my $RES, $CONTENT) = fetch("/nikto/versions.txt","GET");
 if ($RES ne 200) { print "ERROR: Unable to to get www.cirt.net/nikto/versions.txt\n"; exit; }

 # parse into an array
 my @CON=split(/\n/,$CONTENT);
 foreach my $line (@CON)
 { my @l=parse_csv($line);
  $REMOTE{$l[0]}=$l[1]; }
 
 # get local versions of plugins/dbs
 my @FILES=dirlist($NIKTO{plugindir},"(^nikto_|\.db\$)");

 foreach my $file (@FILES)
 {
  my $v="";
  open(LOCAL,"<$NIKTO{plugindir}/$file") || print "ERROR: Unable to open '$NIKTO{plugindir}/$file' for read: $!\n";
  my @l=<LOCAL>;
  close(LOCAL);
  foreach my $line (@l) { if ($line =~ /^#VERSION/) { $v=$line; last; } }
  chomp($v);
  my @x=parse_csv($v);
  $LOCAL{$file}=$x[1]; 
 }

 # check versions
 my (@PITOGET, @DBTOGET)=();
 foreach my $remotefile (keys %REMOTE)
 {
  if ($remotefile eq "nikto") # main program version
   { if ($REMOTE{$remotefile} > $NIKTO{version}) 
    { print "+ Nikto has been updated to $REMOTE{$remotefile}, local copy is $NIKTO{version}\n";
      print "+ No update has taken place. Please upgrade Nikto by visiting http://www.cirt.net/\n"; 
      exit; } 
    next; }

  if ($LOCAL{$remotefile} eq "")   # no local copy
   { if ($remotefile =~ /^nikto/) { push(@PITOGET,$remotefile); } else { push(@DBTOGET,$remotefile); } }
  elsif ($REMOTE{$remotefile} > $LOCAL{$remotefile})  # remote is newer
   { if ($remotefile =~ /^nikto/) { push(@PITOGET,$remotefile); } else { push(@DBTOGET,$remotefile); } }
  elsif ($REMOTE{$remotefile} < $LOCAL{$remotefile})  # local is newer (!)
   { print "Local '$remotefile' (ver $LOCAL{$remotefile}) is NEWER than remote (ver $REMOTE{$remotefile}).\n";
     print "This seems a bit odd...\n"; } 
  
 }

 # replace local dbs if updated
 my $updates=0;
 foreach my $toget (@DBTOGET)
 {
  $updates++;
  print "+ Retrieving '$toget'\n";
  (my $RES, $CONTENT) = fetch("/nikto/$toget","GET");
  if ($RES ne 200) { print "ERROR: Unable to to get www.cirt.net/nikto/$toget\n"; exit; }
  if ($CONTENT ne "") {
   open(OUT,">$NIKTO{plugindir}/$toget") || die print "ERROR: Unable to open '$NIKTO{plugindir}/$toget' for write: $!\n";
   print OUT $CONTENT;
   close(OUT); 
  }
 }

 # notify about plugins updated
 foreach my $toget (@PITOGET)
 { $pluginmsg=1; $updates++;
   print "+ Plugin '$toget' has been added/updated. Download it at http://www.cirt.net/nikto/$toget\n"; }
 if ($pluginmsg)
  { print "- Plugins are not downloaded automatically because you could then run untrusted/unreviwed perl code.\n";
   print "- Some risk is assumed downloading .db files, but the risk is higher with actual code.\n"; }

if ($updates eq 0) { print "+ No updates required.\n"; }
exit;
}
#################################################################################
# auth_check
# if the server requires authentication & we have it...
#################################################################################
sub auth_check
{
 # find the right auth 'name' to compensate for different capitalization (Netscape!)
 my $authkey="";
 foreach my $header (keys %result) { if ($header =~ /www-authenticate/i) { $authkey=$header; last; } }

 my $R=$result{$authkey};
 $R =~ s/^Basic //i;
 $R =~ s/realm=//;
 if ($R eq "") { $R="unnamed"; }

if ($result{$authkey} !~ /basic/i)  # doh, not basic!
 {
  $R=$result{$authkey};
  $R =~ s/ .*$//;
  fprint("+ Server uses '$R' rather than 'Basic' authentication. $NIKTO{name} $NIKTO{version} can't do that.\n");
  fprint("+ Continuing scan without authentication (just in case), but suppressing 401 messages..");
  $NIKTO{suppressauth}=1;
 }

if ($AUTH{hostid} eq "")
 {
  fprint("+ Server requires authentication for $R realm, please set.\n");
  fprint("+ Continuing scan without authentication (just in case), but suppressing 401 messages..");
  $NIKTO{suppressauth}=1;
 }

 vprint("- Attempting authorization to $R realm.\n");

 $AUTH{hoststring}='Basic '.&lw::encode_base64($AUTH{hostid}.':'.$AUTH{hostpw},'');
 $request{'whisker'}->{'http_req_trailer'}="\nAuthorization: $AUTH{hoststring}f\n";

 lw::http_fixup_request(\%request);

 lw::http_do_request(\%request,\%result);

 if ($result{$authkey} ne "")
  {
   fprint("+ Server requires authentication for $R realm, unable to authenticate with supplied credentials.\n");
   fprint("+ Continuing scan without authentication (just in case), but suppressing 401 messages..");
   $NIKTO{suppressauth}=1;
  }
  else { fprint("- Successfully authenticated to realm $R.\n"); }

return;
}
#################################################################################
# proxy_check
# test whether proxy requires authentication, and if we can use it
#################################################################################
sub proxy_check
{
 # test for proxy auth
 if ($request{'whisker'}->{'proxy_host'} ne "")
 {
  lw::http_fixup_request(\%request);
  lw::http_do_request(\%request,\%result);
  if ($result{'Proxy-authenticate'} ne "")
  {
   # have id/pw?
   if ($AUTH{proxyid} eq "") { fprint("+ Proxy set up requires authentication, please set.\n"); exit; }
   $AUTH{proxystring}='Basic '.&lw::encode_base64($AUTH{proxyid}.':'.$AUTH{proxypw},'');
   $request{'whisker'}->{'http_req_trailer'}="\nProxy-authorization: $AUTH{proxystring}\n";

   # is just basic auth, right...?
   if ($result{'Proxy-authenticate'} !~ /Basic/i)
    {
     my @pauthinfo=split(/ /,$result{'Proxy-authenticate'});
     fprint("+ Proxy server uses '$pauthinfo[0]' rather than 'Basic' authentication. $NIKTO{name} $NIKTO{version} can't do that.\n");
     exit;
    }
   
   # test if id/pw are working
   lw::http_fixup_request(\%request);
   lw::http_do_request(\%request,\%result);
   if ($result{'Proxy-authenticate'} ne "") 
    { 
     my @pauthinfo=split(/ /,$result{'Proxy-authenticate'});
     my @pauthinfo2=split(/=/,$result{'Proxy-authenticate'});
     $pauthinfo2[1]=~s/^\"//; $pauthinfo2[1]=~s/\"$//;
     fprint("+ Proxy requires authentication for '$pauthinfo[0]' realm '$pauthinfo2[1]', unable to authenticate.\n");
     exit; 
    }
   else { vprint("- Successfully authenticated to proxy.\n"); }
  }
 }
 # these may be duplicates...
 $request{'whisker'}->{'method'}="HEAD";
 $request{'whisker'}->{'uri'}="/";

return;
}
#################################################################################
# directory listing
# 'pattern' is an optional regex to match the file names agains
# written by Thomas Reucker for the SETI-Web project (GPL)
#################################################################################
sub dirlist
{
 my $DIR=$_[0] || return;
 my $PATTERN=$_[1] || "";
 my @FILES = ();

 # some basic security checks... REALLY basic
 # this should be better
 if ($DIR =~ /etc/) { return; }
 
 opendir(DIRECTORY,$DIR) || die print "ERROR: Can't open directory '$DIR': $!";
 foreach my $file (readdir(DIRECTORY))
  {
   if ($file =~ /^\./)    { next; } # skip hidden files, '.' and '..'
   if ($PATTERN ne "") { if ($file =~ /$PATTERN/) { push (@FILES,$file); } }
   else { push (@FILES,$file); }
   }
closedir(DIRECTORY);
 
return @FILES;
}
#######################################################################
# dbcheck
# checks the standard databases for duplicate entries
#######################################################################
sub dbcheck {
 my (@L, @ENTRIES, %ENTRIES)=();
 my ($line, $entry) ="";

 print "--> $FILES{dbfile} Checks\n";
 open(IN,"<$FILES{dbfile}") || die print "ERROR: Unable to open '$FILES{dbfile}' for write: $!\n"; 
 @ENTRIES=<IN>; close(IN);

 foreach $line (@ENTRIES)
 {
  if ($line !~ /^check/) { next; }
  @L=parse_csv($line);
  if (($#L < 7) || ($#L > 8)) { print "Invalid syntax ($#L): $line"; next; }
  # build entry based on all except output message
  $ENTRIES{"$L[1],$L[2],$L[3],$L[4],$L[5]"}++;
 }

 foreach $entry (keys %ENTRIES) { if ($ENTRIES{$entry} > 1) { print "Duplicate ($ENTRIES{$entry}): $entry\n"; } }

 # outdated.db
 print "--> $NIKTO{plugindir}/outdated.db Checks <--\n";
 %ENTRIES=();
 open(IN,"<$NIKTO{plugindir}/outdated.db") || die print "ERROR: Unable to open '$NIKTO{plugindir}/outdated.db' for write: $!\n"; 
 @ENTRIES=<IN>; close(IN);

 foreach $line (@ENTRIES)
 {
  $line =~ s/^\s+//;
  if ($line =~ /^\#/) { next; }
  chomp($line);
  if ($line eq "") { next; }
  @L=parse_csv($line);
  if ($#L ne 2) { print "Invalid syntax ($#L): $line\n"; next; }
  $ENTRIES{"$L[0]"}++;
 }

 foreach $entry (keys %ENTRIES) { if ($ENTRIES{$entry} > 1) { print "Duplicate ($ENTRIES{$entry}): $entry\n"; } }

 #server_msgs.db
 print "--> $NIKTO{plugindir}/server_messages.db <--\n";
 %ENTRIES=();
 open(IN,"<$NIKTO{plugindir}/server_msgs.db") || die print "ERROR: Unable to open '$NIKTO{plugindir}/server_msgs.db' for write: $!\n"; 
 @ENTRIES=<IN>; close(IN);

 foreach $line (@ENTRIES)
 {
  $line =~ s/^\s+//;
  if ($line =~ /^\#/) { next; }
  chomp($line);
  if ($line eq "") { next; }
  @L=parse_csv($line);
  if ($#L ne 1) { print "Invalid syntax ($#L): $line\n"; next; }
  $ENTRIES{"$L[0]"}++;
 }

 foreach $entry (keys %ENTRIES) { if ($ENTRIES{$entry} > 1) { print "Duplicate ($ENTRIES{$entry}): $entry\n"; } }

 exit;
}
#######################################################################
# check_responses
# check what the 200/404 messages are...
#######################################################################
sub check_responses
{
 # get NOT FOUND response (404)
 ($SERVER{notfound}, $CONTENT)=fetch("/$NIKTO{fingerprint}","GET");

 if (($SERVER{notfound} eq "400") || ($SERVER{notfound} eq "")) # may need to use HTTP/1.0
  {
   my $old=$request{'whisker'}->{'http_ver'};
   if ($request{'whisker'}->{'http_ver'} eq "1.1") { $request{'whisker'}->{'http_ver'}="1.0"; }
   else { $request{'whisker'}->{'http_ver'}="1.1"; }
   fprint("- Server did not understand HTTP $old, switching to HTTP $request{'whisker'}->{'http_ver'}\n");
   ($SERVER{notfound}, $CONTENT)=fetch("/$NIKTO{fingerprint}","GET");
  }

 if ($SERVER{notfound} ne "404") 
 {
  fprint("+ Server does not follow standards--responds with '$SERVER{notfound}' for error messages instead of '404'.\n");
  fprint("+     This may increase false-positives.\n");
  if ($SERVER{notfound} eq "302") { fprint("+ Not found files redirect to: $result{'Location'}\n"); }
  if ($CONTENT =~ /not found/i) { $SERVER{notfound}="not found"; }  # shorten it, content has "not found" in it
  elsif ($CONTENT =~ /404/i) { $SERVER{notfound}="404"; }        # shorten it, content has "404" in it
  else { $SERVER{notfound} = $CONTENT; }
 }

 # get OK response (200)
 ($SERVER{found}, $CONTENT)=fetch("/","GET");
 if ($SERVER{found} eq 404)  # assume server does not actually have a / & set it to 200
 {
  $SERVER{found}=200;
  vprint("+ No root document found, assuming 200 is OK response.\n");
 }
 elsif ($SERVER{found} != 200) 
 {
  #fprint("+ Server does not follow standards--responds with '$SERVER{found}' for OK messages instead of '200'.\n");
  #fprint("+     This may increase false-positives.\n");
  if ($SERVER{found} eq "302") 
   { 
    fprint("+ The root file redirects to: $result{'Location'}\n"); 
    # try to get redirected location to see if 200 is actually the valid response
    ($SERVER{found}, $CONTENT)=fetch($result{'Location'},"GET");
    if ($SERVER{found} ne 200) # still no good... just a 302, stop going in circles
     {  $SERVER{found}=302; } 
    }
 }

 # if they're the same, something is amiss... just pick a 404/200 scheme, nothing better to do
 if ($SERVER{notfound} eq $SERVER{found}) 
 { 
  $SERVER{notfound}=404; $SERVER{found}=200; 
  fprint("+ The found & not found messages appear to be the same, be skeptical of positives.\n");
 }
return;
}
#######################################################################
# figure out CGI directories
# check_cgi
#######################################################################
sub check_cgi
{
 my ($gotvalid,$gotinvalid)=0;
 my @POSSIBLECGI=();
 my ($res, $possiblecgidir) ="";

 foreach $possiblecgidir (@CGIDIRS)
  {
   ($res, $CONTENT)=fetch($possiblecgidir,"GET");
   dprint("Checked for CGI dir\t$possiblecgidir\tgot:$res\n");
   if (($res eq 302) || ($res eq 200) || ($res eq 403)) { 
     push(@POSSIBLECGI,$possiblecgidir); 
     $gotvalid++; 
   }
  }

 if ($gotvalid eq 0) 
  { 
   fprint("+ No CGI Directories found (use -a to force check all possible dirs)\n"); 
   @CGIDIRS=();
  }
 else 
  { 
   @CGIDIRS=@POSSIBLECGI; 
   vprint("- Checking for CGI in: @CGIDIRS\n");
  }

 return @CGIDIRS;
}
#######################################################################
# get a page
# fetch URI, METHOD
#######################################################################
sub fetch
{
 my $uri=$_[0] || return;
 if ($uri eq "//") { $uri="/"; } # trap for some weird ones
 $request{'whisker'}->{'method'} = $_[1] || "GET";
 $request{'whisker'}->{'uri'}    = $uri;
 if ($_[2] ne "") {  my $x=$_[2]; $x=~s/\\\"/\"/g; $request{'whisker'}->{'data'} = $x; }
 $STATS{requests}++;
 lw::http_fixup_request(\%request);
 lw::http_do_request(\%request,\%result);
 
 if ($result{'Set-Cookie'} ne "") { push(@COOKIES,"/--=--$result{'Set-Cookie'}"); }
 &lw::http_reset;

 return $result{'whisker'}->{'http_resp'}, $result{'whisker'}->{'data'};
}


#######################################################################
# return $_[0] 'x' characters
#######################################################################
sub junk
{
 return "x" x $_[0];
}
#######################################################################
# load scan database
#######################################################################
sub load_scan_db
{
 my $shname=$SERVER{hostname} || $SERVER{ip};
 my ($line, $stype) = "";
 my (@item, @file, @scat) = ();
 open(IN,"<$FILES{dbfile}") || die print "ERROR: Unable to open '$FILES{dbfile}' for write: $!\n";
 @file=<IN>;
 close(IN); 

 # first figure out server type
 foreach $line (@file)
 {
  if ($line =~ /^servercat/i)
   {
    if ($line =~ /\#/) { $line=~s/\#.*$//; $line=~s/\s+$//; }
    chomp($line);
    @scat=parse_csv($line);
    dprint("servercat compare: '$SERVER{servertype}' to '$scat[2]'\n");
    if ($SERVER{servertype} =~ /$scat[2]/i) 
      { 
        $SERVER{category}=$scat[1]; 
        dprint("servercat match:$scat[1]\n"); 
        last; 
      }
   }
 }
 if ($SERVER{category} eq "") { $SERVER{category}="generic"; }

 # now load checks
 foreach $line (@file)
 {
  if ($line !~ /^check/i) { next; }
  @item=();
  chomp($line);
  #if ($line =~ /\#/) { $line=~s/\#.*$//; $line=~s/\s+$//; }
  @item=parse_csv($line);
  # if the right category or cat is generic...
  #dprint("db load check: '$SERVER{category}' to '$item[1]'\n");
  if (($SERVER{category} =~ /$item[1]/i) || ($item[1] =~ /generic/i) || ($SERVER{servertype} eq "") || ($SERVER{forcegen}))
   {
    # substitute for @IP, @HOSTNAME in check
    for (my $i=2;$i<=$#item;$i++)
     {
      if ($i eq 5) { next; }  # skip 5, method
      $item[$i] =~ s/\@IP/$SERVER{ip}/g;
      $item[$i] =~ s/\@HOSTNAME/$shname/g;
      if ($item[$i] =~ /(JUNK\([0-9]+\))/)  # junk overflow
       {
        my $j= my $m=$1;
        $j=~ s/^JUNK\(//;
        $j=~ s/\)//;
        $j=junk($j);
        $m=~s/([^a-zA-Z0-9])/\\$1/g;
        $item[$i] =~ s/$m/$j/;
       }
     }
    
    if ($item[2] eq "") { $item[2]="/"; }
    if (($#item < 5) || ($#item > 7)) { dprint("Invalid check syntax:@item:\n"); }
    if ($item[2] eq "\@CGIDIRS")  # multiple checks in one
     {
      foreach my $CGI (@CGIDIRS)
       {
       $ITEMCOUNT++;
       $ROOTS{$ITEMCOUNT}=$CGI;
       $FILES{$ITEMCOUNT}=$item[3];
       $RESPS{$ITEMCOUNT}=$item[4] || "200";
       $METHD{$ITEMCOUNT}=$item[5] || "GET";
       $INFOS{$ITEMCOUNT}=$item[6] || "Informational";
       $DATAS{$ITEMCOUNT}=$item[7] || "";
       dprint("Loaded:\t$item[1]:\t$ROOTS{$ITEMCOUNT}$FILES{$ITEMCOUNT}\n");
       }
     }
    else # normal, single check
     {
      $ITEMCOUNT++;
      $ROOTS{$ITEMCOUNT}=$item[2];
      $FILES{$ITEMCOUNT}=$item[3];
      $RESPS{$ITEMCOUNT}=$item[4] || "200";
      $METHD{$ITEMCOUNT}=$item[5] || "GET";
      $INFOS{$ITEMCOUNT}=$item[6] || "Informational";
      $DATAS{$ITEMCOUNT}=$item[7] || "";
      dprint("Loaded:\t$item[1]:\t$ROOTS{$ITEMCOUNT}$FILES{$ITEMCOUNT})\n");
     }
   }
 }

vprint("- Server category identified as '$SERVER{category}', if this is not correct please use -g to force a generic scan.\n");
vprint("- Loaded $ITEMCOUNT server checks\n");
if ($ITEMCOUNT eq 0) { fprint("+ Unable to load valid checks!\n"); exit; }
if ($SERVER{forcegen}  eq 0) { vprint("+ Forcing full DB scan"); }

return;
}
#######################################################################
# Print standard item information
# iprint CHECKID
#######################################################################
sub iprint
{
 print "+ $URI - $INFOS{$_[0]} ($METHD{$_[0]})\n";
 push(@PRINT,"+ $URI - $INFOS{$_[0]} ($METHD{$_[0]})\n");
 return;
}
#######################################################################
# print debug information
# dprint 'string'
#######################################################################
sub dprint
{
 if ($OUTPUT{debug}) { print $_[0]; }
 return;
}
#######################################################################
# print verbose information
# vprint 'string'
#######################################################################
sub vprint
{
 if ($OUTPUT{verbose}) { print $_[0]; }
 return;
}
#######################################################################
# basic print (but pushes to @PRINT for file save)
# fprint 'string'
#######################################################################
sub fprint
{
 push(@PRINT,$_[0]);
 print $_[0];
 return;
}
#######################################################################
# turn CSV data to an array
# parse_csv 'string'
#######################################################################
sub parse_csv
{
 my $text = $_[0];
 my @new = ();
 push(@new, $+) while $text =~ m{
 "([^\"\\]*(?:\\.[^\"\\]*)*)",?
    |  ([^,]+),?
    | ,
  }gx;
  push(@new, undef) if substr($text, -1,1) eq ',';
  return @new;
}
#######################################################################
# print help info
#######################################################################
sub help
{
 fprint("$NIKTO{name} - $NIKTO{version}");
 fprint("$CLIOPTS");
 exit;
}
#######################################################################
#######################################################################

