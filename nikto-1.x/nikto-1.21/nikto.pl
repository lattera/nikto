#!/usr/bin/perl
use IO::Socket;
use Getopt::Long;

# INSTALLED LW:
#use LW; 
# LOCAL LW:
require "./plugins/LW.pm";

#######################################################################
# last update: 08.21.2002
# --------------------------------------------------------------------#
#                               Nikto                                 #
# --------------------------------------------------------------------#
# This copyright applies to all code included in this distribution.
#
# Copyright (C) 2001, 2002 Sullo/CIRT.net
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2  of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the 
# Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
# Contact Information:
#  Sullo (sullo@cirt.net)
#  http://www.cirt.net/
#######################################################################
# See the README.txt and/or help files for more information on how to use & config.  
# See the LICENSE.txt file for more information on the License Nikto is distributed under.
#
# This program is intended for use in an authorized manner only, and the author
# can not be held liable for anything done with this program, code, or items discovered
# with this program's use.
#######################################################################
# global var/definitions
use vars qw/@OPTS $URI $SKIPLOOKUP $CONTENT $ITEMCOUNT $CLIOPTS $PAUSE $TIME @PRINT @CGIDIRS @COOKIES %FILES/;
use vars qw/%CONFIG %NIKTO %OUTPUT %ROOTS %METHD %FILES %RESPS %INFOS %SERVER %request %result %JAR %DATAS/;
use vars qw/$DIV $VULS $OKTRAP $HOST %BANNERS %TARGETS @DBFILE @BUILDITEMS $PROXYCHECKED/;

$NIKTO{version}="1.21";
$NIKTO{name}="Nikto";
$DIV = "-" x 100;
my $STARTTIME=localtime();
fprint("$DIV\n");
fprint("- $NIKTO{name} v$NIKTO{version}  - www.cirt.net - $STARTTIME\n");

&general_config;
LW::http_init_request(\%request);
&host_config;
&load_scan_items;
$PROXYCHECKED=0; # only do proxy_check once

# actual scan for each host/port
foreach $target (keys %TARGETS)
 {
  foreach $port ( keys %{$TARGETS{$target}} )
   {
    $request{'whisker'}->{'host'}=$target;
    $request{'whisker'}->{'port'}=$port;
    $request{'whisker'}->{'ssl'}=$TARGETS{$target}{$port};
    $request{'whisker'}->{'lowercase_incoming_headers'}=1;
    $request{'whisker'}->{'http_ver'}=$CONFIG{DEFAULTHTTPVER};
    $request{'whisker'}->{'timeout'}=$TIME || 10;
    $request{'User-Agent'} = $NIKTO{useragent};
    $request{'whisker'}->{'anti_ids'}=$NIKTO{evasion};
    $request{'Host'}=$SERVER{vhost} || $SERVER{hostname} || $SERVER{ip};
    $VULS=0;

    &proxy_check;
    &banner_get;
    &dump_target_info;
    &check_responses;
    @CGIDIRS=&check_cgi;
    &set_scan_items;
    &run_plugins;
    &test_target;
   }
 }

exit;

# --------------------------------------------------------------------#
#                             Functions                               #
# --------------------------------------------------------------------#
sub test_target
{
  # print connection details
  if ($OUTPUT{debug})
   {
    dprint("- Initial Server Connect Details:\n");
    &dump_result_hash;
   }

  # this is actual the looped code for all the checks
  for (my $CHECKID=1;$CHECKID<=$ITEMCOUNT;$CHECKID++)
  { 
   $URI = "$ROOTS{$CHECKID}$FILES{$CHECKID}";
   if ($URI eq "//") { $URI="/"; }
   (my $RES, $CONTENT) = fetch($URI,$METHD{$CHECKID},$DATAS{$CHECKID});
   vprint("- $RES for $METHD{$CHECKID}:\t$request{whisker}{uri}\n");

   if ($RESPS{$CHECKID} =~ /[^0-9]/)   # response has text to match--before response code, just in case
    {
     $RESPS{$CHECKID} =~ s/([^a-zA-Z0-9\s])/\\$1/g; # escaping...
     if ($CONTENT =~ /$RESPS{$CHECKID}/) { $VULS++; iprint($CHECKID,$request{whisker}{uri}); $NIKTO{totalokay}++; }
    }
   # is response 200 or 'found' response, and not match notfound message? or matches checkid response?
   elsif ((($RES eq ("200" || $SERVER{found})) && ($RES !~ /$SERVER{notfound}/i)) || ($RES eq $RESPS{$CHECKID}))
    {  $VULS++; iprint($CHECKID,$request{whisker}{uri}); $NIKTO{totalokay}++; }
   elsif ($RES eq "302")
    {
     fprint("+ $URI Redirects to '" . $result{'location'} ."', $INFOS{$CHECKID}\n");
     $NIKTO{totalmoved}++;
    }
   elsif (($RES eq "401") && !($NIKTO{suppressauth}))
    {
     my $R=$result{'www-authenticate'};
     $R =~ s/^Basic //i;
     $R =~ s/realm=//i;
     fprint("+ $URI Needs Auth: (realm $R)\n");
    }

 # verify we're not getting bogus 200/302 messages
 &fp_warning;
 
 # end check loop
 sleep $PAUSE;
 }

# print any cookies found
foreach my $cookie (@COOKIES)
{
 $cookie =~ s/\n/ /g;
 my @C=split(/--=--/,$cookie);
 fprint("+ Got Cookie on file '$C[0]' with value '$C[1]'\n");
}

# do this again, at the end so it's obvious. reset OKTRAP.
$OKTRAP=1;
&fp_warning;

if ($VULS eq 1) { fprint("- $ITEMCOUNT items checked, $VULS item found on remote host\n"); }
else            { fprint("- $ITEMCOUNT items checked, $VULS items found on remote host\n"); }

 &save_output;

}
#################################################################################
sub fp_warning
{
 if ($OKTRAP) 
  {
   if ($NIKTO{totalokay} > 30)
    { 
     $OKTRAP=0;
     fprint("\n+ Over 30 \"OK\" messages, this may be a by-product of the
            +     server answering all requests with a \"200 OK\" message. You should
            +     manually verify your results.\n");
    }
   elsif ($NIKTO{totalmoved} > 30)
    {
     $OKTRAP=0;
     fprint("\n+ Over 30 \"Moved\" messages, this may be a by-product of the
            +     server answering all requests with a \"302\" Moved message. You should
            +     manually verify your results.\n");
    }
  }
}
#################################################################################
sub dump_target_info
{
 # print out initial connection junk
 my $SSLPRINT="";
 if ($SERVER{ssl}) 
   { 
    my $SSLCIPHERS=$result{whisker}{ssl_cipher}      || "Enabled"; 
    my $SSLISSUERS=$result{whisker}{ssl_cert_issuer} || "Unknown";
    my $SSLINFO=$result{whisker}{ssl_cert_subject}   || "Unknown";
    $SSLPRINT="$DIV\n";
    $SSLPRINT.="+ SSL Info:        Ciphers: $SSLCIPHERS\n                   Info:    $SSLISSUERS\n                   Subject: $SSLINFO\n";
   }
 
  
 fprint("$DIV\n");
 if ($SERVER{ip} =~ /[a-z]/i) { fprint("+ Target IP:       ?? (proxied)\n"); }
     else { fprint("+ Target IP:       $SERVER{ip}\n"); }
 if ($SERVER{hostname} ne "") { fprint("+ Target Hostname: $SERVER{hostname}\n"); }
     else { fprint("+ Target Hostname: ?? (unable to resolve)\n"); }
 fprint("+ Target Port:     $request{'whisker'}{'port'}\n");
 if (($SERVER{vhost} ne $SERVER{hostname}) && ($SERVER{vhost} ne ""))
     { fprint("+ Virtual Host: $SERVER{vhost}\n"); }
 if ($request{'whisker'}->{'proxy_host'} ne "") 
     { fprint("- Proxy:           $request{'whisker'}->{'proxy_host'}:$request{'whisker'}->{'proxy_port'}\n"); }
 if ($NIKTO{hostid} ne "") { vprint("- Host Auth:       $NIKTO{hostid}/$NIKTO{hostpw}\n"); }
 if ($SERVER{ssl}) { fprint($SSLPRINT); }
 for (my $i=1;$i<=9;$i++) { if ($NIKTO{evasion} =~ /$i/) { fprint("+ Using IDS Evasion:\t$NIKTO{anti_ids}{$i}\n"); }}
 fprint("$DIV\n");
 if (!($SERVER{forcegen})) { fprint("- Scan is dependent on \"Server\" string which can be faked, use -g to override\n"); }

 if ($SERVER{servertype} ne "") { fprint("+ Server: $SERVER{servertype}\n"); }
    else { fprint("+ Server ID string not sent\n"); }
 return;
}
#################################################################################
sub general_config
{
 my ($HOSTAUTH) ="";
 ## gotta set these first
 $|=1;
 $NIKTO{anti_ids}{1}="Random URI encoding (non-UTF8)";
 $NIKTO{anti_ids}{2}="Directory self-reference (/./)";
 $NIKTO{anti_ids}{3}="Premature URL ending";
 $NIKTO{anti_ids}{4}="Prepend long random string";
 $NIKTO{anti_ids}{5}="Fake parameter";
 $NIKTO{anti_ids}{6}="TAB as request spacer";
 $NIKTO{anti_ids}{7}="Random case sensitivity";
 $NIKTO{anti_ids}{8}="Use Windows directory separator (\\)";
 $NIKTO{anti_ids}{9}="Session splicing";

 $NIKTO{mutate_opts}{1}="Test all files with all root directories";
 $NIKTO{mutate_opts}{2}="Guess for password file names";

 $CLIOPTS="
   Options:
       -allcgi       		force scan of all possible CGI directories
       -mutate+           	mutate checks (see below)
       -evasion+        	ids evasion technique (1-9, see below)
       -findonly      		find http(s) ports only, don't perform a full scan
       -generic       		force full (generic) scan
       -host+       		target host
       -id+          		host authentication to use, format is userid:password
       -nolookup       		skip name lookup
       -output+       		also write output to this file
       -port+       		port to use (default 80)
       -ssl 	     		force ssl mode on port
       -timeout	     		timeout (default is 10 seconds)
       -useproxy         	use the proxy defined in config.txt
       -vhost+       		virtual host (for Host header)
       -web (format)  		write to file in web HTML format
   * required argument, + requires a value
   
   These options cannot be abbreviated:
       -update      		update databases and plugins from cirt.net
       -verbose      		verbose mode
       -debug            	debug mode
       -google              use Google search to find files
   
   IDS Evasion Techniques:
   ";

 for (my $i=0;$i<=9;$i++) { if ($NIKTO{anti_ids}{$i} eq "") { next; } 
                            $CLIOPTS .= "\t$i\t$NIKTO{anti_ids}{$i}\n"; }
 $CLIOPTS .= "\n   Mutation Techniques:\n";
 for (my $i=0;$i<=9;$i++) { if ($NIKTO{mutate_opts}{$i} eq "") { next; } 
                            $CLIOPTS .= "\t$i\t$NIKTO{mutate_opts}{$i}\n"; }

 ### CONFIG FILE STUFF
 my $configfile="config.txt";
 my $noconfig=0;
   open(CONF,"<$configfile") || $noconfig++;
   my @CONFILE=<CONF>;
   close(CONF);

 if ($noconfig) { fprint("- No config.txt file found, only 1 CGI directory defined.\n"); }

  foreach my $line (@CONFILE)
   {
    $line =~ s/\#.*$//;
    chomp($line);
    $line =~ s/\s+$//;
    $line =~ s/^\s+//;
    if ($line eq "") { next; }
    my @temp=split(/=/,$line);
    if ($temp[0] ne "") { $CONFIG{$temp[0]}=$temp[1]; }
   }

 # add CONFIG{CLIOPTS} to ARGV if defined...
 if ($CONFIG{CLIOPTS} ne "")
  {
   my @t=split(/ /,$CONFIG{CLIOPTS});
   foreach my $c (@t) { push(@ARGV,$c); }
  }

 ### PLUGIN DIRECTORY STUFF
 # get the correct path to 'plugins'
 # if defined in config.txt file...
 if ($CONFIG{PLUGINDIR} ne "")
  {
   if (-d $CONFIG{PLUGINDIR}) { $NIKTO{plugindir}=$CONFIG{PLUGINDIR}; }
  }
 
 if ($NIKTO{plugindir} eq "")
  { 
   # try pwd?
   my $NIKTODIR="";
   if (-d "$ENV{PWD}/plugins") { $NIKTODIR="$ENV{PWD}/"; }
   elsif (-d "plugins") { $NIKTODIR=""; }
   else
   {
    my $EXECDIR=$ENV{_};
    chomp($EXECDIR);
    $EXECDIR =~ s/nikto.pl$//;
    if ($EXECDIR =~ /(perl|perl\.exe)$/) { $EXECDIR=""; }  # executed as 'perl nikto.pl' ...
    if (-e "$EXECDIR/plugins") { $NIKTODIR="$EXECDIR/"; }
   }
   $NIKTO{plugindir}="$NIKTODIR"; $NIKTO{plugindir} .= "plugins";
  }

  if (!(-d $NIKTO{plugindir}))
  {
   print "I can't find 'plugins' directory. ";
   print "I looked in \& around:\n\t$ENV{PWD}\n\t$ENV{_}\n";
   print "Try switching to the 'nikto' directory so that the plugins dir can be found.\n";
   exit;
  }
 $FILES{dbfile}="$NIKTO{plugindir}/scan_database.db";
 $FILES{userdbfile}="$NIKTO{plugindir}/user_scan_database.db"; 

 ### CLI STUFF
 $PAUSE=$NIKTO{google}=$NIKTO{suppressauth}=$OUTPUT{html}=$OUTPUT{verbose}=$SKIPLOOKUP=$NIKTO{totalmoved}=$NIKTO{totalokay}=$NIKTO{totalrequests}=$ITEMCOUNT=0;
 @OPTS=@ARGV;
 
 # preprocess some CLI options
 for (my $i=0;$i<=$#ARGV;$i++)
  {
   if    ($ARGV[$i] =~ /\-dbcheck/)  { &dbcheck; }   
   elsif ($ARGV[$i] =~ /\-update/)   { &check_updates; } 
   elsif ($ARGV[$i] =~ /\-verbose/)  { $OUTPUT{verbose}=1; $ARGV[$i]=""; }
   elsif ($ARGV[$i] =~ /\-debug/)    { $OUTPUT{debug}=1;   $ARGV[$i]=""; }
   elsif ($ARGV[$i] =~ /\-google/)   { $NIKTO{google}=1;   $ARGV[$i]=""; }
  }

 GetOptions(
           "nolookup" => \$SKIPLOOKUP,
           "gener"    => \$SERVER{forcegen},
           "allcgi"   => \$SERVER{forcecgi},
           "output=s" => \$OUTPUT{file},
           "mutate=s" => \$NIKTO{mutate},
           "web"      => \$OUTPUT{html},
           "id=s"     => \$HOSTAUTH,
           "evasion=s"=> \$NIKTO{evasion},
           "port=s"   => \$SERVER{port},
           "findonly" => \$SERVER{findonly},
           "ssl"      => \$SERVER{ssl},
           "timeout=s"=> \$TIME,
           "x=s"      => \$PAUSE,
           "useproxy" => \$SERVER{useproxy},
           "vhost=s"  => \$SERVER{vhost},
           "host=s"   => \$HOST);

 ### VARIABLES (STUFF)
 @CGIDIRS=split(/ /,$CONFIG{CGIDIRS});
 if ($#CGIDIRS < 0) { $CGIDIRS[0]="/cgi-bin/"; }

 $OKTRAP=1;
 if ($HOSTAUTH ne "")
 {
  my @t=split(/:/,$HOSTAUTH);
  if (($#t ne 1) || ($t[0] eq ""))
   { fprint("+ ERROR: '$HOSTAUTH' (-i option) syntax is 'user:password' for host authentication.\n")  }
  $NIKTO{hostid}=$t[0];
  $NIKTO{hostpw}=$t[1];
 } 
 $NIKTO{evasion}=~s/[^0-9]//g;

 $NIKTO{useragent}="Mozilla/4.75 ($NIKTO{name}/$NIKTO{version} $request{'User-Agent'})";
 
 # here's the fingerprint -- this should always be something which will NOT be found on the server!
 $NIKTO{fingerprint}="$NIKTO{name}-$NIKTO{version}-" . LW::utils_randstr() . ".htm";

 if ($NIKTO{evasion} ne "")  # remove all refs to Nikto/LW
 {
  $NIKTO{useragent}="Mozilla/4.75";
  $NIKTO{fingerprint}=LW::utils_randstr() . ".htm";
 }

# SSL Test
if (!$LW::LW_HAS_SSL) 
 { fprint("-***** SSL support not available (see docs for SSL install instructions) *****\n"); }


return;
}
#################################################################################
sub host_config
{

if ($SERVER{useproxy}) {
 $request{'whisker'}->{'proxy_host'}=$CONFIG{PROXYHOST};
 $request{'whisker'}->{'proxy_port'}=$CONFIG{PROXYPORT};
}

 my @ports = ();
  ### HOST STUFF

 if ($HOST eq "") { &usage; }  # if no target
 elsif ($HOST =~ /[^0-9\.]/)   # if hostname
   {
    $SERVER{hostname}=$HOST;
    my $ip=gethostbyname($SERVER{hostname});
    if (($ip eq "") && ($request{'whisker'}->{'proxy_host'} ne ""))
     { $SERVER{ip}=$SERVER{hostname}; }
    elsif (($ip eq "") && ($request{'whisker'}->{'proxy_host'} eq ""))
     { print("+ ERROR: Cannot resolve hostname to IP\n"); 
       exit;
     }
    else
     { $SERVER{ip}=inet_ntoa($ip); }
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

 # port(s)
 $SERVER{port}=~s/^\s+//;
 $SERVER{port}=~s/\s+$//;
 if ($SERVER{port} eq "") { $SERVER{port}=80; }
 if ($SERVER{port} =~ /[^0-9\-\, ]/) { fprint("+ ERROR: Invalid port option '$SERVER{port}'\n"); exit; }
 
 if ($SERVER{port} =~ /[\,\-]/)  # need a port scan
  { portscan($SERVER{ip},$SERVER{port}); }
 else  # just 1 port
  { port_check($SERVER{ip},$SERVER{port}); }

# if no open ports found
 my $VALID=0;
 foreach $target (keys %TARGETS) { $VALID++; last; }
 if (!$VALID) { fprint("+ No HTTP(s) ports were found open on the server.\n"); }

if ($SERVER{findonly})  # no scan!
{
 foreach $target (keys %TARGETS)
  {
   foreach $port ( sort keys %{$TARGETS{$target}} )
    {
     if ($TARGETS{$target}{$port}) 
      {
       if ($BANNERS{$target}{$port} eq "") { $BANNERS{$target}{$port}="(no identification could be made)"; } 
       fprint("+ Server: https://$target:$port\t$BANNERS{$target}{$port}\n"); }
     else { fprint("+ Server: http://$target:$port\t$BANNERS{$target}{$port}\n"); }
  }
 }
 &save_output;
 exit;
} 
 return;
}
#################################################################################
# perform a port scan
#################################################################################
sub portscan
{
 my $portopts=$_[1] || return;
 my $target=$_[0]   || return;
 my (@t) = ();
 my %portlist;
 
 # if we're using nmap, skip this & let nmap handle port ranges...
 if (!(-X $CONFIG{NMAP}))
{
 # break out , items
 if ($portopts =~ /,/)
  {
   my @u=split(/\,/,$portopts);
   foreach my $x (@u) { push(@t,$x); }
  }
 else { push(@t,$portopts); }
 
 # ranges
 foreach my $x (@t)
  {
   $x=~s/^\s+//;
   $x=~s/\s+$//;
   if ($x !~ /-/) { $portlist{$x}=0; }
   else 
    {
     my @u=split(/\-/,$x);
     for (my $i=$u[0];$i<=$u[1];$i++) { $portlist{$i}=0; } 
    }
  }
  
 # last check for only null lists (i.e., user put in 4-1 as a range)
 my $invalid=1;
 foreach $p (keys %portlist) { if ($p =~/[0-9]/) { $invalid=0; } last; }
 if ($invalid) { fprint("+ ERROR: Invalid port option '$SERVER{port}'\n"); exit; }
}  # end if not NMAP

 # if NMAP is defined, use that... if not, we do it the hard way
 if (-X $CONFIG{NMAP})
  {
   vprint("- Calling nmap:$CONFIG{NMAP} -oG - -p $portopts $SERVER{ip}\n");
   foreach my $line (split(/\n/,`$CONFIG{NMAP} -oG - -p $portopts $SERVER{ip}`))
    {
     if ($line !~ /^Host/) { next; }
     $line =~ s/^.*Ports: //;
     $line =~ s/Ignored.*$//;
     $line =~ s/^\s+//;
     $line =~ s/\s+$//;
     foreach my $PORTSTRING (parse_csv($line)) { $portlist{(split(/\//,$PORTSTRING))[0]}=0; }
    } 
  }

 # test each port...
 vprint("- Testing open ports for web servers\n");
 foreach $p (sort keys %portlist) 
  { 
   if ($p !~ /[0-9]/) { next; }
   $p =~ s/\s+$//;
   $p =~ s/^\s+//;
   foreach my $skip (split(/ /,$CONFIG{SKIPPORTS})) { if ($skip eq $p) { $p=""; last; } }
   if ($p eq "") { next; }
   port_check($target,$p); 
  }
  
 return;
}
#################################################################################
sub port_check
{
 my $host=$_[0] || return 0;
 my $port=$_[1] || return 0;
 $port =~ s/(^\s+|\s+$)//g;
 # we don't really need to do this (now), but...
 my $oldhost= $request{'whisker'}->{'host'};
 $request{'whisker'}->{'host'}=$host;
 
 dprint("- Checking for open port: $port\n");
 # if no proxy, try regular socket connection & if it fails, return
 if ($request{'whisker'}->{'proxy_host'} eq "")  
  {
   if (!LW::utils_port_open($host,$port)) { $request{'whisker'}->{'host'}=$oldhost; return; }
  }
  
 # if the connect succeeded OR there is a proxy set up...
 # try http
 if (!$SERVER{ssl}) # no force-ssl
  {
   vprint("- Checking for HTTP on port $port\n");
   $request{'whisker'}->{'ssl'}=0;
   $request{'whisker'}->{'port'}= $port;
   LW::http_fixup_request(\%request);
   $request{'whisker'}->{'lowercase_incoming_headers'}=1;
   if (!LW::http_do_request(\%request,\%result)) 
    { $TARGETS{$host}{$port}=0;
      $BANNERS{$host}{$port}=$result{'server'};
      dprint("- Server found: $host:$port \t$result{'server'}\n"); 
      $request{'whisker'}->{'host'}=$oldhost; 
      return; 
    }
  }
  
 # if that fails, try https
 vprint("- Checking for HTTPS on port $port\n");
 $request{'whisker'}->{'ssl'}=1;
 $request{whisker}->{save_ssl_info}=1;
 $request{'whisker'}->{'port'}= $port;
 LW::http_fixup_request(\%request);
 $request{'whisker'}->{'lowercase_incoming_headers'}=1;
 if (!LW::http_do_request(\%request,\%result)) 
    { $TARGETS{$host}{$port}=1; 
      $BANNERS{$host}{$port}=$result{'server'};
      $request{'whisker'}->{'host'}=$oldhost; 
      $SERVER{ssl}=1;
      dprint("- Server found: $host:$port \t$result{'server'}\n"); 
      return; 
    }
  
 return;
}
#################################################################################
# save output to a file
#################################################################################
sub save_output
{
 my $linkhost=$SERVER{hostname} || $SERVER{ip};
 my $httpstring="http";
 if ($SERVER{ssl}) { $httpstring="https"; }
 
 my $lctr=0;
 
 if ($OUTPUT{file} ne "")
  {
   open(OUT,">>$OUTPUT{file}") || die print "+ ERROR: Unable to open '$OUTPUT{file}' for write: $@\n";
   if ($OUTPUT{html}) { print OUT "<html>\n<body bgcolor=white>\n"; }

     my $t=join(" ",@OPTS);
     if ($OUTPUT{html}) 
      { 
       push(@PRINT,"<br>CLI Options Executed: $t<br>Explanation of options:");
       $CLIOPTS=~s/\n/<br>\n\&nbsp\;/g;
       push(@PRINT,$CLIOPTS);
      }
     else { push(@PRINT,"\n");
            push(@PRINT,"$DIV\n");
            push(@PRINT,"CLI Options Executed: $t");
            push(@PRINT,"Explanation of options:"); 
            foreach my $l (split(/\n/,$CLIOPTS)) { chomp($l); push(@PRINT,$l); }
         }

   if (!$OUTPUT{html})
   {      
   foreach my $line (@PRINT)
    {
     chomp($line);
     $line =~ s/((CVE|CAN)\-[0-9]{4}-[0-9]{4})/http\:\/\/icat\.nist\.gov\/icat\.cfm\?cvename=$1/g;
     $line =~ s/(CA\-[0-9]{4}-[0-9]{2})/http\:\/\/www\.cert\.org\/advisories\/$1\.html/g;
     $line =~ s/(BID\-[0-9]{4})/http\:\/\/www\.securityfocus\.com\/bid\/$1/g;
     $line =~ s/(IN\-[0-9]{4}\-[0-9]{2})/http\:\/\/www\.cert\.org\/incident_notes\/$1\.html/gi;
     $line =~ s/(MS[0-9]{2}\-[0-9]{3})/http\:\/\/www\.microsoft\.com\/technet\/security\/bulletin\/$1\.asp/gi;
     @temp=();

     if (length($line) > 100) 
       {
         while (length($line) > 100) 
          {
           # get last space
           my $i=""; my @b=split(//,$line);
           for ($i=$#b;$i>=0;$i--) { if (($b[$i] eq " ") && ($i < 100)) { last; } }
           push(@temp,substr($line,0,$i));
           substr($line,0,$i,"    ");
          }
          # remainder
        if (length($line) > 0) { push(@temp,$line); }
       }
      else { push(@temp,$line); }
       
     foreach $l (@temp) {
 #     chomp($KG[$lctr]);
 #     if ($KG[$lctr] eq "") { $KG[$lctr] = " " x 30, "  | "; }
      if ($OUTPUT{html}) { print OUT "<pre>"; }
      print OUT "$l\n";
      $lctr++;
     }
    }
    
 #  if ($lctr < $#KG) { while ($lctr < $#KG) { print OUT "$KG[$lctr]  | \n"; $lctr++; } } 
   print OUT "$DIV\n";
   close(OUT);
   }
   
   if ($OUTPUT{html})
   {
    print OUT "<html><body bgcolor=white>\n";
    print OUT "<ul>\n";
    my $skip=1;
    foreach my $line (@PRINT)
    {
      $line .= "<br>"; 
      if ($line =~ /---------/) { if ($skip) { $skip--; next; } $line="<hr>"; }
      elsif ($line =~ /$NIKTO{name} v/)  { $line=~s/$NIKTO{name}/\<a href=\"$httpstring\:\/\/www.cirt.net\/\">$NIKTO{name}\<\/a\>/;
                                     $line ="<center><font size=+1>$line</font></center>\n"; }
      elsif ($line =~ /^(\+|\-) Target IP/)  
        { $line =~ s/$SERVER{ip}/<a href=\"$httpstring\:\/\/$SERVER{ip}:$SERVER{port}\/\">$SERVER{ip}<\/a>/; }
      elsif ($line =~ /^(\+|\-) Target Host/)  
        { $line =~ s/$SERVER{hostname}/<a href=\"$httpstring\:\/\/$SERVER{hostname}:$SERVER{port}\/\">$SERVER{hostname}<\/a>/; }
      elsif ($line =~ /^\+ \//) # item
       {
       if ($line =~ /\(GET\)/) 
       {
        my @TEMP=split(/ /,$line);
        my $r=$TEMP[1];
        $r =~ s/^\///;
        my $disp=$r;
        $disp =~ s/\</\&lt\;/g;
        $disp =~ s/\>/\&gt\;/g;
        $TEMP[1] =~ s/([^a-zA-Z0-9\s])/\\$1/g;
        $line =~ s/$TEMP[1]/<a href=\"$httpstring\:\/\/$linkhost:$SERVER{port}\/$r\">$disp<\/a>/;
       }

        # make a link for CVE/CAN/CA/IN/BID/MS identifiers
        $line =~ s/((CVE|CAN)\-[0-9]{4}-[0-9]{4})/<a href=\"http\:\/\/icat\.nist\.gov\/icat\.cfm\?cvename=$1\">$1<\/a>/g;
        $line =~ s/(CA\-[0-9]{4}-[0-9]{2})/<a href=\"http\:\/\/www\.cert\.org\/advisories\/$1\.html\">$1<\/a>/g;
        $line =~ s/(BID\-[0-9]{4})/<a href=\"http\:\/\/www\.securityfocus\.com\/bid\/$1\">$1<\/a>/g;
        $line =~ s/(IN\-[0-9]{4}\-[0-9]{2})/<a href=\"http\:\/\/www\.cert\.org\/incident_notes\/$1\.html\">$1<\/a>/gi;
        $line =~ s/(MS[0-9]{2}\-[0-9]{3})/<a href=\"http\:\/\/www\.microsoft\.com\/technet\/security\/bulletin\/$1\.asp\">$1<\/a>/gi;
       }
     $line =~ s/^\- /<li>/;
     $line =~ s/^\+ /<li>/;
     print OUT "$line\n";
     }
    
   print OUT "</ul>\n"; 
   print OUT "<!-- generated by $NIKTO{name} v$NIKTO{version}\n     http://www.cirt.net/ -->\n";
   close(OUT);
   }
   
  }

 return;
}
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
  dprint("- Calling plugin:$PIFILE\n");
  $PIFILE =~ s/\.plugin$//;
  # just call it...hope it works...taint doesn't like this very much for obvious reasons
  &$PIFILE();
 }
return;
}
#################################################################################
# check_updates
#################################################################################
sub check_updates
{
 LW::http_init_request(\%request);
 my (%REMOTE, %LOCAL) = ();
 my ($pluginmsg, $remotemsg) = "";
 my $serverdir="/nikto";
 my $server="www.cirt.net";
 $request{'whisker'}->{'http_ver'}="1.1";
 $request{'whisker'}->{'port'}=80;
 $request{'whisker'}->{'anti_ids'}="";
 $request{'Host'}="www.cirt.net";
 
 # clear the -update to allow -u to work for 'useproxy'
for (my $i=0;$i<=$#ARGV;$i++) 
{
 if (($ARGV[$i] eq "-u") || ($ARGV[$i] eq "-useproxy"))
    { $SERVER{useproxy}=1; last; }
}
 
# check for proxy usage -u
 for (my $i=0;$i<=$#ARGV;$i++) { if ($ARGV[$i] eq "-u") { $SERVER{useproxy}=1; last; } }
 if (($CONFIG{PROXYHOST} ne "") && ($SERVER{useproxy}))
  {
   $request{'whisker'}->{'proxy_host'}=$CONFIG{PROXYHOST};
   $request{'whisker'}->{'proxy_port'}=$CONFIG{PROXYPORT};
   $request{'whisker'}->{'proxy_host'}=$CONFIG{PROXYHOST};
   if ($CONFIG{PROXYUSER} ne "") {
    LW::auth_set_header("proxy-basic",\%request,$CONFIG{PROXYUSER},$CONFIG{PROXYPASS});
    }
  }

 my  $ip=gethostbyname($server);
 if ($ip ne "") { $request{'whisker'}->{'host'}= inet_ntoa($ip); }
 else { $request{'whisker'}->{'host'}=$server; }

 # retrieve versions file
 LW::http_fixup_request(\%request);
 (my $RES, $CONTENT) = fetch("$serverdir/versions.txt","GET");
 if ($RES ne 200) { print "+ ERROR: Unable to to get $request{'whisker'}->{'host'}$serverdir/versions.txt\n"; exit; }

 # parse into an array
 my @CON=split(/\n/,$CONTENT);
 foreach my $line (@CON)
 { my @l=parse_csv($line);
  if ($line =~ /^msg/) { $remotemsg="$l[1]"; next; }
  $REMOTE{$l[0]}=$l[1]; 
 }
 
 # get local versions of plugins/dbs
 my @FILES=dirlist($NIKTO{plugindir},"(^nikto_|\.db\$)");

 foreach my $file (@FILES)
 {
  my $v="";
  open(LOCAL,"<$NIKTO{plugindir}/$file") || print "+ ERROR: Unable to open '$NIKTO{plugindir}/$file' for read: $@\n";
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
      print "+ No update has taken place. Please upgrade Nikto by visiting http://$server/\n"; 
      if ($remotemsg ne "") { print "$server set message: $remotemsg\n"; }
      exit; } 
    next; }

  if ($LOCAL{$remotefile} eq "")   # no local copy
   { if ($remotefile =~ /^nikto/) { push(@PITOGET,$remotefile); } else { push(@DBTOGET,$remotefile); } }
  elsif ($REMOTE{$remotefile} > $LOCAL{$remotefile})  # remote is newer
   { push(@DBTOGET,$remotefile); }
  elsif ($REMOTE{$remotefile} < $LOCAL{$remotefile})  # local is newer (!)
   { print "+ Local '$remotefile' (ver $LOCAL{$remotefile}) is NEWER than remote (ver $REMOTE{$remotefile}).\n";  } 
  
 }

 # replace local dbs if updated
 my $updates=0;
 foreach my $toget (@DBTOGET)
 {
  $updates++;
  print "+ Retrieving '$toget'\n";
  (my $RES, $CONTENT) = fetch("$serverdir/$toget","GET");
  if ($RES ne 200) { print "+ ERROR: Unable to to get $server$serverdir/$toget\n"; exit; }
  if ($CONTENT ne "") {
   open(OUT,">$NIKTO{plugindir}/$toget") || die print "+ ERROR: Unable to open '$NIKTO{plugindir}/$toget' for write: $@\n";
   print OUT $CONTENT;
   close(OUT); 
  }
 }

if ($updates eq 0)    { print "+ No updates required.\n"; }
if ($remotemsg ne "") { print "+ $server message: $remotemsg\n"; }
exit;
}
#################################################################################
# auth_check
# if the server requires authentication & we have it...
#################################################################################
sub auth_check
{
 my $REALM=$result{'www-authenticate'};
 $REALM =~ s/^Basic //i;
 $REALM =~ s/realm=//i;
 if ($REALM eq "") { $REALM="unnamed"; }
 
if (($result{'www-authenticate'} !~ /basic/i)  && ($result{'www-authenticate'} ne ""))# doh, not basic!
 {
  my $AUTHTYPE=$result{'www-authenticate'};
  $AUTHTYPE =~ s/ .*$//;
  fprint("+ ERROR: Host uses '$AUTHTYPE'\n");
  fprint("+ Continuing scan without authentication (just in case), but suppressing 401 messages.\n");
  $NIKTO{suppressauth}=1;
 }
elsif ($NIKTO{hostid} eq "")
 {
  fprint("+ ERROR: No auth credentials for $REALM, please set.\n");
  fprint("+ Continuing scan without authentication (just in case), but suppressing 401 messages.\n");
  $NIKTO{suppressauth}=1;
  return;
 }
else
 {
 vprint("- Attempting authorization to $REALM realm.\n");

 LW::auth_set_header("basic",\%request,$NIKTO{hostid},$NIKTO{hostpw});   # set auth
 LW::http_fixup_request(\%request);
 LW::http_do_request(\%request,\%result); # test auth

 if ($result{'www-authenticate'} ne "")
  {
   fprint("+ ERROR: Unable to authenticate to $REALM\n");
   fprint("+ Continuing scan without authentication (just in case), but suppressing 401 messages.\n");
   $NIKTO{suppressauth}=1;
  }
  else { fprint("- Successfully authenticated to realm $REALM.\n"); }
 }
 
return;
}
#################################################################################
# proxy_check
# test whether proxy requires authentication, and if we can use it
#################################################################################
sub proxy_check
{
 if ($PROXYCHECKED) { return; }
 if ($request{'whisker'}->{'proxy_host'} ne "")  # proxy is set up
 {
  LW::http_fixup_request(\%request);
  LW::http_do_request(\%request,\%result);
  if ($result{'proxy-authenticate'} ne "")       # proxy requires auth
  { 
   # have id/pw?
   if ($CONFIG{PROXYUSER} eq "") { fprint("+ Proxy set up requires authentication, please set.\n"); exit; }
   if ($result{'proxy-authenticate'} !~ /Basic/i)
    {
     my @pauthinfo=split(/ /,$result{'proxy-authenticate'});
     fprint("+ Proxy server uses '$pauthinfo[0]' rather than 'Basic' authentication. $NIKTO{name} $NIKTO{version} can't do that.\n");
     exit;
    }
   
   # test it...
   LW::auth_set_header("proxy-basic",\%request,$CONFIG{PROXYUSER},$CONFIG{PROXYPASS});   # set auth
   LW::http_fixup_request(\%request);
   LW::http_do_request(\%request,\%result);
   if ($result{'proxy-authenticate'} ne "") 
    { 
     my @pauthinfo=split(/ /,$result{'proxy-authenticate'});
     my @pauthinfo2=split(/=/,$result{'proxy-authenticate'});
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
 $PROXYCHECKED=1;
 return;
}
#################################################################################
# directory listing
# 'pattern' is an optional regex to match the file names against
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
 
 opendir(DIRECTORY,$DIR) || die print "+ ERROR: Can't open directory '$DIR': $@";
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
 my $ctr=0;
 
 print "-->\t$FILES{dbfile}\n";
 open(IN,"<$FILES{dbfile}") || die print "\tERROR: Unable to open '$FILES{dbfile}' for read: $@\n"; 
 @ENTRIES=<IN>; close(IN);

 foreach $line (@ENTRIES)
 {
  if ($line !~ /^c\,/) { next; }
  @L=parse_csv($line);
  if (($#L < 7) || ($#L > 8)) { print "Invalid syntax ($#L): $line"; next; }
  if (($L[2] =~ /^\@C/) && ($L[2] !~ /^\@CGIDIRS/)) { chomp($line); print "\tERROR: Possible \@CGIDIRS misspelling:$line\n"; }
  # build entry based on all except output message
  $ENTRIES{"$L[1],$L[2],$L[3],$L[4],$L[5]"}++;
  $ctr++;
 }

 foreach $entry (keys %ENTRIES) { if ($ENTRIES{$entry} > 1) { print "\tERROR: Duplicate ($ENTRIES{$entry}): $entry\n"; } }
 print "\t$ctr entries\n";


 # user_scan_database.db
 if (-e $FILES{userdbfile}) {
 print "--> $FILES{userdbfile}\n";
 %ENTRIES=();
 open(IN,"<$FILES{userdbfile}") || die print "\tERROR: Unable to open '$FILES{userdbfile}' for read: $@\n"; 
 @ENTRIES=<IN>; close(IN);
 
 $ctr=0;
 foreach $line (@ENTRIES)
 {
  if ($line !~ /^c\,/) { next; }
  @L=parse_csv($line);
  if (($#L < 7) || ($#L > 8)) { print "\tERROR: Invalid syntax ($#L): $line"; next; }
  if (($L[2] =~ /^\@C/) && ($L[2] !~ /^\@CGIDIRS/)) { chomp($line); print "\tERROR: Possible \@CGIDIRS misspelling:$line\n"; }
  # build entry based on all except output message
  $ENTRIES{"$L[1],$L[2],$L[3],$L[4],$L[5]"}++;
  $ctr++;
 }
 foreach $entry (keys %ENTRIES) { if ($ENTRIES{$entry} > 1) { print "\tERROR: Duplicate ($ENTRIES{$entry}): $entry\n"; } }
 print "\t$ctr entries\n";
 }

 # outdated.db
 $ctr=0;
 print "-->\t$NIKTO{plugindir}/outdated.db\n";
 %ENTRIES=();
 open(IN,"<$NIKTO{plugindir}/outdated.db") || die print "\tERROR: Unable to open '$NIKTO{plugindir}/outdated.db' for read: $@\n"; 
 @ENTRIES=<IN>; close(IN);

 foreach $line (@ENTRIES)
 {
  $line =~ s/^\s+//;
  if ($line =~ /^\#/) { next; }
  chomp($line);
  if ($line eq "") { next; }
  @L=parse_csv($line);
  if ($#L ne 2) { print "\tERROR: Invalid syntax ($#L): $line\n"; next; }
  $ENTRIES{"$L[0]"}++;
  $ctr++;
 }

 foreach $entry (keys %ENTRIES) { if ($ENTRIES{$entry} > 1) { print "\tERROR: Duplicate ($ENTRIES{$entry}): $entry\n"; } }
 print "\t$ctr entries\n";

 #server_msgs.db
 $ctr=0;
 print "-->\t$NIKTO{plugindir}/server_messages.db\n";
 %ENTRIES=();
 open(IN,"<$NIKTO{plugindir}/server_msgs.db") || die print "\tERROR: Unable to open '$NIKTO{plugindir}/server_msgs.db' for read: $@\n"; 
 @ENTRIES=<IN>; close(IN);

 foreach $line (@ENTRIES)
 {
  $line =~ s/^\s+//;
  if ($line =~ /^\#/) { next; }
  chomp($line);
  if ($line eq "") { next; }
  @L=parse_csv($line);
  if ($#L ne 1) { print "\tERROR: Invalid syntax ($#L): $line\n"; next; }
  $ENTRIES{"$L[0]"}++;
  $ctr++;
 }

 foreach $entry (keys %ENTRIES) { if ($ENTRIES{$entry} > 1) { print "\tERROR: Duplicate ($ENTRIES{$entry}): $entry\n"; } }
 print "\t$ctr entries\n";

 exit;
}
#######################################################################
# spit out all the details
#######################################################################
sub dump_result_hash
{
 dprint("- Result Hash:\n");
 foreach my $item (sort keys %result) {if ($item eq "whisker") { next; } dprint("- $item \t\t$result{$item}\n"); }
 foreach my $item (sort keys %{$result{'whisker'}}) { dprint("- \$whisker-\>$item \t$result{'whisker'}->{$item}\n"); }
}
#######################################################################
#######################################################################
# spit out all the details
#######################################################################
sub dump_request_hash
{
 dprint("- Request Hash:\n");
 foreach my $item (sort keys %request) { if ($item eq "whisker") { next; } dprint("- $item \t$request{$item}\n"); }
 foreach my $item (sort keys %{$request{'whisker'}}) { dprint("- $item \t$request{'whisker'}->{$item}\n"); }
}
#######################################################################
# check_responses
# check what the 200/404 messages are...
#######################################################################
sub check_responses
{
 # get NOT FOUND response (404)
 ($SERVER{notfound}, $CONTENT)=fetch("/$NIKTO{fingerprint}","GET");

 if (($SERVER{notfound} eq "400") || ($SERVER{notfound} eq "")) # may need to use HTTP/1.?
  {
   my $old=$request{'whisker'}->{'http_ver'};
   if ($request{'whisker'}->{'http_ver'} eq "1.1") { $request{'whisker'}->{'http_ver'}="1.0"; }
   else { $request{'whisker'}->{'http_ver'}="1.1"; }
   fprint("- Server did not understand HTTP $old, switching to HTTP $request{'whisker'}->{'http_ver'}\n");
   ($SERVER{notfound}, $CONTENT)=fetch("/$NIKTO{fingerprint}","GET");
  }

 if (($SERVER{notfound} ne "404") && ($SERVER{notfound} ne "401"))
 {
  fprint("+ Server does not respond with '404' for error messages (uses '$SERVER{notfound}').\n");
  fprint("+     This may increase false-positives.\n");
  if ($SERVER{notfound} eq "302") { fprint("+ Not found files redirect to: $result{'location'}\n"); }
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
  if ($SERVER{found} eq "302") 
   { 
    fprint("+ The root file (/) redirects to: $result{'location'}\n"); 
    # try to get redirected location to see if 200 is actually the valid response
    ($SERVER{found}, $CONTENT)=fetch($result{'location'},"GET");
    if ($SERVER{found} ne 200) # still no good... just a 302, stop going in circles
     {  $SERVER{found}=302; } 
    }
 }

 if ($SERVER{found} eq "401") { &auth_check; }
  
 # if they're the same, something is amiss... just pick a 404/200 scheme, nothing better to do
 if ($SERVER{notfound} eq $SERVER{found})
 { 
  if ($SERVER{notfound} ne "401") {
    fprint("+ The found & not found messages appear to be the same, be skeptical of positives.\n");
   }
  $SERVER{notfound}=404; $SERVER{found}=200; 
 }

return;
}
#######################################################################
# just get the banner, nothing major
# banner_get
#######################################################################
sub banner_get
{
 (my $TEMP, $CONTENT)=fetch("/","GET");
 $SERVER{servertype}=$result{'server'};
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

 #force all possible CGI directories to be "true" 
 if (!$SERVER{forcecgi}) 
 {
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
 elsif ($#CGIDIRS eq $#POSSIBLECGI)
  {
   fprint("+ All CGI directories 'found'--assuming invalid responses and using none (use -a to force check all possible dirs)\n"); 
   @CGIDIRS=();
  }
 else { @CGIDIRS=@POSSIBLECGI; }
 
 } # end !$SERVER{forcecgi}

 vprint("- Checking for CGI in: @CGIDIRS\n");
 return @CGIDIRS;
}
#######################################################################
# get a page
# fetch URI, METHOD
#######################################################################
sub fetch
{
 my $uri=$_[0] || return;
 &LW::http_reset;
 delete $result{'whisker'}->{'data'};
 if ($uri eq "//") { $uri="/"; } # trap for some weird ones
 $request{'whisker'}->{'method'} = $_[1] || "GET";
 $request{'whisker'}->{'uri'}    = $uri;
 if (($_[2] ne "") && ($_[2] ne " "))
  { my $x=$_[2]; 
    $x=~s/\\\"/\"/g; 
    $request{'whisker'}->{'data'} = $x; 
  }
  else { delete $request{'whisker'}->{'Content-Length'}; }
  
 $NIKTO{totalrequests}++;
 LW::http_fixup_request(\%request);
 $request{'whisker'}->{'uri_orig'}=$request{'whisker'}->{'uri'};  # for anti-ids encoding

 LW::http_do_request(\%request,\%result);
 &dump_result_hash;
 if (exists($result{'set-cookie'})) { push(@COOKIES,"/--=--$result{'set-cookie'}"); }
 $request{'whisker'}->{'data'}="";
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
# load the scan database
#######################################################################
sub load_scan_items
{
 open(IN,"<$FILES{dbfile}") || die print "+ ERROR: Unable to open '$FILES{dbfile}' for read: $@\n";
 @DBFILE=<IN>;
 close(IN); 

 # load a user database if it exists...
 if (-e $FILES{userdbfile})
  {
   open(IN,"<$FILES{userdbfile}") || die print "+ ERROR: Unable to open '$FILES{userdbfile}' for read: $@\n";
   my @DBFILE_USER=<IN>;
   close(IN); 
   # join them...
   foreach $line (@DBFILE_USER) { push(@DBFILE,$line); }
  }

 return;
}
#######################################################################
# set up the scan database
#######################################################################
sub set_scan_items
{
 my $shname=$SERVER{hostname} || $SERVER{ip};
 my ($line, $stype) = "";
 my (@item, @scat, $ROOTS, $FILES, $RESPS, $METHD, $INFOS, $DATAS) = ();
 $ITEMCOUNT=0;
  
 # first figure out server type
 foreach $line (@DBFILE)
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
 foreach $line (@DBFILE)
 {
  if ($line =~ /^c\,/i)  # check
  {
   chomp($line);
   @item=parse_csv($line);
   # if the right category or cat is generic...
   if (($SERVER{category} =~ /$item[1]/i) || ($item[1] =~ /generic/i) || ($SERVER{servertype} eq "") || ($SERVER{forcegen}))
   {
    # substitute for @IP, @HOSTNAME in check
    for (my $i=2;$i<=$#item;$i++)
     {
      chomp($item[$i]);
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

     }
   }
  }
 }

vprint("- Server category identified as '$SERVER{category}', if this is not correct please use -g to force a generic scan.\n");
vprint("- $ITEMCOUNT basic server checks\n");
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
 print "+ $_[1] - $INFOS{$_[0]} ($METHD{$_[0]})\n"; 
 push(@PRINT,"+ $_[1] - $INFOS{$_[0]} ($METHD{$_[0]})\n");
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
# print usage info
#######################################################################
sub usage
{
 fprint("$CLIOPTS");
 exit;
}
#######################################################################
#######################################################################


