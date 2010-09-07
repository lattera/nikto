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

# setup
$NIKTO{version}="1.22";
$NIKTO{name}="Nikto";
$DIV = "-" x 100;
my $STARTTIME=localtime();
&load_configs;
&find_plugins;
require "$NIKTO{plugindir}/nikto_core.plugin";

&general_config;

fprint("$DIV\n");
fprint("- $NIKTO{name} v$NIKTO{version}  - www.cirt.net - $STARTTIME\n");

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

#################################################################################
####                 Most functions moved to core.plugin                     ####
#################################################################################
# load config file
sub load_configs
{
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
return;
}

#################################################################################
# find plugins directory
sub find_plugins
{
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
return;
}
#################################################################################
