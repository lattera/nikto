#!/usr/bin/perl
#VERSION,1.14
use Getopt::Long;
Getopt::Long::Configure('no_ignore_case');

# The LW require has been moved down about 40 lines...

#######################################################################
# last update: 05.22.2005
# --------------------------------------------------------------------#
#                               Nikto                                 #
# --------------------------------------------------------------------#
# Copyright (C) 2001-2005 Sullo/CIRT.net, except as noted
#
# This program code is licensed under the GNU General Public License. This license does
# not cover the database (".db") files, which are licensed individually, as described
# in beginning of each file.
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
use vars qw/@OPTS %CLI %VARIABLES $CONTENT $ITEMCOUNT @COOKIES %FILES $CURRENT_HOST_ID $CURRENT_PORT/;
use vars qw/%CONFIG %NIKTO %OUTPUT %METHD %RESPS %INFOS %SERVER %request %result %JAR %DATAS %COUNTERS/;
use vars qw/%CFG %UPDATES $DIV $VULS $OKTRAP $HOST %TARGETS @DBFILE @SERVERFILE @BUILDITEMS $PROXYCHECKED/;

# setup
$NIKTO{version}="1.35";
$NIKTO{name}="Nikto";
$CFG{configfile}="config.txt";

# read the --config option
{
 my %optcfg;
 Getopt::Long::Configure('pass_through', 'noauto_abbrev');
 GetOptions(\%optcfg, "config=s");
 Getopt::Long::Configure('nopass_through', 'auto_abbrev');
 if (defined $optcfg{'config'})
  {
   $CFG{configfile} = $optcfg{'config'};
  }
}

$DIV = "-" x 75;
my $STARTTIME=localtime();
load_configs();
find_plugins();
require "$NIKTO{plugindir}/nikto_core.plugin";
require "$NIKTO{plugindir}/LW.pm";
# use LW;

general_config();

LW::http_init_request(\%request);
$request{'whisker'}->{'lowercase_incoming_headers'}=1;
$request{'whisker'}->{'timeout'}=$CLI{timeout} || 10;
$request{'whisker'}->{'anti_ids'}=$CLI{evasion};
$request{'User-Agent'} = $NIKTO{useragent};
$request{'Host'} = $CLI{vhost} unless $CLI{vhost} eq "";
proxy_setup();

open_output();
nprint($DIV);
print "- $NIKTO{name} $NIKTO{version}/$NIKTO{core_version}     -     www.cirt.net\n";

set_targets();
load_scan_items();
$PROXYCHECKED=0; # only do proxy_check once

# actual scan for each host/port
foreach $CURRENT_HOST_ID (sort { $a<=>$b } keys %TARGETS)
 {
  $COUNTERS{hosts_completed}++;
  if (($CLI{findonly}) && ($COUNTERS{hosts_completed} % 10) eq 0) { nprint("($COUNTERS{hosts_completed} of $COUNTERS{hosts_total})"); }
  host_config();
  $request{'whisker'}->{'host'} = $TARGETS{$CURRENT_HOST_ID}{hostname} || $TARGETS{$CURRENT_HOST_ID}{ip};

  foreach $CURRENT_PORT ( keys %{$TARGETS{$CURRENT_HOST_ID}{ports}} )
   {
    if ($CURRENT_PORT eq "") { next; }
    $request{'whisker'}->{'port'}=$CURRENT_PORT;
    $request{'whisker'}->{'ssl'}=$TARGETS{$CURRENT_HOST_ID}{ports}{$CURRENT_PORT}{ssl};
    $request{'whisker'}->{'http_ver'}=$CONFIG{DEFAULTHTTPVER};
    if ($CONFIG{'STATIC-COOKIE'} ne "") { $request{'Cookie'} = $CONFIG{'STATIC-COOKIE'}; }

    get_banner();

    if ($CLI{findonly}) 
    { 
     my $protocol="http";
     if ($TARGETS{$CURRENT_HOST_ID}{ports}{$CURRENT_PORT}{banner} eq "") { $TARGETS{$CURRENT_HOST_ID}{ports}{$CURRENT_PORT}{banner}="(no identification possible)"; }
     if ($TARGETS{$CURRENT_HOST_ID}{ports}{$CURRENT_PORT}{ssl}) { $protocol .= "s"; }
     nprint("+ Server: $protocol://$TARGETS{$CURRENT_HOST_ID}{display_name}:$CURRENT_PORT\t$TARGETS{$CURRENT_HOST_ID}{ports}{$CURRENT_PORT}{banner}");
     next;
    }

    $VULS=0;
    dump_target_info();
    check_responses();
    check_cgi();
    set_scan_items();
    run_plugins();
    test_target();
   }
 }

nprint("+ $COUNTERS{hosts_total} host(s) tested");

send_updates();
close_output();
exit;

#################################################################################
####                  Most subs in nikto_core.plugin                         ####
#################################################################################
# load config file
sub load_configs
{
 open(CONF,"<$CFG{configfile}") || print STDERR "- ERROR: Unable to open config file '$CFG{configfile}' ($!), only 1 CGI directory defined.\n";
 my @CONFILE=<CONF>;
 close(CONF);

 foreach my $line (@CONFILE)
 {
  $line =~ s/\#.*$//;
  chomp($line);
  $line =~ s/\s+$//;
  $line =~ s/^\s+//;
  if ($line eq "") { next; }
  my @temp=split(/=/,$line,2);
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
   print STDERR "I can't find 'plugins' directory. I looked around:\n";
   print STDERR "\t$CONFIG{PLUGINDIR}\n\t$ENV{PWD}\n\t$ENV{_}\n";
   print STDERR "Try: switch to the 'nikto' base dir, or\n";
   print STDERR "Try: set PLUGINDIR in config.txt\n";
   exit;
  }
 $NIKTOFILES{dbfile}="$NIKTO{plugindir}/scan_database.db";
 $NIKTOFILES{userdbfile}="$NIKTO{plugindir}/user_scan_database.db"; 
 $NIKTOFILES{serverdbfile}="$NIKTO{plugindir}/servers.db"; 
return;
}
#################################################################################
