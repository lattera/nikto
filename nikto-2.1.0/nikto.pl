#!/usr/bin/perl
use strict;

#VERSION,2.1.0
use Getopt::Long;
Getopt::Long::Configure('no_ignore_case');

###############################################################################
#                               Nikto                                         #
# --------------------------------------------------------------------------- #
#   $Id$                             #   
# --------------------------------------------------------------------------- #
###############################################################################
#  Copyright (C) 2004-2008 CIRT, Inc.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; version 2
#  of the License only.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
# Contact Information:
#     Sullo (sullo@cirt.net)
#     http://cirt.net/
#######################################################################
# See the README.txt and/or help files for more information on how to use & config.
# See the LICENSE.txt file for more information on the License Nikto is distributed under.
#
# This program is intended for use in an authorized manner only, and the author
# can not be held liable for anything done with this program, code, or items discovered
# with this program's use.
#######################################################################

# global var/definitions
use vars qw/$TEMPLATES %ERRSTRINGS %CLI %VARIABLES %TESTS $CONTENT/;
use vars qw/%NIKTO %REALMS %NIKTOCONFIG %request %result %COUNTERS/;
use vars qw/%db_extensions %FoF %UPDATES $DIV @DBFILE @BUILDITEMS $PROXYCHECKED $http_eol/;
use vars qw/@RESULTS @PLUGINS @MARKS @REPORTS %CACHE/;

# setup
my $starttime      = localtime();
$DIV               = "-" x 75;
$NIKTO{version}    = "2.1.0";
$NIKTO{name}       = "Nikto";
$NIKTO{configfile} = "/etc/nikto.conf";    ### Change this line if your setup is having trouble finding it
$http_eol          = "\r\n";

# read the --config option
{
    my %optcfg;
    Getopt::Long::Configure('pass_through', 'noauto_abbrev');
    GetOptions(\%optcfg, "config=s");
    Getopt::Long::Configure('nopass_through', 'auto_abbrev');
    if (defined $optcfg{'config'}) { $NIKTO{configfile} = $optcfg{'config'}; }
}

# Read the config files in order
my $error;
my $config_exists=0;
$error=load_config("$NIKTO{configfile}");
$config_exists=1 if ($error eq "");
$error=load_config("$ENV{HOME}/nikto.conf");
$config_exists=1 if ($error eq "");
$error=load_config("nikto.conf");
$config_exists=1 if ($error eq "");

if ($config_exists==0)
{
   die "- Could not find a valid nikto config file\n";
}

setup_dirs();
require "$NIKTOCONFIG{PLUGINDIR}/nikto_core.plugin";
nprint("T:$starttime: Starting", "d");
require "$NIKTOCONFIG{PLUGINDIR}/nikto_single.plugin";
require "$NIKTOCONFIG{PLUGINDIR}/LW2.pm";

# use LW2;                   ### Change this line to use a different installed version

($a, $b) = split(/\./, $LW2::VERSION);
die("- You must use LW2 2.4 or later\n") if ($a != 2 || $b < 4);

general_config();
load_databases();
load_databases('u');
nprint("- $NIKTO{name} v$NIKTO{version}/$NIKTO{core_version}");

LW2::http_init_request(\%request);
$request{'whisker'}->{'ssl_save_info'}              = 1;
$request{'whisker'}->{'lowercase_incoming_headers'} = 1;
$request{'whisker'}->{'timeout'}                    = $CLI{timeout} || 10;
if (defined $CLI{evasion}) { $request{'whisker'}->{'encode_anti_ids'} = $CLI{evasion}; }
$request{'User-Agent'} = $NIKTO{useragent};
$request{'whisker'}->{'retry'} = 0;
proxy_setup();

nprint($DIV);

# No targets - quit while we're ahead
if ($CLI{host} eq "") 
{ 
   nprint("+ ERROR: No host specified");
   usage(); 
}

$PROXYCHECKED = 0;    # only do proxy_check once
$COUNTERS{hosts_total}=$COUNTERS{hosts_complete}=0;
load_plugins();

# Parse the supplied list of targets
my @MARKS=set_targets($CLI{host}, $CLI{ports}, $CLI{ssl}, $CLI{root});
# Now check each target is real and remove duplicates/fill in extra information
foreach my $mark (@MARKS)
{
   $mark->{test} = 1;
   # Try to resolve the host
   ($mark->{hostname}, $mark->{ip}, $mark->{display_name}) = resolve($mark->{ident});
   
   # Skip if we can't resolve the host - we'll error later
   if (!defined $mark->{ip})
   {
      $mark->{test} = 0;
      next;
   }

   # Check that the port is open
   my $open=port_check($mark->{ip}, $mark->{port});
   if ($open == 0) 
   {
      $mark->{test} = 0;
      next;
   }
   $mark->{ssl}=$open-1;
}

# Open reporting
report_head($CLI{format}, $CLI{file});

# Now we've done the precursor, do the scan
foreach my $mark (@MARKS)
{
   next unless ($mark->{test});
   $COUNTERS{hosts_total}++;
   $mark->{start_time} = time();
   # These should just be passed in the hash - but it's a lot of work to move to a local $request
   $request{whisker}->{host} = $mark->{hostname} || $mark->{ip};
   if (defined $CLI{vhost})
   {
      $request{Host} = $CLI{vhost};
      $mark->{vhost} = $CLI{vhost};
   }
   $request{'whisker'}->{'port'}    = $mark->{port};
   $request{'whisker'}->{'ssl'}     = $mark->{ssl};
   $request{'whisker'}->{'version'} = $NIKTOCONFIG{DEFAULTHTTPVER};
   if (defined $NIKTOCONFIG{'STATIC-COOKIE'}) { $request{'Cookie'} = $NIKTOCONFIG{'STATIC-COOKIE'}; }
   $mark->{total_vulns}=0;
   $mark->{total_checks}=0;
   
   %FoF = ();
   
   $mark->{banner}=get_banner($mark);
   report_host_start($mark);

   # put a signal trap so we can close down reports properly
   $SIG{'INT'} = sub
   {
      report_host_end($mark);
      report_close($mark);
      exit(1);
   };
   
   if ($CLI{findonly})
   {
      my $protocol="http";
      if ($mark->{ssl}) { $protocol .= "s"; }
      if ($mark->{banner} eq "")
      {
         $mark->{banner} = "(no identification possible)";
      }
      nprint("+ Server: $protocol://$mark->{display_name}:$mark->{port}\t$mark->{banner}");
   }
   else
   {
      dump_target_info($mark);
      set_scan_items($mark);
      unless (defined $CLI{nofof}) { map_codes() };
      run_plugins($mark);
   }
   $mark->{end_time} = time();
   my $time=date_disp($mark->{end_time});
   my $elapsed=$mark->{end_time}-$mark->{start_time};
   nprint("+ $mark->{total_checks} items checked: $mark->{total_vulns} item(s) reported on remote host");
   nprint("+ End Time:           $time ($elapsed seconds)");
   nprint("$DIV");
   
   $COUNTERS{hosts_completed}++;
   report_host_end($mark);
}
report_close();
   
nprint("+ $COUNTERS{hosts_total} host(s) tested");
nprint("+ $NIKTO{totalrequests} requests made","v");
send_updates();
nprint("T:" . localtime() . ": Ending", "d");

exit;

#################################################################################
####                Most code is now in nikto_core.plugin                    ####
#################################################################################
# load config file
# error=load_config(FILENAME)
sub load_config
{
   my $configfile=$_[0];

   open(CONF, "<$configfile") || return "- ERROR: Unable to open config file '$configfile'";
   my @CONFILE = <CONF>;
   close(CONF);

   foreach my $line (@CONFILE)
   {
      $line =~ s/\#.*$//;
      chomp($line);
      $line =~ s/\s+$//;
      $line =~ s/^\s+//;
      next if ($line eq "");
      my @temp = split(/=/, $line, 2);
      if ($temp[0] ne "") { $NIKTOCONFIG{ $temp[0] } = $temp[1]; }
   }

   # add CONFIG{CLIOPTS} to ARGV if defined...
   if (defined $NIKTOCONFIG{CLIOPTS})
   {
      my @t = split(/ /, $NIKTOCONFIG{CLIOPTS});
      foreach my $c (@t) { push(@ARGV, $c); }
   }

   # Check for necessary config items
   check_config_defined("CHECKMETHODS", "HEAD");

   return "";
}
#################################################################################
# find plugins directory
sub setup_dirs
{
   my $CURRENTDIR = $0;
   chomp($CURRENTDIR);
   $CURRENTDIR =~ s#[\\/]nikto.pl$##;

   # First assume we get it from NIKTOCONFIG
   unless (defined $NIKTOCONFIG{EXECDIR})
   {
      if (-d "$ENV{PWD}/plugins")
      {
         $NIKTOCONFIG{EXECDIR}=$ENV{PWD};
      }
      elsif (-d "$CURRENTDIR/plugins")
      {
         $NIKTOCONFIG{EXECDIR}=$CURRENTDIR;
      }
      elsif (-d "./plugins")
      {
         $NIKTOCONFIG{EXECDIR}=$CURRENTDIR;
      }
      else
      {
         print STDERR "Could not work out the nikto EXECDIR, try setting it in niktorc";
         exit;
      }
   }
   unless (defined $NIKTOCONFIG{PLUGINDIR})
   {
      $NIKTOCONFIG{PLUGINDIR}="$NIKTOCONFIG{EXECDIR}/plugins";
   }
   unless (defined $NIKTOCONFIG{TEMPLATEDIR})
   {
      $NIKTOCONFIG{TEMPLATEDIR}="$NIKTOCONFIG{EXECDIR}/templates";
   }
   unless (defined $NIKTOCONFIG{DOCUMENTDIR})
   {
      $NIKTOCONFIG{DOCUMENTDIR}="$NIKTOCONFIG{EXECDIR}/docs";
   }
   return;
}

######################################################################
## check_config_defined(item, default)
## Checks whether config has been set, warns and sets to a default
sub check_config_defined
{
   my $item=$_[0];
   my $default=$_[1];
 
   if (!defined $NIKTOCONFIG{$item})
   {
      print STDERR "- Warning: $item is not defined in Nikto configuration, setting to \"$default\"\n"; 
      $NIKTOCONFIG{$item}=$default;
   }
}
