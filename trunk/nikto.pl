#!/usr/bin/perl
use strict;

#VERSION,2.1.2
use Getopt::Long;
Getopt::Long::Configure('no_ignore_case');

# use LW2;                   ### Change this line to use a different installed version

###############################################################################
#                               Nikto                                         #
# --------------------------------------------------------------------------- #
#   $Id$                             #
# --------------------------------------------------------------------------- #
###############################################################################
#  Copyright (C) 2001 CIRT, Inc.
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
# See the LICENSE.txt file for more information on the License Nikto is distributed under.
#
# This program is intended for use in an authorized manner only, and the author
# can not be held liable for anything done with this program, code, or items discovered
# with this program's use.
#######################################################################

# global var/definitions
use vars qw/$TEMPLATES %ERRSTRINGS %CLI %VARIABLES %TESTS $CONTENT/;
use vars qw/%NIKTO %REALMS %NIKTOCONFIG %request %result %COUNTERS/;
use vars qw/%db_extensions %FoF %UPDATES @DBFILE @BUILDITEMS/;
use vars qw/@RESULTS @PLUGINS @MARKS @REPORTS %CACHE %CONTENTSEARCH/;

# setup
my $starttime = localtime();
$NIKTO{'DIV'}     = "-" x 75;
$NIKTO{'version'} = "2.1.2";
$NIKTO{'name'}    = "Nikto";
$NIKTO{'configfile'} = "/etc/nikto.conf";    ### Change this line if it's having trouble finding it

# put a signal trap so we can close down reports properly
$SIG{'INT'} = \&safe_quit;

# read the --config option
{
    my %optcfg;
    Getopt::Long::Configure('pass_through', 'noauto_abbrev');
    GetOptions(\%optcfg, "config=s");
    Getopt::Long::Configure('nopass_through', 'auto_abbrev');
    if (defined $optcfg{'config'}) { $NIKTO{'configfile'} = $optcfg{'config'}; }
}

# Read the config files in order
my ($error, $home);
my $config_exists = 0;
$error = load_config("$NIKTO{'configfile'}");
$config_exists = 1 if ($error eq "");

# Guess home directory -- to support Windows
foreach my $var (split(/ /, "HOME USERPROFILE")) {
    $home = $ENV{$var} if ($ENV{$var});
}
$error         = load_config("$home/nikto.conf");
$config_exists = 1 if ($error eq "");
$error         = load_config("nikto.conf");
$config_exists = 1 if ($error eq "");

if ($config_exists == 0) {
    die "- Could not find a valid nikto config file\n";
}

setup_dirs();
require "$NIKTOCONFIG{'PLUGINDIR'}/nikto_core.plugin";
nprint("T:$starttime: Starting", "d");
require "$NIKTOCONFIG{'PLUGINDIR'}/nikto_single.plugin";
require "$NIKTOCONFIG{'PLUGINDIR'}/LW2.pm";

my ($a, $b) = split(/\./, $LW2::VERSION);
die("- You must use LW2 2.4 or later\n") if ($a != 2 || $b < 4);

general_config();
load_databases();
load_databases('u');
nprint("- $NIKTO{'name'} v$NIKTO{'version'}");

LW2::http_init_request(\%request);
$request{'whisker'}->{'ssl_save_info'}              = 1;
$request{'whisker'}->{'lowercase_incoming_headers'} = 1;
$request{'whisker'}->{'timeout'}                    = $CLI{'timeout'} || 10;
if (defined $CLI{'evasion'}) { $request{'whisker'}->{'encode_anti_ids'} = $CLI{'evasion'}; }
$request{'User-Agent'} = $NIKTO{'useragent'};
$request{'whisker'}->{'retry'} = 0;
proxy_setup();

nprint($NIKTO{'DIV'});

# No targets - quit while we're ahead
if ($CLI{'host'} eq "") {
    nprint("+ ERROR: No host specified");
    usage();
}

$NIKTO{'total_targets'} = $COUNTERS{'hosts_completed'} = 0;
load_plugins();

# Parse the supplied list of targets
my @MARKS = set_targets($CLI{'host'}, $CLI{'ports'}, $CLI{'ssl'}, $CLI{'root'});

# Now check each target is real and remove duplicates/fill in extra information
foreach my $mark (@MARKS) {
    $mark->{'test'} = 1;

    # Try to resolve the host
    ($mark->{'hostname'}, $mark->{'ip'}, $mark->{'display_name'}) = resolve($mark->{'ident'});

    # Skip if we can't resolve the host - we'll error later
    if (!defined $mark->{'ip'}) {
        $mark->{'test'} = 0;
        next;
    }

    # Check that the port is open
    my $open = port_check($mark->{'hostname'}, $mark->{'ip'}, $mark->{'port'});
    if (defined $CLI{'vhost'}) { $mark->{'vhost'} = $CLI{'vhost'} }
    if ($open == 0) {
        $mark->{'test'} = 0;
        next;
    }
    else {
	$NIKTO{'total_targets'}++;
	}
    $mark->{'ssl'} = $open - 1;
}

# Open reporting
report_head($CLI{'format'}, $CLI{'file'});

# Load db_tests
set_scan_items();

# Start hook to allow plugins to load databases etc
run_hooks("", "start");

# Now we've done the precursor, do the scan
foreach my $mark (@MARKS) {
    next unless ($mark->{'test'});
    $mark->{'start_time'} = time();

    # These should just be passed in the hash - but it's a lot of work to move to a local $request
    $request{'whisker'}->{'host'} = $mark->{'hostname'} || $mark->{'ip'};
    if (defined $CLI{'vhost'}) {
        $request{'Host'} = $CLI{'vhost'};
        $mark->{'vhost'} = $CLI{'vhost'};
    }
    $request{'whisker'}->{'port'}    = $mark->{'port'};
    $request{'whisker'}->{'ssl'}     = $mark->{'ssl'};
    $request{'whisker'}->{'version'} = $NIKTOCONFIG{'DEFAULTHTTPVER'};
    if (defined $NIKTOCONFIG{'STATIC-COOKIE'}) {
        $request{'Cookie'} = $NIKTOCONFIG{'STATIC-COOKIE'};
    }
    $mark->{'total_vulns'}  = 0;
    $mark->{'total_checks'} = 0;
    $mark->{'total_errors'} = 0;

    %FoF = ();

    nfetch($mark, "/", "GET", "", "", { nocache => 1, noprefetch => 1, nopostfetch => 1 },
           "getinfo");

    report_host_start($mark);
    if ($CLI{'findonly'}) {
        my $protocol = "http";
        if ($mark->{'ssl'}) { $protocol .= "s"; }
        if ($mark->{'banner'} eq "") {
            $mark->{'banner'} = "(no identification possible)";
        }
	add_vulnerability($mark, "Web server banner: " . $mark->{'banner'}, 0);
        nprint("+ Server: $protocol://$mark->{'display_name'}:$mark->{'port'}\t$mark->{'banner'}");
    }
    else {
        dump_target_info($mark);
        unless (defined $CLI{'nofof'}) { map_codes($mark) }
        run_hooks($mark, "recon");
        run_hooks($mark, "scan");
    }
    $mark->{'end_time'} = time();
    my $time    = date_disp($mark->{'end_time'});
    my $elapsed = $mark->{'end_time'} - $mark->{'start_time'};
    nprint(
        "+ $NIKTO{'total_checks'} items checked: $mark->{'total_errors'} error(s) and $mark->{'total_vulns'} item(s) reported on remote host"
        );
    nprint("+ End Time:           $time ($elapsed seconds)");
    nprint($NIKTO{'DIV'});

    $COUNTERS{'hosts_completed'}++;
    report_host_end($mark);
}
report_close();

nprint("+ $COUNTERS{'hosts_completed'} host(s) tested");
nprint("+ $NIKTO{'totalrequests'} requests made", "v");
send_updates();
nprint("T:" . localtime() . ": Ending", "d");

exit;

#################################################################################
####                Most code is now in nikto_core.plugin                    ####
#################################################################################
# load config file
# error=load_config(FILENAME)
sub load_config {
    my $configfile = $_[0];

    open(CONF, "<$configfile") || return "+ ERROR: Unable to open config file '$configfile'";
    my @CONFILE = <CONF>;
    close(CONF);

    foreach my $line (@CONFILE) {
        $line =~ s/\#.*$//;
        chomp($line);
        $line =~ s/\s+$//;
        $line =~ s/^\s+//;
        next if ($line eq "");
        my @temp = split(/=/, $line, 2);
        if ($temp[0] ne "") { $NIKTOCONFIG{ $temp[0] } = $temp[1]; }
    }

    # add CONFIG{'CLIOPTS'} to ARGV if defined...
    if (defined $NIKTOCONFIG{'CLIOPTS'}) {
        my @t = split(/ /, $NIKTOCONFIG{'CLIOPTS'});
        foreach my $c (@t) { push(@ARGV, $c); }
    }

    # Check for necessary config items
    check_config_defined("CHECKMETHODS", "HEAD");
    check_config_defined('@@MUTATE',     'dictionary;subdomain');
    check_config_defined('@@DEFAULT',    '@@ALL,-@@MUTATE');

    return "";
}
#################################################################################
# find plugins directory
sub setup_dirs {
    my $CURRENTDIR = $0;
    chomp($CURRENTDIR);
    $CURRENTDIR =~ s#[\\/]nikto.pl$##;

    # First assume we get it from NIKTOCONFIG
    unless (defined $NIKTOCONFIG{'EXECDIR'}) {
        if (-d "$ENV{'PWD'}/plugins") {
            $NIKTOCONFIG{'EXECDIR'} = $ENV{'PWD'};
        }
        elsif (-d "$CURRENTDIR/plugins") {
            $NIKTOCONFIG{'EXECDIR'} = $CURRENTDIR;
        }
        elsif (-d "./plugins") {
            $NIKTOCONFIG{'EXECDIR'} = $CURRENTDIR;
        }
        else {
            print STDERR "Could not work out the nikto EXECDIR, try setting it in nikto.conf";
            exit;
        }
    }
    unless (defined $NIKTOCONFIG{'PLUGINDIR'}) {
        $NIKTOCONFIG{'PLUGINDIR'} = "$NIKTOCONFIG{'EXECDIR'}/plugins";
    }
    unless (defined $NIKTOCONFIG{'TEMPLATEDIR'}) {
        $NIKTOCONFIG{'TEMPLATEDIR'} = "$NIKTOCONFIG{'EXECDIR'}/templates";
    }
    unless (defined $NIKTOCONFIG{'DOCUMENTDIR'}) {
        $NIKTOCONFIG{'DOCUMENTDIR'} = "$NIKTOCONFIG{'EXECDIR'}/docs";
    }
    return;
}

######################################################################
## check_config_defined(item, default)
## Checks whether config has been set, warns and sets to a default
sub check_config_defined {
    my $item    = $_[0];
    my $default = $_[1];

    if (!defined $NIKTOCONFIG{$item}) {
        print STDERR
          "- Warning: $item is not defined in Nikto configuration, setting to \"$default\"\n";
        $NIKTOCONFIG{$item} = $default;
    }
}
