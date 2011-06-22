#!/bin/perl
# Compare all the versions loaded from file and print out the latest.

my $infile = $ARGV[0] || die print "$0 <infile>\n";
my ($COMPONENTS, $RESULTS) = {};

open(IN,"<$infile") || die print "Error opening $infile: $!\n";
my @INDATA=<IN>;
close(IN);

# load into hash
foreach my $line (@INDATA) { 
	chomp($line);
	# skip any w/o numbers
	if ($line !~ /[0-9]/) { next; }
	$RAW{$line}=1;
	}
	
get_items();
find_latest();

foreach my $item (sort keys %RESULTS) { print "$item,$RESULTS{$item}\n"; }

###########################
sub find_latest { 
	foreach my $item (keys %COMPONENTS) { 
		$item =~ s/\([^\)]+\)//;
		$item =~ s/\(.*$//;
		if ($item !~ /[0-9]/) { next; }
		my @bits = split(/\//, $item);
		if (!exists($RESULTS{$bits[0]})) { $RESULTS{$bits[0]}=$bits[1]; next; }
		my $r = vereval($bits[1], $RESULTS{$bits[0]});
	#	print "$bits[0]\tchallenger $bits[1] vs incumbent: $RESULTS{$bits[0]}\t";
	#	if ($r eq 2) { print "tie\n"; }
	#	elsif ($r eq 1) { print "Challenger wins\n"; }
	#	elsif ($r eq 0) { print "Incumbent wins\n"; }
		next if $r eq 2;
		next if $r eq 0;
		if ($r eq 1) { 
			$RESULTS{$bits[0]}=$bits[1];
			}
		}
	}
	
sub get_items {	
	foreach my $item (keys %RAW) { 
		my $MATCHSTRING='';
    	# if Apache, split on space...
	    if ($item =~ /apache/i) {
        	foreach my $i (split(/ /, $item)) {
            	$COMPONENTS{$item} = 1;
        		}
    		}
    	elsif ($item =~ /weblogic/i)    # strip all the date info...
    		{
        		my @T = split(/ /, $item);
        		$COMPONENTS{ $T[0] . '\/' . $T[1] } = 1;
    		}
    	elsif ($item =~ /sitescope/i)    # strip all the date info...
    		{
        		my @T = split(/ /, $item);
        		$COMPONENTS{ $T[0] } = 1;
		    }
    	else {
        	if ($item !~ /\s/)           # has no spaces
        		{
            		$MATCHSTRING = $item;
        		}
        	elsif ($item =~ /\//)        # has spaces and / sepr
        		{
            		$MATCHSTRING = $item;
            		$MATCHSTRING =~ s/\s+//g;
        		}
        	else        # must create  sepr
        		{
            		# use the last non 0-9 . a-z char as a sepr (' ', '-', '_' etc)
            		my $sepr = $item;
            		$sepr =~ s/[a-zA-Z0-9\.\(\)]//gi;
		            $sepr = substr($sepr, (length($sepr) - 1), 1);
		            # break up ID string on $sepr
        		    my @T = split(/$sepr/, $item);

		            # assume last is version...
        		    for ($i = 0 ; $i < $#T ; $i++) { $MATCHSTRING .= "$T[$i] "; }
        		}
        	$MATCHSTRING =~ s/\s+$//;
        	$COMPONENTS{$MATCHSTRING} = 1;
    		}
	}
}

sub vereval {

    # split both by last char of @_[0], as it is the name to version separator

    my $CHALLENGER      = lc($_[0]);
    my $INCUMBENT      = lc($_[1]);
    my $CHALLENGER_ORIG = $CHALLENGER;
    my $INCUMBENT_ORIG = $INCUMBENT;
    my $mark         = $_[3];

    # convert alphas to numerics so we can do a real comparison
    $CHALLENGER =~ s/([^0-9\.]){1}/"." . ord($1) . "."/eg;
    $INCUMBENT =~ s/([^0-9\.]){1}/"." . ord($1) . "."/eg;
    $INCUMBENT =~ s/\.+/\./g;
    $CHALLENGER =~ s/\.+/\./g;
    $INCUMBENT =~ s/^\.//;
    $CHALLENGER =~ s/^\.//;
    $INCUMBENT =~ s/\.$//;
    $CHALLENGER =~ s/\.$//;
    
 #   print "c:$CHALLENGER\ti:$INCUMBENT\n";

    if (($CHALLENGER !~ /[a-z]/) && ($INCUMBENT !~ /[a-z]/)) {
        @CHAL = split(/\./, $CHALLENGER);
        @INC = split(/\./, $INCUMBENT);
    }
    else {
        @CHAL = split(//, $CHALLENGER);
        @INC = split(//, $INCUMBENT);
    }

    # start with 0... eval each in turn...
    for (my $i = 0 ; $i <= $#CHAL ; $i++) {
#       print "major compare: \$CHAL[$i]:$CHAL[$i]: \$INC[$i]:$INC[$i]\n";
        if ($CHAL[$i] > $INC[$i]) { return 1; }    # INCUMBENT is older
        if (($CHAL[$i] ne "") && ($INC[$i] eq "")) { return 1; }    # INCUMBENT is older
        if ($CHAL[$i] < $INC[$i])                                   # INCUMBENT is newer
        {
            return 0;
        }
    }
    return 2;    # INCUMBENT is the same version if we make it here
}
