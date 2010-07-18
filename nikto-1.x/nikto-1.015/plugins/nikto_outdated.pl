#VERSION,1.01 
#LASTMOD,01.06.2001  
# eval build parameters for web servers

# the stripping of letters from version numbers could be done better
# versions are loaded from the "outdated.db" file, which should be in the plugins directory
# we cheat, as apache is the main one that uses spaces for loaded modules... if there are others we'll have to hard code them

# This software is distributed under the terms of the GPL, which should have been received
# with a copy of this software in the "LICENSE.txt" file.

sub nikto_outdated
{
 my $VFILE="$NIKTO{plugindir}/outdated.db";
 my %VERSIONS=load_versions($VFILE);
 my @BUILDITEMS=();

 # populate @BUILDITEMS with appropriate values
 # if Apache, split on space...
 if ($SERVER{servertype} =~ /apache/i) 
   {
    @BUILDITEMS=split(/ /,$SERVER{servertype});
   }
 elsif ($SERVER{servertype} =~ /weblogic/i) # strip all the date info from weblogic...
   {
    my @T=split(/ /,$SERVER{servertype});
    push(@BUILDITEMS,"@T[0]\/@T[1]");
   }
 else
   {
    my $t="";
    if ($SERVER{servertype} !~ /\s/) { $t=$SERVER{servertype}; }                    # has no spaces
    elsif ($SERVER{servertype} =~ /\//) { $t=$SERVER{servertype}; $t =~ s/\s+//g; } # has spaces and / sepr
    else                                                                            # must create  sepr
     {
      # use the last non 0-9 . a-z char as a sepr (' ', '-', '_' etc)
      my $sepr=$SERVER{servertype};
      $sepr =~ s/[a-zA-Z0-9\.]//gi;
      $sepr=substr($sepr,(length($sepr)-1),1);
      $sepr=~ s/\s+/ /g;
      # break up ID string on $sepr
      my @T=split($SERVER{servertype},$sepr);
      # assume last is version...
      @T[$#T]="/@T[$#T]";
      $t=join(//,@T);
      $t=~s/\s+//g;
     }
   push(@BUILDITEMS,$t);
   dprint("Server Version String:$t\n");
   }

 my ($v, $V, $BI, $k) = "";

 foreach $BI (@BUILDITEMS)
  {
   foreach $V (sort keys %VERSIONS)
    {
     if ($BI =~ /$V/i)  # software name matched
      {
       foreach $k (keys %{ $VERSIONS{$V} }) { if ($k eq "") { next; } $v=$k; }
       if (vereval($v,$BI,$V))  # version check
        { 
         my $t = $v;
         my $msg = $VERSIONS{$V}{$v};
         $msg =~ s/RUNNING_VER/$BI/g;
         $msg =~ s/CURRENT_VER/$v/g;
         chomp($msg);
         fprint("+ $msg\n");
        }
      }
    }
  }
 return;
}

sub load_versions
{
 my @T=();
 my %VERS;
 my $F=$_[0] || return;
 open(VF,"<$F") || die fprint("Cannot open versions file '$F': $!\n");
 my @V=<VF>;
 close(VF);
 foreach my $line (@V)
 {
  chomp($line);
  if ($line =~ /^\#/) { next; }
  if ($line eq "") { next; }
  if ($line =~ /\#/) { $line=~s/\#.*$//; $line=~s/\s+$//; }
  my @T=parse_csv($line); 
  #    Match   Vers   Message
  $VERS{@T[0]}{@T[1]}=@T[2];
 }
return %VERS;
}

sub vereval
{
 # split both by last char of @_[0], as it is the name to version separator
 my @T=();
 my @C=();
 my $sepr=substr(@_[2],(length($sepr)-1),1);
 dprint("nikto_outdated.pl: verstring: @_[2], sepr:$sepr\n");

 @T=split(/$sepr/,@_[0]);
 my $C=@T[$#T]; # should be version...
 @T=split(/$sepr/,@_[1]);
 my $R=@T[$#T]; # should be version...

 # turn non version "numbers" into separators...
 $R =~ s/[^0-9\.\_\-]/ /g;
 $C =~ s/[^0-9\.\_\-]/ /g;
 $R =~ s/\s+$//;
 $C =~ s/\s+$//;
 $R =~ s/^\s+//;
 $C =~ s/^\s+//;
 $R =~ s/[^0-9\.]/\./;  # make seprs a dot again
 $C =~ s/[^0-9\.]/\./;  # make seprs a dot again

 my @CURRENT=split(/\./,$C); 
 my @RUNNING=split(/\./,$R);
 
 # start with 0... eval each in turn...
 for (my $i=0;$i<=$#CURRENT;$i++)
  {
   if (@CURRENT[$i] > @RUNNING[$i]) { return 1; }
   if ((@CURRENT[$i] ne "") && (@RUNNING[$i] eq "")) { return 1; }
  }

 return 0;
}

1;
