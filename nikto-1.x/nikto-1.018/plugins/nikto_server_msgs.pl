#VERSION,1.01 
#LASTMOD,01.06.2001  

# versions are loaded from the "server_msgs.db" file, which should be in the plugins directory

# this plugin checks the server version to see if there are any version specific items in the4 server_msgs.db
# this differs from nikto_outdated because that is ONLY checking to see if it is an old version, whereas this
# checks to see if the versions match

# This software is distributed under the terms of the GPL, which should have been received
# with a copy of this software in the "LICENSE.txt" file.

sub nikto_server_msgs
{
 my %VERSIONS;
 %VERSIONS=load_versions("$NIKTO{plugindir}/server_msgs.db");

 foreach my $VER (keys %VERSIONS)
  {
   if ($SERVER{servertype} =~ /($VER)/i)  { fprint("+ $1 - $VERSIONS{$VER}\n");  } 
  }

 return;
}

sub load_versions
{
 my %VERS;
 my $VFILE=$_[0]; 
 open(IN,"<$VFILE") || die fprint("Can't open $VFILE:$!\n");
 my @file=<IN>;
 close(IN);
 foreach my $line (@file)
 {
  if ($line =~ /^\#/) { next; } # comment
  if ($line =~ /\#/) { $line=~s/\#.*$//; $line=~s/\s+$//; }
  if ($line eq "") { next; }
  my @t=parse_csv($line);
  $VERS{@t[0]}=@t[1];
  dprint("Loaded:@t[0] -- @t[1]\n");
 }
return %VERS;

}

1;
