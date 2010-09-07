# libwhisker v1.6
# libwhisker is a collection of routines used by whisker
#
# libwhisker copyright 2000,2001,2002 rfp.labs
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
#
# More information can be found at http://www.wiretrip.net/rfp/
# Libwhisker mailing list and resources are also available at
# http://sourceforge.net/projects/whisker/
#

package LW;
use 5.004;
$LW::VERSION="1.6";

####### external module tests ###################################

BEGIN {

## LW module manager stuff ##

	%LW::available		= ();
	$LW::LW_HAS_SOCKET	= 0;
	$LW::LW_HAS_SSL		= 0;
	$LW::LW_SSL_LIB		= 0;
	$LW::LW_NONBLOCK_CONNECT= 0;

## binary helper - may contain functions substituted further down ##
        eval "use LW::bin"; # do we have libwhisker binary helpers?
        if($@){ $LW::available{'LW::bin'}=$LW::bin::VERSION; }

## encode subpackage ##
	eval "require MIME::Base64";
	if($@){
        	*encode_base64 = \&encode_base64_perl; 
	        *decode_base64 = \&decode_base64_perl; 
	} else{ 
		# MIME::Base64 typically has faster C versions
		$LW::available{'mime::base64'}=$MIME::Base64::VERSION;
        	*encode_base64 = \&MIME::Base64::encode_base64;
        	*decode_base64 = \&MIME::Base64::decode_base64;}

## md5 subpackage ##
	eval "require MD5";
	if(!$@){ $LW::available{'md5'}=$MD5::VERSION;}

## http subpackage ##
        eval "use Socket"; # do we have socket support?
        if($@){ $LW::LW_HAS_SOCKET=0; }
        else { $LW::LW_HAS_SOCKET=1;
                $LW::available{'socket'}=$Socket::VERSION;}

    if($LW_HAS_SOCKET){
	eval "use Net::SSLeay"; # do we have SSL support?
        if($@){ $LW::LW_HAS_SSL=0; }
        else { $LW::LW_HAS_SSL=1;
                $LW::LW_SSL_LIB=1;
                $LW::available{'net::ssleay'}=$Net::SSLeay::VERSION;
                Net::SSLeay::load_error_strings();
                Net::SSLeay::SSLeay_add_ssl_algorithms();
                Net::SSLeay::randomize();}
        if(!$LW::LW_HAS_SSL){
                eval "use Net::SSL"; # different SSL lib
                if($@){ $LW::LW_HAS_SSL=0; }
                else { $LW::LW_HAS_SSL=1;
                        $LW::LW_SSL_LIB=2;
                        $LW::available{'net::ssl'}=$Net::SSL::VERSION;}
        }

## non-blocking IO ##

	if($^O!~/Win32/){
		eval "use POSIX qw(:errno_h :fcntl_h)"; # better
		if(!$@){
			$LW::LW_NONBLOCK_CONNECT=1;
		}
	}

    } # if($LW_HAS_SOCKET)

} # BEGIN

####### package variables #######################################

## crawl subpackage ##
	%LW::crawl_config=(	'save_cookies'	=> 0,
				'reuse_cookies'	=> 1,
				'save_offsites'	=> 0,
				'follow_moves'	=> 1,
				'url_limit'	=> 1000,
				'use_params'	=> 0,
				'params_double_record' => 0,
				'skip_ext'	=> '.gif .jpg .gz .mp3 .swf .zip ',
				'save_skipped'	=> 0,
				'save_referrers'=> 0,
				'do_head'	=> 0,
				'callback'	=> 0,
				'slashdot_bug'	=> 1,
				'normalize_uri'	=> 1,
				'source_callback' => 0
			);


	@LW::crawl_urls=();;
	%LW::crawl_server_tags=();
	%LW::crawl_referrers=();
	%LW::crawl_offsites=();
	%LW::crawl_cookies=();
	%LW::crawl_forms=();
	%LW::crawl_temp=();

	# this idea/structure was taken from HTML::LinkExtor.pm,
	# copyright 2000 Gisle Aas and Michael A. Chase
	%LW::crawl_linktags = (
		 'a'       => 'href',
		 'applet'  => [qw(codebase archive code)],
		 'area'    => 'href',
		 'base'    => 'href',
		 'bgsound' => 'src',
		 'blockquote' => 'cite',
		 'body'    => 'background',
		 'del'     => 'cite',
		 'embed'   => [qw(src pluginspage)],
		 'form'    => 'action',
		 'frame'   => [qw(src longdesc)],
		 'iframe'  => [qw(src longdesc)],
		 'ilayer'  => 'background',
		 'img'     => [qw(src lowsrc longdesc usemap)],
		 'input'   => [qw(src usemap)],
		 'ins'     => 'cite',
		 'isindex' => 'action',
		 'head'    => 'profile',
		 'layer'   => [qw(background src)],
		 'link'    => 'href',
		 'object'  => [qw(codebase data archive usemap)],
		 'q'       => 'cite',
		 'script'  => 'src',
		 'table'   => 'background',
		 'td'      => 'background',
		 'th'      => 'background',
		 'xmp'     => 'href',
	);


## forms subpackage ##
	@LW::forms_found=();
	%LW::forms_current=();


## http subpackage ##
	my $SOCKSTATE=0;
	my $TIMEOUT=10; # default
	my ($STATS_REQS,$STATS_SYNS)=(0,0);
	my ($LAST_HOST,$LAST_INET_ATON,$LAST_SSL)=('','',0);
	my ($OUTGOING_QUEUE,$INCOMING_QUEUE)=('','');
	my ($SSL_CTX, $SSL_THINGY);

	my %http_host_cache=();
	# order is following:
	# [0] - SOCKET
	# [1] - $SOCKSTATE
	# [2] - INET_ATON
	# [3] - $SSL_CTX
	# [4] - $SSL_THINGY
	# [5] - $OUTGOING_QUEUE
	# [6] - $INCOMING_QUEUE
	# [7] - $STATS_SYNS
	# [8] - $STATS_REQS

	my $Z; # array ref to current host specs





sub anti_ids {
	my ($rhin,$modes)=(shift,shift);
	my (@T,$x,$c,$s,$y);
	my $ENCODED=0;
	my $W = $$rhin{'whisker'};

	return if(!(defined $rhin && ref($rhin)));

	# in case they didn't do it already
	$$rhin{'whisker'}->{'uri_orig'}=$$rhin{'whisker'}->{'uri'};

	# note: order is important!

	# mode 9 - session splicing
	if($modes=~/9/){
		$$rhin{'whisker'}->{'ids_session_splice'}=1;
	}

	# mode 4 - prepend long random string
	if($modes=~/4/){$s='';
		if($$W{'uri'}=~m#^/#){
			$y=&utils_randstr;
			$s.=$y while(length($s)<512);
			$$W{'uri'}="/$s/..".$$W{'uri'};
		}
	}

	# mode 7  - (windows) random case sensitivity
	if($modes=~/7/){ 
		@T=split(//,$$W{'uri'});
		for($x=0;$x<(scalar @T);$x++){
			if((rand()*2)%2 == 1){
				$T[$x]=uc($T[$x]);}}
		$$W{'uri'}=join('',@T);
	}

	# mode 2 - directory self-reference (/./)
	if($modes=~/2/){
		$$W{'uri'}=~s#/#/./#g;
	}


	# mode 8 - windows directory separator (\)
	if($modes=~/8/){
		$$W{'uri'}=~s#/#\\#g;
		$$W{'uri'}=~s#^\\#/#;
		$$W{'uri'}=~s#^(http|file|ftp|nntp|news|telnet):\\#$1://#;
		$$W{'uri'}=~s#\\$#/#;
	}

	# mode 1 - random URI (non-UTF8) encoding
	if($modes=~/1/){
		if($ENCODED==0){
			$$W{'uri'}=encode_str2ruri($$W{'uri'});
		$ENCODED=1;}
	}	


	# mode 5 - fake parameter
	if($modes=~/5/){ 
		($s,$y)=(&utils_randstr,&utils_randstr); 
		$$W{'uri'}="/$s.html%3f$y=/../$$W{'uri'}";
	}

	# mode 3 - premature URL ending
	if($modes=~/3/){ 
		$s=&utils_randstr;
		$$W{'uri'}="/%20HTTP/1.1%0D%0A%Accept%3A%20$s/../..$$W{'uri'}";
	}
	
	# mode 6 - TAB as request spacer
	if($modes=~/6/){
		$$W{'req_spacer'}="\t";
	}	

} # end anti_ids







sub auth_brute_force {
 my ($auth_method, $hrin, $user, $pwordref, $dom)=@_;
 my ($P,%hout);

 return undef if(!defined $auth_method || length($auth_method)==0);
 return undef if(!defined $user        || length($user)       ==0);
 return undef if(!(defined $hrin     && ref($hrin)    ));
 return undef if(!(defined $pwordref && ref($pwordref)));

 map {
    ($P=$_)=~tr/\r\n//d;
    auth_set_header($auth_method,$hrin,$user,$P,$dom);
    return undef if(http_do_request($hrin,\%hout));
    return $P if($hout{'whisker'}->{'http_resp'} ne 401);
 } @$pwordref;

 return undef;}




sub auth_set_header {
 my ($method, $href, $user, $pass, $domain)=(lc(shift),@_);

 return if(!(defined $href && ref($href)));
 return if(!defined $user || !defined $pass);

 if($method eq 'basic'){
	$$href{'Authorization'}='Basic '.encode_base64($user.':'.$pass,'');
 }

 if($method eq 'proxy-basic'){
	$$href{'Proxy-Authorization'}='Basic '.encode_base64($user.':'.$pass,'');
 }

 if($method eq 'ntlm'){
	my $o=ntlm_new($user,$pass,$domain);
	$$href{'whisker'}->{'ntlm_obj'}=$o;
	$$href{'whisker'}->{'ntlm_step'}=0;
	$$href{'Authorization'}='NTLM '.ntlm_client($o);
 }

}




sub do_auth {
	goto &auth_set_header;
}



sub bruteurl {
 my ($hin, $upre, $upost, $arin, $arout)=@_;
 my ($U,%hout);

 return if(!(defined $hin   && ref($hin)  ));
 return if(!(defined $arin  && ref($arin) ));
 return if(!(defined $arout && ref($arout)));
 return if(!defined $upre  || length($upre) ==0);
 return if(!defined $upost || length($upost)==0);

 http_fixup_request($hin);

 map {
  ($U=$_)=~tr/\r\n//d; next if($U eq '');
  if(!http_do_request($hin,\%hout,{'uri'=>$upre.$U.$upost})){
    if(	$hout{'whisker'}->{'http_resp'}==200 ||
	$hout{'whisker'}->{'http_resp'}==403){
	push(@{$arout},$U);
    }
  }
 } @$arin;
}





sub cookie_read {
 my ($count,$jarref,$href)=(0,@_);

 return 0 if(!(defined $jarref && ref($jarref)));
 return 0 if(!(defined $href   && ref($href)  ));

 my $lc = $$href{'whisker'}->{'lowercase_incoming_headers'}||0;
 my $target = $lc ? 'set-cookie' : 'Set-Cookie';

 if(!defined $$href{$target}){
	return 0;}

 if(ref($$href{$target})){ # multiple headers
	foreach ($$href{$target}){
		cookie_parse($jarref,$_);
		$count++; }
 } else { # single header
	cookie_parse($jarref,$$href{$target});
	$count=1; }

 return $count;
}




sub cookie_parse {
 my ($jarref, $header)=@_;
 my ($del,$part,@parts,@construct,$cookie_name)=(0);

 return if(!(defined $jarref && ref($jarref)));
 return if(!(defined $header && length($header)>0));

 @parts=split(/;/,$header);

 foreach $part (@parts){
	if($part=~/^[ \t]*(.+?)=(.*)$/){
		my ($name,$val)=($1,$2);
		if($name=~/^domain$/i){		
			$val=~s#^http://##;
			$val=~s#/.*$##;
			$construct[1]=$val;
		} elsif($name=~/^path$/i){
			$val=~s#/$## if($val ne '/');
			$construct[2]=$val;
		} elsif($name=~/^expires$/i){
			$construct[3]=$val;
		} else {
			$cookie_name=$name;
			if($val eq ''){		$del=1;
			} else {		$construct[0]=$val;}
		}	
	} else {
		if($part=~/secure/){
			$construct[4]=1;}
 }	}

 if($del){
  	delete $$jarref{$cookie_name} if defined $$jarref{$cookie_name};
 } else {
	$$jarref{$cookie_name}=\@construct;
 }
}




sub cookie_write {
 my ($jarref, $hin, $override)=@_;
 my ($name,$out)=('','');

 return if(!(defined $jarref && ref($jarref)));
 return if(!(defined $hin    && ref($hin)   ));

 $override=$override||0;
 $$hin{'whisker'}->{'ssl'}=$$hin{'whisker'}->{'ssl'}||0;

 foreach $name (keys %$jarref){
	next if($name eq '');
	next if($$hin{'whisker'}->{'ssl'}==0 && $$jarref{$name}->[4]>0);
	if($override || 
          ($$hin{'whisker'}->{'host'}=~/$$jarref{$name}->[1]$/i &&
	   $$hin{'whisker'}->{'uri'}=~/$$jarref{$name}->[2]/i)){
		$out.="$name=$$jarref{$name}->[0];";
 }	}

 if($out ne ''){ $$hin{'Cookie'}=$out; }

}




sub cookie_get {
 my ($jarref,$name)=@_;

 return undef if(!(defined $jarref && ref($jarref)));

 if(defined $$jarref{$name}){
	return @{$$jarref{$name}};}

 return undef;
}




sub cookie_set {
 my ($jarref,$name,$value,$domain,$path,$expire,$secure)=@_;
 my @construct;

 return if(!(defined $jarref && ref($jarref)));

 return if($name eq '');
 if($value eq ''){
	delete $$jarref{$name};
	return;}
 $path=$path||'/';
 $secure=$secure||0;

 @construct=($value,$domain,$path,$expire,$secure);
 $$jarref{$name}=\@construct; 
}







sub crawl {
 my ($START, $MAX_DEPTH, $hrtrack, $hrin)=@_;
 my (%hout, %jar);
 my ($T, @ST, @links, @tlinks, @vals, @ERRORS)=('');

 return if(!(defined $hrtrack && ref($hrtrack)));
 return if(!(defined $hrin    && ref($hrin)   )); 
 return if(!defined $START || length($START)==0);

 $MAX_DEPTH||=2;

 # $ST[0]=HOST  $ST[1]=URL  $ST[2]=CWD  $ST[3]=HTTPS  $ST[4]=SERVER
 # $ST[5]=PORT  $ST[6]=DEPTH

 @vals=utils_split_uri($START);
 $ST[1]=$vals[0]; 	# uri
 $ST[0]=$vals[2]; 	# host
 $ST[5]=$vals[3]; 	# port
 $ST[4]=undef;		# server tag

 return if($ST[0] eq '');

 # some various informationz...
 $LW::crawl_config{'host'}=$ST[0];
 $LW::crawl_config{'port'}=$ST[5];
 $LW::crawl_config{'start'}=$ST[1];

 $$hrin{'whisker'}->{'host'}=$ST[0];
 $$hrin{'whisker'}->{'port'}=$ST[5];
 $$hrin{'whisker'}->{'lowercase_incoming_headers'}=1; # makes life easier

 http_fixup_request($hrin);

 # this is so callbacks can access internals via references
 $LW::crawl_config{'ref_links'}=\@links;
 $LW::crawl_config{'ref_jar'}=\%jar;
 $LW::crawl_config{'ref_hin'}=$hrin;
 $LW::crawl_config{'ref_hout'}=\%hout;

 %LW::crawl_referrers=(); # empty out existing referrers
 %LW::crawl_server_tags=();
 %LW::crawl_offsites=();
 %LW::crawl_cookies=();
 %LW::crawl_forms=();

 push @links, \@{[$ST[1],1,($vals[1] eq 'https')?1:0]};

 while(@links){
  my $C=shift @links;
  $ST[1]=$C->[0]; # url
  $ST[6]=$C->[1]; # depth
  $ST[3]=$C->[2]; # https

  next if(defined $$hrtrack{$ST[1]} && $$hrtrack{$ST[1]} ne '?');

  if($ST[6] > $MAX_DEPTH){
	$$hrtrack{$ST[1]}='?' if($LW::crawl_config{'save_skipped'}>0);
	next;
  }

  $ST[2]=utils_get_dir($ST[1]);

  $$hrin{'whisker'}->{'uri'}=$ST[1];
  $$hrin{'whisker'}->{'ssl'}=$ST[3];
  my $result = crawl_do_request($hrin,\%hout);
  if($result==1 || $result==2){
	push @ERRORS, "Error on making request for '$ST[1]': $hout{'whisker'}->{'error'}";
	next;
  }

  if($result==0 || $result==4){
	$$hrtrack{$ST[1]}=$hout{'whisker'}->{'http_resp'}; }
  
  if($result==3 || $result==5){
	$$hrtrack{$ST[1]}='?' if($LW::crawl_config{'save_skipped'}>0); }

  if(defined $hout{'server'}){ 
   if(!defined $ST[4]){ # server tag
	$ST[4]=$hout{'server'}; }
   $LW::crawl_server_tags{$hout{'server'}}++;
  }

  if(defined $hout{'set-cookie'}){
		if($LW::crawl_config{'save_cookies'}>0){
			if(ref($hout{'set-cookie'})){
				foreach (@{$hout{'set-cookie'}}){
					$LW::crawl_cookies{$_}++; }
			} else {
				$LW::crawl_cookies{$hout{'set-cookie'}}++; 
		}	}

		if($LW::crawl_config{'reuse_cookies'}>0){
			cookie_read(\%jar,\%hout); }
  }


  next if($result==4 || $result==5);  
  next if(scalar @links > $LW::crawl_config{'url_limit'});

  if($result==0){ # page should be parsed
	if($LW::crawl_config{'source_callback'} != 0  &&
		ref($LW::crawl_config{'source_callback'})){
		&{$LW::crawl_config{'source_callback'}}($hrin,\%hout); }

	LW::html_find_tags(\$hout{'whisker'}->{'data'},
		\&crawl_extract_links_test);
	$LW::crawl_config{'stats_html'}++; # count how many pages we've parsed
  }

  if($result==3){ # follow the move via location header
	push @LW::crawl_urls, $hout{'location'}; }

  foreach $T (@LW::crawl_urls){
	 $T=~tr/\0\r\n//d; # the NULL character is a bug that's somewhere
	 next if (length($T)==0);
	 next if ($T=~/^javascript:/i); # stupid javascript
	 next if ($T=~/^#/i); # fragment

	 if($LW::crawl_config{'callback'} != 0){
		next if &{$LW::crawl_config{'callback'}}($T,@ST); }

	 push(@{$LW::crawl_referrers{$T}}, $ST[1]) 
		if( $LW::crawl_config{'save_referrers'}>0 );

	 $T=utils_absolute_uri($T,$ST[1],1) if($LW::crawl_config{'normalize_uri'}>0);
	 @vals=utils_split_uri($T);

	 # slashdot bug: workaround for the following fsck'd html code:
	 # <FORM ACTION="//slashdot.org/users.pl" METHOD="GET">
	 if($LW::crawl_config{'slashdot_bug'} > 0 && 
			substr($vals[0],0,2) eq '//'){
		if($ST[3]==1){	$T='https:'.$T;
		} else {	$T='http:' .$T; }
		@vals=utils_split_uri($T);
	 }

	 # make sure URL is on same host, port, and protocol
	 if( (defined $vals[2] && $vals[2] ne $ST[0]) || 
			(defined $vals[3] && $vals[3] != $ST[5]) ||
			(defined $vals[1] && ($vals[1] ne 'http' 
				&& $vals[1] ne 'https'))){
		if($LW::crawl_config{'save_offsites'}>0){
			$LW::crawl_offsites{utils_join_uri(@vals)}++; }
		next; }

	 if(substr($vals[0],0,1) ne '/'){
		$vals[0]=$ST[2].$vals[0]; }

	 my $where=rindex($vals[0],'.');
	 my $EXT='';
	 if($where >= 0){
	   $EXT = substr($vals[0], $where+1, length($vals[0])-$where); }

	 $EXT=~tr/0-9a-zA-Z//cd; # yucky chars will puke regex below

	 if($EXT ne '' && $LW::crawl_config{'skip_ext'}=~/\.$EXT /i){
		if($LW::crawl_config{'save_skipped'}>0){
			$$hrtrack{$vals[0]}='?'; }
	 	next; }

	 if(defined $vals[4] && $LW::crawl_config{'use_params'}>0){
		if($LW::crawl_config{'params_double_record'}>0 &&
				!defined $$hrtrack{$vals[0]}){
			$$hrtrack{$vals[0]}='?'; }
		$vals[0]=$vals[0].'?'.$vals[4];	
	 }

	 next if(defined $$hrtrack{$vals[0]});

	 push @links, \@{[$vals[0],$ST[6]+1, ($vals[1] eq 'https')?1:0]};

  } # foreach

  @LW::crawl_urls=(); # reset for next round
 } # while

 my $key;
 foreach $key (keys %LW::crawl_config){
 	delete $LW::crawl_config{$key} if (substr($key,0,4) eq 'ref_');}

 $LW::crawl_config{'stats_reqs'}=$hout{'whisker'}->{'stats_reqs'};
 $LW::crawl_config{'stats_syns'}=$hout{'whisker'}->{'stats_syns'};

} # end sub crawl



sub crawl_get_config {
	my $key=shift;
	return $LW::crawl_config{$key};
}



sub crawl_set_config {
	return if(!defined $_[0]);
	my %opts=@_;
	while( my($k,$v)=each %opts){
		$LW::crawl_config{lc($k)}=$v; }
}



sub crawl_extract_links_test {
	my ($TAG, $hr, $dr, $start, $len)=(lc(shift),@_);
	my $t;

	# this should be most of the time...
	return undef if(!defined ($t=$LW::crawl_linktags{$TAG}));
	return undef if(!scalar %$hr); # fastpath quickie

	while( my ($key,$val)= each %$hr){ # normalize element values
		$$hr{lc($key)} = $val;
	}

	if(ref($t)){
		foreach (@$t){
			push(@LW::crawl_urls,$$hr{$_}) if(defined $$hr{$_});
		}
	} else {
		push(@LW::crawl_urls,$$hr{$t}) if(defined $$hr{$t});
	}

	if($TAG eq 'form' && defined $$hr{action}){
		my $u=$LW::crawl_config{'ref_hout'}->{'whisker'}->{'uri'};
		$LW::crawl_forms{utils_absolute_uri($$hr{action},$u,1)}++;
	}

	return undef;
}



sub crawl_do_request {
 my ($hrin,$hrout) = @_;
 my $ret;

 if($LW::crawl_config{'do_head'}){  
	my $save=$$hrin{'whisker'}->{'method'};
	$$hrin{'whisker'}->{'method'}='HEAD';
	$ret=http_do_request($hrin,$hrout);
	$$hrin{'whisker'}->{'method'}=$save;

	return 2 if($ret==2); # if there was connection error, do not continue
	if($ret==0){ # successful request
	    	if($$hrout{'whisker'}->{'http_resp'}==501){ # HEAD not allowed
    			$LW::crawl_config{'do_head'}=0; # no more HEAD requests
	    	}

		if($$hrout{'whisker'}->{'http_resp'} <308 &&
				$$hrout{'whisker'}->{'http_resp'} >300){
			if($LW::crawl_config{'follow_moves'} >0){
				return 3 if(defined $$hrout{'location'}); }
			return 5; # not avail
		}

		if($$hrout{'whisker'}->{'http_resp'}==200){
			# no content-type is treated as text/htm
			if(defined $$hrout{'content-type'} &&
					$$hrout{'content-type'}!~/^text\/htm/i){
				return 4;
			}		
			# fall through to GET request below			
		}
    	}
	# request errors are essentially redone via GET, below
  }

 return http_do_request($hrin,$hrout);
}





sub dumper {
	my %what=@_;
	my ($final,$k,$v)=('');
	while( ($k,$v)=each %what){
		return 'ERROR' if(ref($k) || !ref($v));
		$final.="\$$k = "._dump(1,$v);
		$final=~s#,\n$##;
		$final.=";\n"; }
	return $final;
}



sub dumper_writefile {
	my $file=shift;
	my $output=dumper(@_);
	return 1 if(!open(OUT,">$file") || $output eq 'ERROR');
	print OUT $output;
	close(OUT);
}



sub _dump { # dereference and dump an element
	my ($t, $ref)=@_;
	my ($out,$k,$v)=('');
	if(ref($ref) eq 'HASH'){
		$out.="{\n";
		while( ($k,$v)=each %$ref){
			$out.= "\t"x$t;
			$out.=_dumpd($k).' => ';
			if(ref($v)){ $out.=_dump($t+1,$v); }
			else { $out.=_dumpd($v).",\n"; }}
		$out=~s#,\n$#\n#;
		$out.="\t"x$t;
		$out.="},\n";
	} elsif(ref($ref) eq 'ARRAY'){
		$out.="[\n";
		foreach $v (@$ref) {
			$out.= "\t"x$t;
			if(ref($v)){ $out.=_dump($t+1,$v); }
			else { $out.=_dumpd($v).",\n"; }}
		$out=~s#,\n$#\n#;
		$out.="\t"x$t;
		$out.="],\n";
	} elsif(ref($ref) eq 'SCALAR'){
		$out.=_dumpd($$ref);
	} elsif(ref($ref) eq 'REF'){
		$out.=_dump($t,$$ref);
	} elsif(ref($ref)){
		$out.='"" # unsupported reference type: ';
		$out.=ref($ref);	$out.="\n";
	} else { # normal scalar
		$out.=_dumpd($ref);
	}
	return $out;
}



sub _dumpd { # escape a scalar string
	my $v=shift;
	return "'$v'" if($v!~tr/!-~//c);
	$v=~s#\\#\\\\#g;	$v=~s#"#\\"#g;
	$v=~s#\r#\\r#g;		$v=~s#\n#\\n#g;
	$v=~s#\0#\\0#g;		$v=~s#\t#\\t#g;
	$v=~s#([^!-~ ])#sprintf('\\x%02x',ord($1))#eg;
	return "\"$v\"";
}




sub get_page {
	my ($URL,$hr)=(shift,shift);
	return (undef,"No URL supplied") if(length($URL)==0);

	my (%req,%resp);
	my $rptr;

	if(defined $hr && ref($hr)){
		$rptr=$hr;
	} else {
		$rptr=\%req;
		LW::http_init_request(\%req);
	}

	LW::utils_split_uri($URL,$rptr); # this is newer >=1.1 syntax
	LW::http_fixup_request($rptr);

	if(http_do_request($rptr,\%resp)){
		return (undef,$resp{'whisker'}->{'error'});
	}

	return ($resp{'whisker'}->{'code'}, $resp{'whisker'}->{'data'});
}



sub get_page_hash {
	my ($URL,$hr)=(shift,shift);
	return undef if(length($URL)==0);

	my (%req,%resp);
	my $rptr;

	if(defined $hr && ref($hr)){
		$rptr=$hr;
	} else {
		$rptr=\%req;
		LW::http_init_request(\%req);
	}

	LW::utils_split_uri($URL,$rptr); # this is newer >=1.1 syntax
	LW::http_fixup_request($rptr);

	my $r=http_do_request($rptr,\%resp);
	$resp{whisker}->{get_page_hash}=$r;

	return \%resp;
}



sub get_page_to_file {
	my ($URL, $filepath, $hr)=@_;

	return undef if(length($URL)==0);
	return undef if(length($filepath)==0);

	my (%req,%resp);
	my $rptr;

	if(defined $hr && ref($hr)){
		$rptr=$hr;
	} else {
		$rptr=\%req;
		LW::http_init_request(\%req);
	}

	LW::utils_split_uri($URL,$rptr); # this is newer >=1.1 syntax
	LW::http_fixup_request($rptr);

	if(http_do_request($rptr,\%resp)){
		return undef;
	}
	open(OUT,">$filepath") || return undef;
	binmode(OUT); # stupid Windows
	print OUT $resp{'whisker'}->{'data'};
	close(OUT);

	return $resp{'whisker'}->{'code'};
}



sub upload_file {
	my ($URL, $filepath, $paramname, $hr)=@_;

	return undef if(length($URL)      ==0);
	return undef if(length($filepath) ==0);
	return undef if(length($paramname)==0);
	return undef if(!(-e $filepath && -f $filepath));

	my (%req,%resp,%multi);
	my $rptr;

	if(defined $hr && ref($hr)){
		$rptr=$hr;
	} else {
		$rptr=\%req;
		LW::http_init_request(\%req);
	}

	LW::utils_split_uri($URL,$rptr); # this is newer >=1.1 syntax
	$rptr{'whisker'}->{'method'}='POST';
	LW::http_fixup_request($rptr);

	LW::multipart_setfile(\%multi,$filepath,$paramname);
	LW::multipart_write(\%multi,$rptr);

	if(http_do_request($rptr,\%resp)){
		return undef;
	}

	return $resp{'whisker'}->{'code'};
}



sub download_file {
	goto &LW::get_page_to_file;
}






#sub encode_base64;




#sub decode_base64;




sub encode_base64_perl { # ripped from MIME::Base64
    my $res = "";
    my $eol = $_[1];
    $eol = "\n" unless defined $eol;
    pos($_[0]) = 0;
    while ($_[0] =~ /(.{1,45})/gs) {
        $res .= substr(pack('u', $1), 1);
        chop($res);}
    $res =~ tr|` -_|AA-Za-z0-9+/|;
    my $padding = (3 - length($_[0]) % 3) % 3;
    $res =~ s/.{$padding}$/'=' x $padding/e if $padding;
    if (length $eol) {
        $res =~ s/(.{1,76})/$1$eol/g;
    } $res; }




sub decode_base64_perl { # ripped from MIME::Base64
    my $str = shift;
    my $res = "";
    $str =~ tr|A-Za-z0-9+=/||cd;
    $str =~ s/=+$//;                        # remove padding
    $str =~ tr|A-Za-z0-9+/| -_|;            # convert to uuencoded format
    while ($str =~ /(.{1,60})/gs) {
        my $len = chr(32 + length($1)*3/4); # compute length byte
        $res .= unpack("u", $len . $1 );    # uudecode
    }$res;}




sub encode_str2uri { # normal hex encoding
	my $str=shift;
	$str=~s/([^\/])/sprintf("%%%02x",ord($1))/ge;
	return $str;}




sub encode_str2ruri { # random normal hex encoding
    my @T=split(//,shift);
    my $s;
    foreach (@T) {
     if(m#;=:&@\?#){
        $s.=$_;
        next;
      }
      if((rand()*2)%2 == 1){	$s.=sprintf("%%%02x",ord($_)) ;
      }else{			$s.=$_; }
    }
    return $s;
}



sub encode_unicode
{
	my $r='';
 	foreach $c (split(//,shift)){
		$r.=pack("v",ord($c));
	}
	return $r;
}




sub forms_read {
	my $dr=shift;
	return undef if(!ref($dr) || length($$dr)==0);

	@LW::forms_found=();
	LW::html_find_tags($dr,\&forms_parse_callback);

	if(scalar %LW::forms_current){
		my %DUP=%LW::forms_current;
		push(@LW::forms_found,\%DUP);
	}
	return @LW::forms_found;
}



sub forms_write {
	my $hr=shift;
	return undef if(!ref($hr) || !(scalar %$hr));
	return undef if(!defined $$hr{"\0"});
	
	my $t='<form name="'.$$hr{"\0"}->[0].'" method="';
	$t.=$$hr{"\0"}->[1].'" action="'.$$hr{"\0"}->[2].'"';
	if(defined $$hr{"\0"}->[3]){
		$t.=' '.join(' ',@{$$hr{"\0"}->[3]}); }
	$t.=">\n";

	while( my($name,$ar)=each(%$hr) ){
	  next if($name eq "\0");
	  foreach $a (@$ar){
		my $P='';
		$P=' '.join(' ', @{$$a[2]}) if(defined $$a[2]);
		$t.="\t";

		if($$a[0] eq 'textarea'){
			$t.="<textarea name=\"$name\"$P>$$a[1]";
			$t.="</textarea>\n";

		} elsif($$a[0]=~m/^input-(.+)$/){
			$t.="<input type=\"$1\" name=\"$name\" ";
			$t.="value=\"$$a[1]\"$P>\n";

		} elsif($$a[0] eq 'option'){
			$t.="\t<option value=\"$$a[1]\"$P>$$a[1]\n";

		} elsif($$a[0] eq 'select'){
			$t.="<select name=\"$name\"$P>\n";

		} elsif($$a[0] eq '/select'){
			$t.="</select$P>\n";

		} else { # button
			$t.="<button name=\"$name\" value=\"$$a[1]\">\n";
		}
	  }
	}

	$t.="</form>\n";
	return $t;
}




{ # these are private static variables for &forms_parse_html
%FORMS_ELEMENTS=(	'form'=>1,	'input'=>1,
			'textarea'=>1,	'button'=>1,
			'select'=>1,	'option'=>1,
			'/select'=>1	);
$CURRENT_SELECT=undef;
$UNKNOWNS=0;

sub forms_parse_callback {
	my ($TAG, $hr, $dr, $start, $len)=(lc(shift),@_);
	my ($saveparam, $parr, $key)=(0,undef,'');

	# fastpath shortcut
	return undef if(!defined $FORMS_ELEMENTS{$TAG});
	LW::utils_lowercase_hashkeys($hr) if(scalar %$hr);

	if($TAG eq 'form'){

		if(scalar %LW::forms_current){ # save last form
			my %DUP=%LW::forms_current;
			push (@LW::forms_found, \%DUP);
			%LW::forms_current=();
		}

		$LW::forms_current{"\0"}=[$$hr{name},$$hr{method},
			$$hr{action},undef];
		delete $$hr{'name'}; delete $$hr{'method'}; delete $$hr{'action'};
		$key="\0"; $parr=\@{$LW::forms_current{"\0"}};
		$UNKNOWNS=0;

	} elsif($TAG eq 'input'){
		$$hr{type}='text' if(!defined $$hr{type});
		$$hr{name}='unknown'.$UNKNOWNS++ if(!defined $$hr{name});
		$key=$$hr{name};
	
		push( @{$LW::forms_current{$key}}, 
			(['input-'.$$hr{type},$$hr{value},undef]) );
		delete $$hr{'name'}; delete $$hr{'type'}; delete $$hr{'value'};
		$parr=\@{$LW::forms_current{$key}->[-1]};

	} elsif($TAG eq 'select'){
		$$hr{name}='unknown'.$UNKNOWNS++ if(!defined $$hr{name});
		$key=$$hr{name};
		push( @{$LW::forms_current{$key}}, (['select',undef,undef]) );
		$parr=\@{$LW::forms_current{$key}->[-1]};
		$CURRENT_SELECT=$key;
		delete $$hr{name};

	} elsif($TAG eq '/select'){
		push( @{$LW::forms_current{$CURRENT_SELECT}}, 
			(['/select',undef,undef]) );
		$CURRENT_SELECT=undef;
		return undef;

	} elsif($TAG eq 'option'){
		return undef if(!defined $CURRENT_SELECT);
		if(!defined $$hr{value}){
			my $stop=index($$dr,'<',$start+$len);
			return undef if($stop==-1); # MAJOR PUKE
			$$hr{value}=substr($$dr,$start+$len,
				($stop-$start-$len));
			$$hr{value}=~tr/\r\n//d;
		}
		push( @{$LW::forms_current{$CURRENT_SELECT}}, 
			(['option',$$hr{value},undef]) );
		delete $$hr{value};
		$parr=\@{$LW::forms_current{$CURRENT_SELECT}->[-1]};

	} elsif($TAG eq 'textarea'){
		my $stop=$start+$len;
		# find closing </textarea> tag
		do {	$stop=index($$dr,'</',$stop+2); 
			return undef if($stop==-1); # MAJOR PUKE
		} while( lc(substr($$dr,$stop+2,8)) ne 'textarea');
		$$hr{value}=substr($$dr,$start+$len,($stop-$start-$len));

		$$hr{name}='unknown'.$UNKNOWNS++ if(!defined $$hr{name});
		$key=$$hr{name};
		push( @{$LW::forms_current{$key}}, 
			(['textarea',$$hr{value},undef]) );
		$parr=\@{$LW::forms_current{$key}->[-1]};
		delete $$hr{'name'}; delete $$hr{'value'};

	} else { # button
		$$hr{name}='unknown'.$UNKNOWNS++ if(!defined $$hr{name});
		$key=$$hr{name};
		push( @{$LW::forms_current{$key}}, 
			(['button',$$hr{value},undef]) );
	}

	if(scalar %$hr){
		my @params=();
		foreach $k (keys %$hr){
			if(defined $$hr{$k}){
					push @params, "$k=\"$$hr{$k}\"";
			} else {	push @params, $k; }
		}
		$$parr[2]=\@params;
	}

	return undef;
}}




sub html_find_tags {
 # use faster binary helper
 goto &LW::bin::html_find_tags 
 	if(defined $LW::available{'lw::bin'});
	
 my ($dataref, $callbackfunc)=@_;

 return if(!(defined $dataref      && ref($dataref)     ));
 return if(!(defined $callbackfunc && ref($callbackfunc)));

 my ($CURTAG, $ELEMENT, $VALUE, $c, $cc);
 my ($INCOMMENT,$INTAG,$INSCRIPT)=(0,0,0);
 my (%TAG, $ret, $start, $tagstart, $commstart, $scriptstart, $x);

 # YES, this looks like C.  In fact, it's my C version ported to
 # perl.  But it's faster and more dependable than any regex mess
 # someone could come up with.
 my $LEN = length($$dataref);
 for ($c=0; $c<$LEN; $c++){

	$cc=substr($$dataref,$c,1);

	if(!$INCOMMENT && !$INTAG && !$INSCRIPT && $cc ne '>' && $cc ne '<'){
		next; }

        if($cc eq '<'){
		if($INSCRIPT){
			if(lc(substr($$dataref,$c+1,7)) eq '/script'){
				$INSCRIPT=0;
				$TAG{'='}=substr($$dataref, $scriptstart,
					$c - $scriptstart - 1);
			} else { next; }
		}

                if(substr($$dataref,$c+1,3) eq '!--'){
                        $INCOMMENT=1; $commstart=$c; $c+=3;

		} else {
    	                $INTAG=1; $c++;
			$c++ while(substr($$dataref,$c,1)=~/[< \t\r\n]/);
			$tagstart=$c-1; 

			$CURTAG='';
			while(($x=substr($$dataref,$c,1))!~/[ \t\r\n>=]/ &&
					$c < $LEN){
				$CURTAG.=$x; $c++;}

			$c++ if($x ne '>');

			$INSCRIPT=1 if($CURTAG eq 'script');
		}	
		$cc=substr($$dataref,$c,1); # refresh current char (cc)
	}

        if($cc eq '>'){
		if($INSCRIPT){
			if($CURTAG eq 'script'){
				$scriptstart = $c + 1; 
			} else { next; }
		}
		if(!$INCOMMENT && $INTAG){ 
			$INTAG=0; 
			$ret=&$callbackfunc($CURTAG,\%TAG, $dataref,
				$tagstart, $c-$tagstart+1);
			if(defined $ret && $ret != 0){
				$c+=$ret;}
			$CURTAG='';
			%TAG=();
		}
                if($INCOMMENT && substr($$dataref,$c-2,2) eq '--'){
                        $INCOMMENT=0; 
			$TAG{'='}=substr($$dataref,$commstart+4,
				$c-$commstart-3);
			$ret=&$callbackfunc('!--',\%TAG, $dataref,
				$commstart, $c-$commstart+1);
			if(defined $ret && $ret != 0){
				$c+=$ret;}
			delete $TAG{'='};
			next;
		}
	}

        next if($INCOMMENT);

        if($INTAG){

                $ELEMENT=''; $VALUE='';

		# eat whitespace
		while(substr($$dataref,$c,1)=~/[ \t\r\n]/i){ $c++; }

		$start=$c;
		while(substr($$dataref,$c,1)!~/[ \t\r\n=\>]/i &&
			$c < $LEN) { $c++; }

		$ELEMENT=substr($$dataref,$start,$c-$start);

		$VALUE='';
		if(substr($$dataref,$c,1) ne '>'){
		 # eat whitespace
		 while(substr($$dataref,$c,1)=~/[ \t\r\n]/i) { $c++; }

                 if(substr($$dataref,$c,1) eq '='){ 
                	$c++;
			$start=$c;
			my $p = substr($$dataref,$c,1);
                        if($p eq '"' || $p eq '\''){ 
                        	$c++; $start++;
	                        $c++ while(substr($$dataref,$c,1) ne $p &&
	                        	$c < $LEN);
				$VALUE=substr($$dataref,$start,$c-$start);
                                $c++; 
			} else {
                                $c++ while(substr($$dataref,$c,1)!~/[ \t\r\n\>]/ &&
                                	$c < $LEN);
				$VALUE=substr($$dataref,$start,$c-$start);
			}

			# eat whitespace
                	while(substr($$dataref,$c,1)=~/[ \t\r\n]/) { $c++; }
                 } 
		} # if $c ne '>'
		$c--;
		$TAG{$ELEMENT}=$VALUE; # save element in the hash
	}
}}





sub http_init_request { # doesn't return anything
 my ($hin)=shift;

 return if(!(defined $hin && ref($hin)));
 %$hin=(); # clear control hash

# control values
 $$hin{'whisker'}={
	req_spacer		=>	' ',
	req_spacer2		=>	' ',
	http_ver		=>	'1.1',
	method			=>	'GET',
	method_postfix		=>	'',
	port			=>	80,
	uri			=>	'/',
	uri_prefix		=>	'',
	uri_postfix		=>	'',
	uri_param_sep		=>	'?',
	host			=>	'localhost',
	http_req_trailer    	=>	'',
	timeout			=>	10,
	include_host_in_uri 	=>	0,
	ignore_duplicate_headers=> 	1,
	normalize_incoming_headers =>	1,
	lowercase_incoming_headers =>	0,
	ssl			=>	0,
	http_eol		=>	"\x0d\x0a",
	force_close		=>	0,
	force_open		=>	0,
	retry			=>	1,
	trailing_slurp		=>	0,
	force_bodysnatch	=>	0,
	INITIAL_MAGIC		=>	31337
};

 
# default header values
 $$hin{'Connection'}='Keep-Alive'; # notice it is now default!
 $$hin{'User-Agent'}="libwhisker/$LW::VERSION"; # heh
}




sub http_do_request {
 my @params = @_;
 my $retry_count = ${$params[0]}{'whisker'}->{'retry'} || 0;
 my ($ret, @retry_errors, $auth);

 return 1 if(!(defined $params[0] && ref($params[0])));
 return 1 if(!(defined $params[1] && ref($params[1])));

 if(defined $params[2]){
	foreach (keys %{$params[2]}){
		${$params[0]}{'whisker'}->{$_}=${$params[2]}{$_};}}

 $auth=$params[0]->{'Authorization'} if(defined $params[0]->{'Authorization'});
 do {
    if(defined $auth && $auth=~/^NTLM/){
	$ret=0;
	if($params[0]->{'whisker'}->{'ntlm_step'}==0){
		$ret=LW::http_do_request_ex($params[0],$params[1]);
		return 2 if($ret==2);
		if($ret==0){
			return 0 if($params[1]->{'whisker'}->{'code'} == 200);
			return 1 if($params[1]->{'whisker'}->{'code'} != 401);
			$params[0]->{'whisker'}->{'ntlm_step'}=1;
			my $thead=utils_find_lowercase_key($params[1],'www-authenticate');
			return 1 if(!defined $thead);
			return 1 if($thead!~m/^NTLM (.+)$/);  
			$params[0]->{'Authorization'}='NTLM '.ntlm_client(
				$params[0]->{'whisker'}->{'ntlm_obj'},$1);
		}
	}
	if($ret==0){
		delete $params[0]->{'Authorization'}
			if($params[0]->{'whisker'}->{'ntlm_step'}>1);
		$ret=LW::http_do_request_ex($params[0],$params[1]);
		$params[0]->{'Authorization'}=$auth; 
		if($ret>0){ 	$params[0]->{'whisker'}->{'ntlm_step'}=0;
		} else {	$params[0]->{'whisker'}->{'ntlm_step'}=2; }
		return $ret if($ret==2||$ret==0);
	}
    } else {
    	$ret=LW::http_do_request_ex($params[0],$params[1]);
	push @{${$params[1]}{'whisker'}->{'retry_errors'}},
		@retry_errors if scalar(@retry_errors);
	return $ret if($ret==0 || $ret==2);
    }
    push @retry_errors, ${$params[1]}{'whisker'}->{'error'};
    $retry_count--;
  } while( $retry_count >= 0);

 # if we get here, we still had errors, but no more retries
 return 1;
}



sub http_do_request_ex {
 my ($hin, $hout, $hashref)=@_;
 my ($temp,$vin,$resp,$S,$a,$b,$vout,@c,$c,$res)=(1,'');
 my $W; # shorthand alias for the {'whisker'} hash

 return 1 if(!(defined $hin  && ref($hin) ));
 return 1 if(!(defined $hout && ref($hout)));

 %$hout=(); # clear output hash
 $$hout{whisker}->{uri}=$$hin{whisker}->{uri}; # for tracking purposes
 $$hout{whisker}->{'INITIAL_MAGIC'}=31338; # we can tell requests from responses

 if($LW::LW_HAS_SOCKET==0){
	$$hout{'whisker'}->{'error'}='Socket support not available';
	return 2;}

 if(!defined $$hin{'whisker'} || 
    !defined $$hin{'whisker'}->{'INITIAL_MAGIC'} ||
    $$hin{'whisker'}->{'INITIAL_MAGIC'}!=31337 ){
	$$hout{'whisker'}->{'error'}='Input hash not initialized';
	return 2;
 }

 if(defined $hashref){
	foreach (keys %$hashref){
		$$hin{'whisker'}->{$_}=$$hashref{$_};}}

 # if we want anti-IDS, make a copy and setup new values
 if(defined $$hin{'whisker'}->{'anti_ids'}){
	my %copy=%{$hin};
	anti_ids(\%copy,$$hin{'whisker'}->{'anti_ids'});
	$W = $copy{'whisker'};
 } else {
	$W = $$hin{'whisker'};
 }

 if($$W{'ssl'}>0 && $LW::LW_HAS_SSL!=1){
	$$hout{'whisker'}->{'error'}='SSL not available';
	return 2;}

 $TIMEOUT=$$W{'timeout'}||10;

 my $cache_key = defined $$W{'proxy_host'} ?
	join(':',$$W{'proxy_host'},$$W{'proxy_port'}) :
	join(':',$$W{'host'},$$W{'port'});

 if(!defined $http_host_cache{$cache_key}){
	# make new entry
	push(@{$http_host_cache{$cache_key}},
		undef, 	# SOCKET		$$Z[0]
		0,	# $SOCKSTATE		$$Z[1]
		undef,	# INET_ATON		$$Z[2]
		undef,	# $SSL_CTX		$$Z[3]
		undef,	# $SSL_THINGY		$$Z[4]
		'',	# $OUTGOING_QUEUE	$$Z[5]
		'',	# $INCOMING_QUEUE	$$Z[6]
		0,	# $STATS_SYNS		$$Z[7]
		0, 	# $STATS_REQS		$$Z[8]
		undef ) # SSL session ID	$$Z[9]
 }

 # NOTE: the 'Z' reference will be going away in future versions...
 $Z = $http_host_cache{$cache_key};

 # use $chost/$cport for actual server we are connecting to
 my ($chost,$cport,$cwhat,$PROXY)=('',80,'',0);

 if(defined $$W{'proxy_host'}){
    $chost=$$W{'proxy_host'};
    $cport=$$W{'proxy_port'}||80;
    $cwhat='proxy';
    $PROXY=1;

    if($$W{'ssl'}>0 && $LW::LW_SSL_LIB==2){
	$ENV{HTTPS_PROXY} ="$$W{'proxy_host'}:";
	$ENV{HTTPS_PROXY}.=$$W{'proxy_port'}||80; }

 } else {
    $chost=$$W{'host'};
    $cport=$$W{'port'};
    $cwhat='host';
 }

 if($$Z[1]>0){ # check to see if socket is still alive
	if(! sock_valid($Z,$hin,$hout) ){
		$$Z[1]=0;
		sock_close($$Z[0],$$Z[4]);
 }	}
 # technically we have a race condition: socket can go
 # bad before we send request, below.  But that's ok,
 # we handle the errors down there.

 if($$Z[1]==0){

	if(defined $$W{'UDP'} && $$W{'UDP'}>0){
		if(!socket(SOCK,PF_INET,SOCK_DGRAM,getprotobyname('udp')||0)){
			$$hout{'whisker'}->{'error'}='Socket() problems (UDP)'; 
			return 2;}
	} else {
		if(!socket(SOCK,PF_INET,SOCK_STREAM,getprotobyname('tcp')||0)){
			$$hout{'whisker'}->{'error'}='Socket() problems'; 
			return 2;}
	}

	$$Z[0]=SOCK; # lame hack to get perl to take variable for socket

	$$Z[5]=$$Z[6]=''; # flush in/out queues

	if($$W{'ssl'}>0){ # ssl setup stuff

	    if($LW::LW_SSL_LIB==1){
		if(!defined($$Z[3])){
		    if(! ($$Z[3] = Net::SSLeay::CTX_new()) ){
			$$hout{'whisker'}->{'error'}="SSL_CTX error: $!";
			return 2;}
		    if(defined $$W{'ssl_rsacertfile'}){
			if(! (Net::SSLeay::CTX_use_RSAPrivateKey_file($$Z[3], 
					$$W{'ssl_rsacertfile'},
					&Net::SSLeay::FILETYPE_PEM))){
				$$hout{'whisker'}->{'error'}="SSL_CTX_use_rsacert error: $!";
				return 2;}
		    }
		    if(defined $$W{'ssl_certfile'}){
			if(! (Net::SSLeay::CTX_use_certificate_file($$Z[3], 
					$$W{'ssl_certfile'},
					&Net::SSLeay::FILETYPE_PEM))){
				$$hout{'whisker'}->{'error'}="SSL_CTX_use_cert error: $!";
				return 2;}
		    }
		}
		if(! ($$Z[4] = Net::SSLeay::new($$Z[3])) ){
			$$hout{'whisker'}->{'error'}="SSL_new error: $!";
			return 2;}
		if(defined $$W{'ssl_ciphers'}){
			if(!(Net::SSLeay::set_cipher_list($$Z[4], 
					$$W{'ssl_ciphers'}))){
				$$hout{'whisker'}->{'error'}="SSL_set_ciphers error: $!";
				return 2;}
		}
	    }
	}

	$$Z[2]=inet_aton($chost) if(!defined $$Z[2]);
	if(!defined $$Z[2]){ # can't find hostname
		$$hout{'whisker'}->{'error'}="Can't resolve hostname";
		return 2;
	}

	if($$W{'ssl'}>0 && $LW::LW_SSL_LIB==2){
		# proxy set in ENV; we always connect to host
		$$Z[4]= Net::SSL->new(
			PeerAddr => $$hin{'whisker'}->{'host'},
			PeerPort => $$hin{'whisker'}->{'port'},
			Timeout => $TIMEOUT );
		if($@){ $$hout{'whisker'}->{'error'}="Can't connect via SSL: $@[0]";
			return 2;}
		$$Z[4]->autoflush(1);
	} else {
		if($LW::LW_NONBLOCK_CONNECT){
			my $flags=fcntl($$Z[0],F_GETFL,0);
			$flags |= O_NONBLOCK; # set nonblock flag
			if(!(fcntl($$Z[0],F_SETFL,$flags))){ # error setting flag
				$LW::LW_NONBLOCK_CONNECT=0; # revert to normal
			} else {
				my $R=connect($$Z[0],sockaddr_in($cport,$$Z[2]));
				if(!$R){ # we didn't connect...
					if($! != EINPROGRESS){
						close($$Z[0]);
						$$Z[0]=undef; # this is a bad socket
						$$hout{'whisker'}->{'error'}="Can't connect to $cwhat";
						return 2;}
					vec($vin,fileno($$Z[0]),1)=1;
					if(!select(undef,$vin,undef,$TIMEOUT) || !getpeername($$Z[0])){
						close($$Z[0]);
						$$Z[0]=undef; # this is a bad socket
						$$hout{'whisker'}->{'error'}="Can't connect to $cwhat";
						return 2;
				}	}
				$flags &= ~O_NONBLOCK; # clear nonblock flag
				if(!(fcntl($$Z[0],F_SETFL,$flags))){ # not good!
					close($$Z[0]);
					$LW::LW_NONBLOCK_CONNECT=0;
					$$Z[0]=undef;
					$$hout{'whisker'}->{'error'}="Error setting socket to block";
					return 2;
			}	}	
		}	

		if(!defined $$Z[0]){ # this is a safety catch
			$$hout{'whisker'}->{'error'}="Error creating valid socket connection";
			return 2; }

		if($LW::LW_NONBLOCK_CONNECT==0){ # attempt to do a timeout alarm...
			eval {
				local $SIG{ALRM} = sub { die "timeout\n" };
				eval {alarm($TIMEOUT)};
				if(!connect($$Z[0],sockaddr_in($cport,$$Z[2]))){
					alarm(0);
					die("no_connect\n"); }
				eval {alarm(0)};
			};
			if($@ || !(defined $$Z[0])){
				$$hout{'whisker'}->{'error'}="Can't connect to $cwhat";
				return 2;
		}	}

		binmode($$Z[0]); # stupid Windows
		# same as IO::Handle->autoflush(1), without importing 1000+ lines
		my $S=select($$Z[0]); 
		$|++; select($S);
	}

	$$Z[1]=1; $$Z[7]++;

	if($$W{'ssl'}>0){

	    if($LW::LW_SSL_LIB==1){

	        if($PROXY){ # handle the proxy CONNECT stuff...
		    my $SSL_CONNECT = "CONNECT $$W{'host'}".
			":$$W{'port'}/ HTTP/1.0\n\n";
		    syswrite($$Z[0],$SSL_CONNECT, length($SSL_CONNECT)); }

		Net::SSLeay::set_fd($$Z[4], fileno($$Z[0]));
		Net::SSLeay::set_session($$Z[4],$$Z[9]) if(defined $$Z[9]);
		if(! (Net::SSLeay::connect($$Z[4])) ){
			$$hout{'whisker'}->{'error'}="SSL_connect error: $!";
			sock_close($$Z[0],$$Z[4]); return 2;}

		if(defined $$W{'save_ssl_info'} && 
				$$W{'save_ssl_info'}>0){
			ssl_save_info($hout,$$Z[4]); }
		my $x=Net::SSLeay::ctrl($$Z[4],6,0,'');
		$$Z[9]=Net::SSLeay::get_session($$Z[4]) unless(defined $$W{'ssl_resume'} &&
			$$W{'ssl_resume'}==0);
	    }

	} else {
		$$Z[4]=undef;
	}
 }

 if(defined $$W{'ids_session_splice'} &&
            $$W{'ids_session_splice'}>0 &&
		$$W{'ssl'}==0){ # no session_spice over ssl
	setsockopt($$Z[0],SOL_SOCKET,SO_SNDLOWAT,1);
	@c=split(//, &http_req2line($hin));
	# notice we bypass queueing here, in order to trickle the packets
	my $ss;
	foreach $c (@c){ 
		$ss=syswrite($$Z[0],$c,1); # char size assumed to be 1
		if(!defined $ss || $ss==0){
			$$hout{'whisker'}->{'error'}="Error sending session splice request to server";
			sock_close($$Z[0],$$Z[4]); return 1;
		}
		select(undef,undef,undef,.1);
	}
 } else {
	 http_queue(http_req2line($hin)); }

 $$Z[8]++;

 if($$W{'http_ver'} ne '0.9'){
    my %SENT;
    if(defined $$W{'header_order'} && ref($$W{'header_order'})){
	foreach (@{$$W{'header_order'}}){
		next if($_ eq '' || $_ eq 'whisker');
		if(ref($$hin{$_})){
			$SENT{$_}||=0;
			my $v=$$hin{$_}->[$SENT{$_}];
			http_queue("$_: $v$$W{'http_eol'}");
		} else {
			http_queue("$_: $$hin{$_}$$W{'http_eol'}");
		}
		$SENT{$_}++;
	}
    }

    foreach (keys %$hin){
	next if($_ eq '' || $_ eq 'whisker');
	next if(defined $SENT{$_});
	if(ref($$hin{$_})){ # header with multiple values
		my $key=$_;
		foreach (@{$$hin{$key}}){
		  http_queue("$key: $_$$W{'http_eol'}");}
	} else { # normal header
		http_queue("$_: $$hin{$_}$$W{'http_eol'}");
	}
    }

    if(defined $$W{'raw_header_data'}){
	http_queue($$W{'raw_header_data'});}

    http_queue($$W{'http_eol'});

    if(defined $$W{'data'}){ 
	http_queue($$W{'data'});}

 } # http 0.9 support

 # take a MD5 of queue, if wanted
 if(defined $$W{'queue_md5'}){
	$$hout{'whisker'}->{'queue_md5'}= LW::md5($$Z[5]);
 }


 # all data is wrangled...actually send it now
 if($res=http_queue_send($$Z[0],$$Z[4])){
	$$hout{'whisker'}->{'error'}="Error sending request to server: $res";
	sock_close($$Z[0],$$Z[4]); $$Z[1]=0; return 1;}

 if(defined $$Z[4]){
	if($LW::LW_SSL_LIB==1){ # Net::SSLeay
 		shutdown $$Z[0], 1; 
	} else { # Net::SSL
		shutdown $$Z[4], 1;
	}
 }

 vec($vin,fileno($$Z[0]),1)=1; # wait only so long to read...
 if(!select($vin,undef,undef,$TIMEOUT)){
	$$hout{'whisker'}->{'error'}="Server read timed out";
	sock_close($$Z[0],$$Z[4]); $$Z[1]=0; return 1;}

my ($LC,$CL,$TE,$CO)=('',-1,'',''); # extra header stuff

$$hout{'whisker'}->{'lowercase_incoming_headers'} = 
	$$W{'lowercase_incoming_headers'};

if($$W{'http_ver'} ne '0.9'){

 do { # catch '100 Continue' responses
  $resp=sock_getline($$Z[0],$$Z[4]);
  #$resp=~tr/\r\n//d if(defined $resp);

  if(!defined $resp){
	$$hout{'whisker'}->{'error'}='Error reading HTTP response';
	if($!){ # this should be left over from sysread via sock_getline
		$$hout{'whisker'}->{'error'}.=": $!"; }
	$$hout{'whisker'}->{'data'}=$$Z[6];
	sock_close($$Z[0],$$Z[4]); $$Z[1]=0; # otherwise bad crap lingers
	return 1;}

  if(defined $$W{'save_raw_headers'}){
	$$hout{'whisker'}->{'raw_header_data'}.=$resp;}

  if($resp!~/^HTTP\/([0-9.]{3})[ \t]+(\d+)[ \t]{0,1}(.*?)[\r\n]+/){
	$$hout{'whisker'}->{'error'}="Invalid HTTP response: $resp";
	# let's save the incoming data...we might want it
	$$hout{'whisker'}->{'data'}=$resp;
	while(defined ($_=sock_getline($$Z[0],$$Z[4]))){ 
		$$hout{'whisker'}->{'data'}.=$_;}
	# normally we'd check the results to see if socket is closed, but
	# we close it anyway, so it doesn't matter
	sock_close($$Z[0],$$Z[4]); $$Z[1]=0; # otherwise bad crap lingers
	return 1;}

  $$hout{'whisker'}->{'http_ver'}	= $1;
  $$hout{'whisker'}->{'http_resp'}	= $2;
  $$hout{'whisker'}->{'http_resp_message'}= $3;
  $$hout{'whisker'}->{'code'}		= $2;

  $$hout{'whisker'}->{'100_continue'}++ if($2 == 100);

  while(defined ($_=sock_getline($$Z[0],$$Z[4]))){ # check pertinent headers

	if(defined $$W{'save_raw_headers'}){
		$$hout{'whisker'}->{'raw_header_data'}.=$_;}

	$_=~s/[\r]{0,1}\n$//; # anchored regex, so it's fast
	last if ($_ eq ''); # acceptable assumption case?

	my $l2=index($_,':'); # this is faster than regex
	$a=substr($_,0,$l2); 
	$b=substr($_,$l2+1);
	$b=~s/^([ \t]*)//; # anchored regex, so it's fast

	$hout{'whisker'}->{'abnormal_header_spacing'}++ if($1 ne ' ');

	$LC = lc($a);
	next         if($LC eq 'whisker');
	$TE = lc($b) if($LC eq 'transfer-encoding');
	$CL = $b     if($LC eq 'content-length');
	$CO = lc($b) if($LC eq 'connection');

	if($$W{'lowercase_incoming_headers'}>0){
		$a=$LC;
	} elsif($$W{'normalize_incoming_headers'}>0){ 
                $a=~s/(-[a-z])/uc($1)/eg;
 	}

	# save the received header order, in case we're curious
	push(@{$$hout{'whisker'}->{'recv_header_order'}},$a);

	if(defined $$hout{$a} && $$W{'ignore_duplicate_headers'}!=1){
	  if(!ref($$hout{$a})){
	    my $temp=$$hout{$a};
	    delete $$hout{$a};
	    push(@{$$hout{$a}},$temp);
	  }
	  push(@{$$hout{$a}},$b);
	} else {
	  $$hout{$a}=$b;
  }	}

  # did we have a socket error?
  if($!){
	$hout{'whisker'}->{'error'}='Error in reading response/headers';
	sock_close($$Z[0],$$Z[4]); $$Z[1]=0; return 1; }

  if( $CO eq '' ){ # do whatever the client wanted
	$CO = (defined $$hin{'Connection'}) ? lc($$hin{'Connection'}) : 
		'close'; }

 } while($$hout{'whisker'}->{'http_resp'}==100);

} else { # http ver 0.9, we need to fake it
 # Keep in mind lame broken servers, like IIS, still send headers for 
 # 0.9 requests; the headers are treated as data.  Also keep in mind
 # that if the server doesn't support HTTP 0.9 requests, it will spit
 # back an HTTP 1.0 response header.  User is responsible for figuring
 # this out himself.
 $$hout{'whisker'}->{'http_ver'}='0.9';
 $$hout{'whisker'}->{'http_resp'}='200';
 $$hout{'whisker'}->{'http_resp_message'}='';
}

 if($$W{'force_bodysnatch'} || ( $$W{'method'} ne 'HEAD' && 
	$$hout{'whisker'}->{'http_resp'}!=206 &&
	$$hout{'whisker'}->{'http_resp'}!=102)){
  if ($TE eq 'chunked') { 
	if(!defined ($a=sock_getline($$Z[0],$$Z[4]))){
		$$hout{'whisker'}->{'error'}='Error reading chunked data length';
		sock_close($$Z[0],$$Z[4]); $$Z[1]=0; return 1;}
	$a=~tr/a-fA-F0-9//cd; $CL=hex($a); 
	$$hout{'whisker'}->{'data'}='';
	while($CL!=0) { # chunked sucks
		if(!defined ($temp=sock_get($$Z[0],$$Z[4],$CL))){
			$$hout{'whisker'}->{'error'}="Error reading chunked data: $!";
			sock_close($$Z[0],$$Z[4]); $$Z[1]=0; return 1;}
		$$hout{'whisker'}->{'data'}=$$hout{'whisker'}->{'data'} . $temp;
		$temp=sock_getline($$Z[0], $$Z[4]);
		($temp=sock_getline($$Z[0], $$Z[4])) if(defined $temp &&
			$temp=~/^[\r\n]*$/);
		if(!defined $temp){ # this will catch errors in either sock_getline
			$$hout{'whisker'}->{'error'}="Error reading chunked data: $!";
			sock_close($$Z[0],$$Z[4]); $$Z[1]=0; return 1;}
		$temp=~tr/a-fA-F0-9//cd; $CL=hex($temp);}
	# read in trailer headers
	while(defined ($_=sock_getline($$Z[0],$$Z[4]))){ tr/\r\n//d; last if($_ eq ''); }
	# Hmmmm...error, but we should have full body.  Don't return error
	if($!){ $$Z[1]=0; sock_close($$Z[0],$$Z[4]); }
  } else {
 	if ($CL != -1) {
		if(!defined ($temp=sock_get($$Z[0],$$Z[4],$CL))){
			$$hout{'whisker'}->{'error'}="Error reading data: $!";
			sock_close($$Z[0],$$Z[4]); $$Z[1]=0; return 1;}
	} else {  # Yuck...read until server stops sending....
		$temp=sock_getall($$Z[0],$$Z[4]);
		# we go until we puke, so close socket and don't return error
		sock_close($$Z[0],$$Z[4]); $$Z[1]=0;
	}
	$$hout{'whisker'}->{'data'}=$temp; 
  }
 } # /method ne HEAD && http_resp ne 206 or 102/

 if(($CO ne 'keep-alive' || ( defined $$hin{'Connection'} &&
		lc($$hin{'Connection'}) eq 'close')) && $$W{'force_open'}!=1){
	$$Z[1]=0; sock_close($$Z[0],$$Z[4]); 
 }	 

 # this way we know what the state *would* have been...
 $$hout{'whisker'}->{'sockstate'}=$$Z[1];
 if($$W{'force_close'}>0) {
	$$Z[1]=0; sock_close($$Z[0],$$Z[4]); } 

 if($$W{'ssl'}>0){ # we don't reuse SSL sockets
	$$Z[1]=0; sock_close($$Z[0],$$Z[4]); }

 $$hout{'whisker'}->{'stats_reqs'}=$$Z[8];
 $$hout{'whisker'}->{'stats_syns'}=$$Z[7];
 $$hout{'whisker'}->{'error'}=''; # no errors
 return 0;
}




sub http_req2line {
 my ($S,$hin,$UO)=('',@_);
 $UO||=0; # shut up -w warning

 # notice: full_request_override can play havoc with proxy settings
 if(defined $$hin{'whisker'}->{'full_request_override'}){
	return $$hin{'whisker'}->{'full_request_override'};

 } else { # notice the components of a request--this is for flexibility

	if($UO!=1){$S.= 	$$hin{'whisker'}->{'method'}.
				$$hin{'whisker'}->{'method_postfix'}.
				$$hin{'whisker'}->{'req_spacer'};
	
		if($$hin{'whisker'}->{'include_host_in_uri'}>0){
			$S.=	'http://';

			if(defined $$hin{'whisker'}->{'uri_user'}){
			$S.=	$$hin{'whisker'}->{'uri_user'};
			if(defined $$hin{'whisker'}->{'uri_password'}){
				$S.=	':'.$$hin{'whisker'}->{'uri_user'};
			}
			$S.=	'@';
			}

			$S.=	$$hin{'whisker'}->{'host'}.
				':'.$$hin{'whisker'}->{'port'};}}

	$S.=	$$hin{'whisker'}->{'uri_prefix'}.
		$$hin{'whisker'}->{'uri'}.
		$$hin{'whisker'}->{'uri_postfix'};

	if(defined $$hin{'whisker'}->{'uri_param'}){
		$S.= 	$$hin{'whisker'}->{'uri_param_sep'}.
			$$hin{'whisker'}->{'uri_param'};}

	if($UO!=1){  if($$hin{'whisker'}->{'http_ver'} ne '0.9'){
			$S.= 	$$hin{'whisker'}->{'req_spacer2'}.'HTTP/'.
				$$hin{'whisker'}->{'http_ver'}.
				$$hin{'whisker'}->{'http_req_trailer'};}
			$S.=	$$hin{'whisker'}->{'http_eol'};}}
 return $S;}





sub sock_close {
	my ($fd,$ssl)=@_;

	eval { close($fd); };
	if(defined $ssl){
	    if($LW::LW_SSL_LIB==1){ # Net::SSLeay
		eval "&Net::SSLeay::free($ssl)";
#		eval "&Net::SSLeay::CTX_free($$Z[3])";
	    } else { # Net::SSL
		eval { close($ssl) }; # is that right for Net::SSL?
	    }
	}

	$$Z[4]=undef;
}



sub sock_valid {
	my ($z,$Hin,$Hout)=@_;

	my $slurp=$$Hin{'whisker'}->{'trailing_slurp'};
	my ($o,$vin)=(undef,'');

	return 0 if(defined $$z[3]); # we don't do SSL yet

	# closed socket sets read flag (and so does waiting data)
 	vec($vin,fileno($$z[0]),1)=1;
 	if(select(($o=$vin),undef,undef,.01)){ # we have data to read
		my ($hold, $res);

		do {
			$res = sysread($$z[0], $hold, 4096);
			$$z[6].=$hold if($slurp==0); # save to queue
			$$Hout{'whisker'}->{'slurped'}.="$hold\0"
				if($slurp==1); # save to hout hash
			# fall through value of 2 doesn't do anything
		} while ($res && select(($o=$vin),undef,undef,.01));

		if(!defined $res || $res==0){ # error or EOF
			return 0;
		}
	}
    
	return 1;
}



sub sock_getline { # read from socket w/ timeouts
        my ($fd,$ssl) = @_;
        my ($str,$t)=('','');

        $t = index($$Z[6],"\n",0);

        while($t < 0){
                return undef if &http_queue_read($fd,$ssl);
                $t=index($$Z[6],"\n",0);
        }

	# MEMLEAK: use following lines; comment out SPEEDUP and LEGACY lines
	# my $r;
	# ($r,$$Z[6])=unpack('A'.($t+1).'A*',$$Z[6]);
	# return $r;

	# SPEEDUP: use following line; comment out MEMLEAK and LEGACY lines
	# return substr($$Z[6],0,$t+1,'');

	# LEGACY: use following lines; comment out MEMLEAK and SPEEDUP lines
	my $r = substr($$Z[6],0,$t+1);
	substr($$Z[6],0,$t+1)='';
	return $r;
}



sub sock_get { # read from socket w/ timeouts
        my ($fd,$ssl,$amount) = @_;
        my ($str,$t)=('','');

	while($amount > length($$Z[6])){
                return undef if &http_queue_read($fd,$ssl);
	}

	# MEMLEAK: use following lines; comment out SPEEDUP and LEGACY lines
	# my $r;
	# ($r,$$Z[6])=unpack('A'.$amount.'A*',$$Z[6]);
	# return $r;

	# SPEEDUP: use following line; comment out MEMLEAK and LEGACY lines
	# return substr($$Z[6],0,$amount,'');

	# LEGACY: use following lines; comment out MEMLEAK and SPEEDUP lines
	my $r = substr($$Z[6],0,$amount);
	substr($$Z[6],0,$amount)='';
	return $r;
}



sub sock_getall {
        my ($fd,$ssl) = @_;
        1 while( !(&http_queue_read($fd,$ssl)) );
        return $$Z[6];
}



sub http_queue_read {
	my ($fd,$ssl)=@_;
	my ($vin, $t)=('','');

	if(defined $ssl){
	    if($LW::LW_SSL_LIB==1){ # Net::SSLeay
		local $SIG{ALRM} = sub { die "timeout\n" };
		local $SIG{PIPE} = sub { die "pipe_error\n" };
		eval {
			eval { alarm($TIMEOUT); };
			$t=Net::SSLeay::read($ssl);
			eval { alarm(0); };
		};
        	if($@ || !defined $t || $t eq ''){
			return 1;}
		$$Z[6].=$t;
	    } else { # Net::SSL
		if(!$ssl->read($t,1024)){ return 1;
		} else { $$Z[6].=$t;}
	    }
	} else {
		vec($vin,fileno($fd),1)=1; # wait only so long to read...
		if(!select($vin,undef,undef,$TIMEOUT)){
			return 1;}
               	if(!sysread($fd,$t,4096)){	return 1; # EOF or error
		} else {			$$Z[6].=$t;}
	}

	return 0;
}



sub http_queue_send { # write to socket
	my ($fd,$ssl)=@_;
	my ($v,$wrote,$err)=('');

	my $len = length($$Z[5]);
	if(defined $ssl){
	    if($LW::LW_SSL_LIB==1){ # Net::SSLeay
		($wrote,$err)=Net::SSLeay::ssl_write_all($ssl,$$Z[5]);
		return 'Could not send entire data queue' if ($wrote!=$len);
		return "SSL_write error: $err" unless $wrote;
	    } else { # Net::SSL
		$ssl->print($$Z[5]);
	    }
	} else {
        	vec($v,fileno($fd),1)=1;
 		if(!select(undef,$v,undef,.01)){ 
			return 'Socket write test failed'; }
		$wrote=syswrite($fd,$$Z[5],length($$Z[5]));
		return "Error sending data queue: $!" if(!defined $wrote);
		return 'Could not send entire data queue' if ($wrote != $len);
	}
	$$Z[5]=''; return undef;
}




sub http_queue {
	$$Z[5].= shift;
}




sub http_fixup_request {
 my $hin=shift;

 return if(!(defined $hin && ref($hin)));

 if($$hin{'whisker'}->{'http_ver'} eq '1.1'){
 	$$hin{'Host'}=$$hin{'whisker'}->{'host'} if(!defined $$hin{'Host'});
	$$hin{'Connection'}='Keep-Alive' if(!defined $$hin{'Connection'});
 }

 if(defined $$hin{'whisker'}->{'data'}){ 
 	if(!defined $$hin{'Content-Length'}){
		$$hin{'Content-Length'}=length($$hin{'whisker'}->{'data'});}
#	if(!defined $$hin{'Content-Encoding'}){
#		$$hin{'Content-Encoding'}='application/x-www-form-urlencoded';}
 }

 if(defined $$hin{'whisker'}->{'proxy_host'}){
	$$hin{'whisker'}->{'include_host_in_uri'}=1;}

}



sub http_reset {
 my $key;

 foreach $key (keys %http_host_cache){
 	# *Z=$http_host_cache{$key};
	sock_close($http_host_cache{$key}->[0],
			$http_host_cache{$key}->[4]);
	my $x=$http_host_cache{$key}->[3];
	if(defined $x && $LW::LW_SSL_LIB==1){
		eval "Net::SSLeay::CTX_free($x)"; }
	delete $http_host_cache{$key};
 }
}



sub ssl_save_info {
	my ($hr,$SSL)=@_;
	my $cert;

	return if($LW::LW_SSL_LIB!=1); # only Net::SSLeay used
	$$hr{'whisker'}->{'ssl_cipher'}=Net::SSLeay::get_cipher($SSL);		

	if( $cert = Net::SSLeay::get_peer_certificate($SSL)){
		$$hr{'whisker'}->{'ssl_cert_subject'} = 
			Net::SSLeay::X509_NAME_oneline(
                    	Net::SSLeay::X509_get_subject_name($cert) );

		$$hr{'whisker'}->{'ssl_cert_issuer'} = 
			Net::SSLeay::X509_NAME_oneline(
                    	Net::SSLeay::X509_get_issuer_name($cert) );
	}
}




{ # start md5 packaged varbs
my (@S,@T,@M);
my $code='';


sub md5 {
	return undef if(!defined $_[0]); # oops, forgot the data
	return MD5->hexhash($_[0]) if(defined $LW::available{'md5'});
	return md5_perl($_[0]);
}



sub md5_perl {
        my $DATA=shift;
        $DATA=md5_pad($DATA);
        &md5_init() if(!defined $M[0]);
        return md5_perl_generated(\$DATA);
}



sub md5_init {
        return if(defined $S[0]);
        for(my $i=1; $i<=64; $i++){ $T[$i-1]=int((2**32)*abs(sin($i))); }
        my @t=(7,12,17,22,5,9,14,20,4,11,16,23,6,10,15,21);
        for($i=0; $i<64; $i++){  $S[$i]=$t[(int($i/16)*4)+($i%4)]; }
        @M=(    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
                1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12,
                5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2,
                0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9 );
        &md5_generate();

	# check to see if it works correctly
	my $TEST=md5_pad('foobar');
	if( md5_perl_generated(\$TEST) ne 
		'3858f62230ac3c915f300c664312c63f'){
		die('Error: MD5 self-test not successful.');
	}
}



sub md5_pad {
	my $l = length(my $msg=shift() . chr(128));
	$ msg .= "\0" x (($l%64<=56?56:120)-$l%64);
	$l=($l-1)*8;
	$msg .= pack 'VV',$l & 0xffffffff, ($l >> 16 >> 16);
	return $msg;
}



sub md5_generate {
 my $N='abcddabccdabbcda';
 my $M='';
 $M='&0xffffffff' if((1 << 16) << 16); # mask for 64bit systems

 $code=<<EOT;
        sub md5_perl_generated {
	BEGIN { \$^H |= 1; }; # use integer
        my (\$A,\$B,\$C,\$D)=(0x67452301,0xefcdab89,0x98badcfe,0x10325476);
        my (\$a,\$b,\$c,\$d,\$t,\$i);
        my \$dr=shift;
        my \$l=length(\$\$dr);
        for my \$L (0 .. ((\$l/64)-1) ) {
                my \@D = unpack('V16', substr(\$\$dr, \$L*64,64));
                (\$a,\$b,\$c,\$d)=(\$A,\$B,\$C,\$D);
EOT

 for($i=0; $i<16; $i++){
        my ($a,$b,$c,$d)=split('',substr($N,($i%4)*4,4));
        $code.="\$t=((\$$d^(\$$b\&(\$$c^\$$d)))+\$$a+\$D[$M[$i]]+$T[$i])$M;\n";
        $code.="\$$a=(((\$t<<$S[$i])|((\$t>>(32-$S[$i]))&((1<<$S[$i])-1)))+\$$b)$M;\n";
 }
 for(; $i<32; $i++){
        my ($a,$b,$c,$d)=split('',substr($N,($i%4)*4,4));
        $code.="\$t=((\$$c^(\$$d\&(\$$b^\$$c)))+\$$a+\$D[$M[$i]]+$T[$i])$M;\n";
        $code.="\$$a=(((\$t<<$S[$i])|((\$t>>(32-$S[$i]))&((1<<$S[$i])-1)))+\$$b)$M;\n";
 }
 for(; $i<48; $i++){
        my ($a,$b,$c,$d)=split('',substr($N,($i%4)*4,4));
        $code.="\$t=((\$$b^\$$c^\$$d)+\$$a+\$D[$M[$i]]+$T[$i])$M;\n";
        $code.="\$$a=(((\$t<<$S[$i])|((\$t>>(32-$S[$i]))&((1<<$S[$i])-1)))+\$$b)$M;\n";
 }
 for(; $i<64; $i++){
        my ($a,$b,$c,$d)=split('',substr($N,($i%4)*4,4));
        $code.="\$t=((\$$c^(\$$b|(~\$$d)))+\$$a+\$D[$M[$i]]+$T[$i])$M;\n";
        $code.="\$$a=(((\$t<<$S[$i])|((\$t>>(32-$S[$i]))&((1<<$S[$i])-1)))+\$$b)$M;\n";
 }

 $code.=<<EOT;
                \$A=\$A+\$a\&0xffffffff; \$B=\$B+\$b\&0xffffffff;
                \$C=\$C+\$c\&0xffffffff; \$D=\$D+\$d\&0xffffffff;
        } # for
	return unpack('H*', pack('V4',\$A,\$B,\$C,\$D)); }
EOT
 eval "$code";
}

} # md5 package container


{ # start md4 packaged varbs
my (@S,@T,@M);
my $code='';


sub md4 {
	return undef if(!defined $_[0]); # oops, forgot the data
	md4_perl(@_);
}



sub md4_perl {
        my $DATA=shift;
        $DATA=md5_pad($DATA);
        &md4_init() if(!defined $M[0]);
        return md4_perl_generated(\$DATA);
}



sub md4_init {
 return if(defined $S[0]);
 my @t=(3,7,11,19,3,5,9,13,3,9,11,15);
 for($i=0; $i<48; $i++){  $S[$i]=$t[(int($i/16)*4)+($i%4)]; }
 @M=(	0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
	0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15,
	0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15 );

 my $N='abcddabccdabbcda';
 my $M='';
 $M='&0xffffffff' if((1 << 16) << 16); # mask for 64bit systems

 $code=<<EOT;
        sub md4_perl_generated {
	BEGIN { \$^H |= 1; }; # use integer
        my (\$A,\$B,\$C,\$D)=(0x67452301,0xefcdab89,0x98badcfe,0x10325476);
        my (\$a,\$b,\$c,\$d,\$t,\$i);
        my \$dr=shift;
        my \$l=length(\$\$dr);
        for my \$L (0 .. ((\$l/64)-1) ) {
                my \@D = unpack('V16', substr(\$\$dr, \$L*64,64));
                (\$a,\$b,\$c,\$d)=(\$A,\$B,\$C,\$D);
EOT
 
 for($i=0; $i<16; $i++){
        my ($a,$b,$c,$d)=split('',substr($N,($i%4)*4,4));
	$code.="\$t=((\$$d^(\$$b\&(\$$c^\$$d)))+\$$a+\$D[$M[$i]])$M;\n";
        $code.="\$$a=(((\$t<<$S[$i])|((\$t>>(32-$S[$i]))&((1<<$S[$i])-1))))$M;\n";
 }
 for(; $i<32; $i++){
        my ($a,$b,$c,$d)=split('',substr($N,($i%4)*4,4));
 	$code.="\$t=(( (\$$b&\$$c)|(\$$b&\$$d)|(\$$c&\$$d) )+\$$a+\$D[$M[$i]]+0x5a827999)$M;\n";
        $code.="\$$a=(((\$t<<$S[$i])|((\$t>>(32-$S[$i]))&((1<<$S[$i])-1))))$M;\n";
 }
 for(; $i<48; $i++){
        my ($a,$b,$c,$d)=split('',substr($N,($i%4)*4,4));
 	$code.="\$t=(( \$$b^\$$c^\$$d )+\$$a+\$D[$M[$i]]+0x6ed9eba1)$M;\n";
        $code.="\$$a=(((\$t<<$S[$i])|((\$t>>(32-$S[$i]))&((1<<$S[$i])-1))))$M;\n";
 }
 
 $code.=<<EOT;
                \$A=\$A+\$a\&0xffffffff; \$B=\$B+\$b\&0xffffffff;
                \$C=\$C+\$c\&0xffffffff; \$D=\$D+\$d\&0xffffffff;
        } # for
	return unpack('H*', pack('V4',\$A,\$B,\$C,\$D)); }
EOT
 eval "$code";

 my $TEST=md5_pad('foobar');
 if( md4_perl_generated(\$TEST) ne 
	'547aefd231dcbaac398625718336f143'){
	die('Error: MD4 self-test not successful.');
 }
}

} # md4 package container





sub multipart_set {
	my ($hr,$n,$v)=@_;
	return if(!ref($hr)); # error check
	return undef if(!defined $n || $n eq '');
	$$hr{$n}=$v;	
}



sub multipart_get {
	my ($hr,$n)=@_;
	return undef if(!ref($hr)); # error check
	return undef if(!defined $n || $n eq '');
	return $$hr{$n};
}



sub multipart_setfile {
	my ($hr,$n,$path)=(shift,shift,shift);
	my ($fname)=shift;

	return undef if(!ref($hr)); # error check
	return undef if(!defined $n || $n eq '');
	return undef if(!defined $path);
	return undef if(! (-e $path && -f $path) );

	if(!defined $fname){
		$path=~m/[\\\/]([^\\\/]+)$/;
		$fname=$1||"whisker-file";
	}

	$$hr{$n}="\0FILE";
	$$hr{"\0$n"}=[$path,$fname];
	return 1;
}



sub multipart_getfile {
	my ($hr,$n)=@_;

	return undef if(!ref($hr)); # error check
	return undef if(!defined $n || $n eq '');
	return undef if(!defined $$hr{$n} || $$hr{$n} ne "\0FILE");

	return @{$$hr{"\0$n"}};
}



sub multipart_boundary {
	my ($hr,$new)=@_;
	my $ret;

	return undef if(!ref($hr)); # error check

	if(!defined $$hr{"\0BOUNDARY"}){
		# create boundary on the fly
		my $b = uc(LW::utils_randstr(20));
		my $b2 = '-' x 32;
		$$hr{"\0BOUNDARY"}="$b2$b";
	}

	$ret=$$hr{"\0BOUNDARY"};
	if(defined $new){
		$$hr{"\0BOUNDARY"}=$new;
	}

	return $ret;
}



sub multipart_write {
	my ($mp,$hr)=@_;

	return undef if(!ref($mp)); # error check
	return undef if(!ref($hr)); # error check

	if(!defined $$mp{"\0BOUNDARY"}){
		# create boundary on the fly
		my $b = uc(LW::utils_randstr(20));
		my $b2 = '-' x 32;
		$$mp{"\0BOUNDARY"}="$b2$b";
	}

	my $B = $$mp{"\0BOUNDARY"};
	my $EOL = $$hr{whisker}->{http_eol}||"\x0d\x0a";

	my $keycount=0;
	foreach (keys %$mp){
		next if(substr($_,0,1) eq "\0");
		$keycount++;
		if($$mp{$_} eq "\0FILE"){
			my ($path,$name)=LW::multipart_getfile($mp,$_);
			next if(!defined $path);
			$$hr{whisker}->{data}.="$B$EOL";
			$$hr{whisker}->{data}.="Content-Disposition: ".
				"form-data; name=\"$_\"; ";
			$$hr{whisker}->{data}.="filename=\"$name\"$EOL";
			$$hr{whisker}->{data}.="Content-Type: ".
				"application/octet-stream$EOL";
			$$hr{whisker}->{data}.=$EOL;
			next if(!open(IN,"<$path"));
			binmode(IN); # stupid Windows
			while(<IN>){
				$$hr{whisker}->{data}.=$_; }
			close(IN);
			$$hr{whisker}->{data}.=$EOL;  # WARNING: is this right? 
		} else {
			$$hr{whisker}->{data}.="$B$EOL";
			$$hr{whisker}->{data}.="Content-Disposition: ".
				"form-data; name=\"$_\"$EOL";
			$$hr{whisker}->{data}.="$EOL$$mp{$_}$EOL";
		}
	}

	if($keycount){
		$$hr{whisker}->{data}.="$B--$EOL"; # closing boundary
		$$hr{"Content-Length"}=length($$hr{whisker}->{data});
		$$hr{"Content-Type"}="multipart/form-data; boundary=$B";
		return 1;
	} else {
		# multipart hash didn't contain params to upload
		return undef;
	}
}




sub multipart_read {
	my ($mp, $hr, $fp)=@_;

	return undef if(!(defined $mp && ref($mp)));
	return undef if(!(defined $hr && ref($hr)));

	my $ctype = LW::utils_find_lowercase_key($hr,'content-type');
	return undef if(!defined $ctype);
	return undef if($ctype!~m#^multipart/form-data#i);

	return LW::multipart_read_data($mp,
		\${$hr{'whisker'}->{'data'}},undef,$fp);

}



sub multipart_read_data {
	my ($mp, $dr, $bound, $fp)=@_;

	return undef if(!(defined $mp && ref($mp)));
	return undef if(!(defined $dr && ref($dr)));

	# if $bound is undef, then we'll snag what looks to be
	# the first boundry from the data.
	if(!defined $bound){
		if($$dr=~/([-]{5,}[A-Z0-9]+)[\r\n]/i){
			$bound=$1;
		} else {
			# we didn't spot a typical boundary; error
			return undef;
		}
	}

	if(defined $fp && !(-d $fp && -w $fp)){
		$fp=undef; }

	my $line = LW::utils_getline_crlf($dr,0);
	return undef if(!defined $line);
	return undef if( index($line,$bound) != 0);

	my $done=0;
	while(!$done){
		$done=multipart_read_data_part($mp, $dr, $bound, $fp);
	}

	return 1;
}



sub multipart_read_data_part {
	my ($mp, $dr, $bound, $fp)=@_;

	my $dispinfo = LW::utils_getline_crlf($dr);
	return 1 if(!defined $dispinfo);
	return 1 if(length($dispinfo)==0);
	my $lcdisp = lc($dispinfo);

	if(index($lcdisp,'content-disposition: form-data;') != 0){
		return 1; } # bad disposition

	my ($s,$e,$l);

	$s=index($lcdisp,'name="',30);
	$e=index($lcdisp, '"', $s+6);
	return 1 if($s == -1 || $e == -1);	
	my $NAME=substr($dispinfo,$s+6,$e-$s-6);

	$s=index($lcdisp,'filename="',$e);
	my $FILENAME=undef;
	if($s != -1){
		$e=index($lcdisp, '"', $s+10);
		return 1 if($e == -1); # puke; malformed filename
		$FILENAME=substr($dispinfo,$s+10,$e-$s-10);
		$s=rindex($FILENAME,'\\');
		$e=rindex($FILENAME,'/');
		$s=$e if($e>$s);
		$FILENAME=substr($FILENAME,$s+1,length($FILENAME)-$s);
	}

	my $CTYPE = LW::utils_getline_crlf($dr);

	return 1 if(!defined $CTYPE);
	$CTYPE = lc($CTYPE);

	if(length($CTYPE)>0){
		$s=index($CTYPE,'content-type:');
		return 1 if($s!=0); # bad ctype line
		$CTYPE=substr($CTYPE,13,length($CTYPE)-13);
		$CTYPE=~tr/ \t//d;
		my $xx=LW::utils_getline_crlf($dr);
		return 1 if(!defined $xx);
		return 1 if(length($xx)>0);
	} else {
		$CTYPE='application/octet-stream';
	}


	my $VALUE='';
	while( defined ($l=LW::utils_getline_crlf($dr)) ){
		last if(index($l,$bound)==0);	
		$VALUE.=$l;
		$VALUE.="\r\n";
	}

	substr($VALUE,-2,2)='';

	if(!defined $FILENAME){ # read in param
		$$mp{$NAME}=$VALUE;
		return 0;

	} else {  # read in file
		$$mp{$NAME}="\0FILE";
		return 0 if(!defined $fp);

		# TODO: funky content types, like application/x-macbinary
		if($CTYPE ne 'application/octet-stream'){
			return 0; }

		my $rfn = lc(LW::utils_randstr(12));
		my $fullpath = "$fp$rfn";

		$$mp{"\0$NAME"}=[undef,$FILENAME];
		return 0 if(!open(OUT,">$fullpath")); # error opening file
		binmode(OUT); # stupid Windows
		$$mp{"\0$NAME"}=[$fullpath,$FILENAME];
		print OUT $VALUE;
		close(OUT);

		return 0;

	} # if !defined $FILENAME

	return 0; # um, this should never be reached...
}




sub multipart_files_list {
	my ($mp)=shift;
	my @ret;

	return () if(!(defined $mp && ref($mp)));
	while( my ($K, $V)=each(%$mp)){
		push(@ret,$K) if($V eq "\0FILE"); }
	return @ret;
}




sub multipart_params_list {
	my ($mp)=shift;
	my @ret;

	return () if(!(defined $mp && ref($mp)));
	while( my ($K, $V)=each(%$mp)){
		push(@ret,$K) if($V ne "\0FILE" &&
			substr($K,0,1) ne "\0" ); 
	}
	return @ret;
}






sub ntlm_new {
	my ($user,$pass,$domain,$flag)=@_; 
	$flag||=0;
	return undef if(!defined $user);
	$pass||=''; $domain||='';
	my @a=("$user","$pass","$domain",undef,undef);
	my $t;

	if($flag==0){
		$t=substr($pass,0,14);
		$t=~tr/a-z/A-Z/;
		$t.= "\0"x(14-length($t));
		$a[3]=des_E_P16($t); # LanMan password hash
		$a[3].= "\0"x(21-length($a[3]));
	}

	$t=md4(encode_unicode($pass));
	$t=~s/([a-z0-9]{2})/sprintf("%c",hex($1))/ieg;
	$t.="\0"x(21-length($t));
	$a[4]=$t; # NTLM password hash

	&des_cache_reset(); # reset the keys hash
	return \@a;
}



sub ntlm_generate_responses {
	my ($obj,$chal)=@_;
	return (undef,undef) if(!defined $obj || !defined $chal);
	return (undef,undef) if(!ref($obj));
	my $x='';
	$x=des_E_P24($obj->[3], $chal) if(defined $obj->[3]);
	return ($x, des_E_P24($obj->[4], $chal));
}



sub ntlm_decode_challenge {
  return undef if(!defined $_[0]);
  my $chal=shift;
  my @res;

  @res=unpack('Z8VvvVVa8a8a8',substr($chal,0,48));
  push(@res,substr($chal,48));
  unshift(@res,substr($chal,$res[4],$res[2]));
  return @res;
}



sub ntlm_header {
	my ($s,$h,$o)=@_;
	my $l=length($s);
	return pack('vvV',0,0,$o-$h) if($l==0);
	return pack('vvV',$l,$l,$o);
}



sub ntlm_client {
	my ($obj,$p)=@_;
	my $resp="NTLMSSP\0";

	return undef if(!defined $obj || !ref($obj));

	if(defined $p && $p ne ''){ # answer challenge
		$p=~tr/ \t\r\n//d;
		$p=LW::decode_base64($p);
		my @c=ntlm_decode_challenge($p);
		$uu=encode_unicode($obj->[0]); # username
		$resp.=pack('V',3);
		my($hl,$hn)=ntlm_generate_responses($obj,$c[7]); # token
		return undef if(!defined $hl || !defined $hn);
		my $o=64;
		$resp.=ntlm_header($hl,64,$o);			# LM hash
		$resp.=ntlm_header($hn,64,($o+=length($hl)));	# NTLM hash
		$resp.=ntlm_header($c[0],64,($o+=length($hn)));	# domain
		$resp.=ntlm_header($uu,64,($o+=length($c[0])));	# username
		$resp.=ntlm_header($uu,64,($o+=length($uu))); 	# workstation
		$resp.=ntlm_header('',64,($o+=length($uu)));	# session
		$resp.=pack('V',$c[6]);
		$resp.=$hl.$hn.$c[0].$uu.$uu;

	} else { # initiate challenge
		$resp.=pack('VV',1,0x0000b207);
		$resp.=ntlm_header($obj->[0],32,32);
		$resp.=ntlm_header($obj->[2],32,32+length($obj->[0]));
		$resp .= $obj->[0].$obj->[2];
	}

	return encode_base64($resp,'');
}



{ # start of DES local container #######################################
my $generated=0;
my $perm1 = [57, 49, 41, 33, 25, 17, 9,	1, 58, 50, 42, 34, 26, 18,
	     10, 2, 59, 51, 43, 35, 27,	19, 11, 3, 60, 52, 44, 36,
	     63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
	     14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4];
my $perm2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
	     23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
	     41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	     44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32];
my $perm3 = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	     62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	     57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	     61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7];
my $perm4 = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
	     8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
	     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
	     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];
my $perm5 = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
	     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25];
my $perm6 = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
	     38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
	     36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
	     34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25];
my $sc = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

sub des_E_P16 {
  my ($p14) = @_;
  my $sp8 = [0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25];
  my $p7 = substr($p14, 0, 7);
  my $p16 = des_smbhash($sp8, $p7);
  $p7 = substr($p14, 7, 7);
  $p16 .= des_smbhash($sp8, $p7);
  return $p16;
}

sub des_E_P24 {
  my ($p21, $c8_str) = @_;
  my @c8 = map {ord($_)} split(//, $c8_str);
  my $p24 = des_smbhash(\@c8, substr($p21, 0, 7));
  $p24 .= des_smbhash(\@c8, substr($p21, 7, 7));
  $p24 .= des_smbhash(\@c8, substr($p21, 14, 7));
}

sub des_permute {
  my ($i,$out, $in, $p, $n) = (0,@_);
  foreach $i (0..($n-1)){
    $out->[$i] = $in->[$p->[$i]-1]; }
}

sub des_lshift {
	my ($c, $d, $count)=@_;
	my (@outc, @outd, $i, $x);
	while($count--){
		push @$c, shift @$c;
		push @$d, shift @$d;
	}
}

my %dohash_cache; # cache for key data; saves some cycles
my %key_cache;	  # another cache for key data
sub des_cache_reset {
	%dohash_cache=();
	%key_cache=();
}

sub des_dohash
{
  my ($out, $in, $key) = @_;
  my ($i, $j, $k, @pk1, @c, @d, @cd,
      @ki, @pd1, @l, @r, @rl);

# if(!defined $dohash_cache{$skey}){
  &des_permute(\@pk1, $key, $perm1, 56);

  for($i=0;$i<28;$i++) {
    $c[$i] = $pk1[$i];
    $d[$i] = $pk1[$i+28];
  }
  for($i=0;$i<16;$i++){
    my @array;
    &des_lshift(\@c,\@d,$sc->[$i]);
    @cd = (@c, @d);
    &des_permute(\@array, \@cd, $perm2, 48);
    $ki[$i] = \@array;
#    $dohash_cache{$skey}->[$i]=\@array; 
  }
# } else {
#	for($i=0;$i<16;$i++){
#		$ki[$i]=$dohash_cache{$skey}->[$i];}
# }

  des_dohash2($in,\@l,\@r,\@ki);

  @rl = (@r, @l);
  &des_permute($out, \@rl, $perm6, 64);
}

sub des_str_to_key{
  my ($str) = @_;
  my ($i,@key,$out);
  unshift(@str,ord($_))while($_=chop($str));
  $key[0] = $str[0]>>1;
  $key[1] = (($str[0]&0x01)<<6) | ($str[1]>>2);
  $key[2] = (($str[1]&0x03)<<5) | ($str[2]>>3);
  $key[3] = (($str[2]&0x07)<<4) | ($str[3]>>4);
  $key[4] = (($str[3]&0x0f)<<3) | ($str[4]>>5);
  $key[5] = (($str[4]&0x1f)<<2) | ($str[5]>>6);
  $key[6] = (($str[5]&0x3f)<<1) | ($str[6]>>7);
  $key[7] = $str[6]&0x7f;
  foreach $i (0..7) {
    $key[$i] = 0xff&($key[$i]<<1); }
  @{$key_cache{$str}}=@key;
  return \@key;
}

sub des_smbhash
{
  # use faster binary helper
  goto &LW::bin::des_smbhash if(defined $LW::available{'lw::bin'});

  my ($in, $key) = @_;
  my $key2;

  &des_generate if(!$generated);
  if(defined $key_cache{$key}){	$key2=$key_cache{$key};
  } else {			$key2=&des_str_to_key($key); }

 my ($i, $div, $mod, @in, @outb, @inb, @keyb, @out);
  foreach $i (0..63){
    $div = int($i/8); $mod = $i%8;
    $inb[$i] = ($in->[$div] & (1<<(7-($mod))))? 1: 0;
    $keyb[$i] = ($key2->[$div] & (1<<(7-($mod))))? 1: 0;
    $outb[$i] = 0;
  }
  &des_dohash(\@outb, \@inb, \@keyb);
  foreach $i (0..7){ $out[$i] = 0; }
  foreach $i (0..63){
    $out[int($i/8)] |= (1<<(7-($i%8))) if ($outb[$i]); }
  my $out = pack("C8", @out);

  return $out;
}


sub des_generate { # really scary dragons here....this code is optimized
		   # for speed, and not readability
 my ($i,$j);
 my $code=<<EOT;
{ my \$sbox = [[
[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]
],[
[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]
],[
[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]
],[
[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]
],[
[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]
],[
[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]
],[
[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]
],[
[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
]];
EOT

 $code.='sub des_dohash2 { my ($in,$l,$r,$ki)=@_; my (@p,$i,$j,$k,$m,$n);';
 for($i=0;$i<64;$i++){
	$code.="\$p[$i] = \$in->[".($perm3->[$i]-1)."];\n"; }
 for($i=0;$i<32;$i++){
	$code.="\$l->[$i]=\$p[$i]; \$r->[$i]=\$p[".($i+32)."];\n"; }
 $code.='for($i=0;$i<16;$i++){ local (@er,@erk,@b,@cb,@pcb,@r2);';
 for($i=0;$i<48;$i++){
	$code.="\$erk[$i]=\$r->[".($perm4->[$i]-1)."]^(\$ki->[\$i]->[$i]);\n"; }
 for($i=0;$i<8;$i++){
	for($j=0;$j<6;$j++){
		$code.="\$b[$i][$j]=\$erk[".($i*6+$j)."];\n"; }}
 for($i=0;$i<8;$i++){
	$code.="\$m=(\$b[$i][0]<<1)|\$b[$i][5];";
	$code.="\$n=(\$b[$i][1]<<3)|(\$b[$i][2]<<2)|(\$b[$i][3]<<1)|\$b[$i][4];";
	for($j=0;$j<4;$j++){
		$code.="\$b[$i][$j]=(\$sbox->[$i][\$m][\$n]&".(1<<(3-$j)).")?1:0;"; }}
 for($i=0;$i<8;$i++){
	for($j=0;$j<4;$j++){
		$code.="\$cb[".($i*4+$j)."]=\$b[$i][$j];\n"; }}
 for($i=0;$i<32;$i++){
	$code.="\$pcb[$i]=\$cb[".($perm5->[$i]-1)."];\n"; }
 for($i=0;$i<32;$i++){
	$code.="\$r2[$i]=(\$l->[$i])^\$pcb[$i];\n"; }
 for($i=0;$i<32;$i++){
	$code.="\$l->[$i]=\$r->[$i]; \$r->[$i]=\$r2[$i];\n"; }
 $code.='}}}';
 
 eval "$code";
 $generated++;
}

} ##### end of DES container ################################################





# '/', 0, \@dir.split, \@valid, \&func, \%track, \%arrays, \&cfunc
sub utils_recperm {
 my ($p, $pp, $pn, $r, $fr, $dr, $ar, $cr)=(shift,shift,@_);
 $p=~s#/+#/#g; if($pp >= @$pn) { push @$r, $p if &$cr($$dr{$p});
 } else { my $c=$$pn[$pp];
  if($c!~/^\@/){ utils_recperm($p.$c.'/',$pp+1,@_) if(&$fr($p.$c.'/'));
  } else {	$c=~tr/\@//d; if(defined $$ar{$c}){
		foreach $d (@{$$ar{$c}}){
			if(&$fr($p.$d.'/')){
                  utils_recperm($p.$d.'/',$pp+1,@_);}}}}}}




sub utils_array_shuffle { # fisher yates shuffle....w00p!
        my $array=shift; my $i;
        for ($i = @$array; --$i;){
                my $j = int rand ($i+1);
                next if $i==$j;
                @$array[$i,$j]=@$array[$j,$i];
}} # end array_shuffle, from Perl Cookbook (rock!)




sub utils_randstr {
        my $str;
        my $drift=shift||((rand() * 10) % 10)+10; 

	# 'a'..'z' doesn't seem to work on string assignment :(
	my $CHARS = shift || 'abcdefghijklmnopqrstuvwxyz' .
			'ABCDEFGHIJKLMNOPQRSTUVWXYZ' .
			'0123456789';

	my $L = length($CHARS);
        for(1..$drift){
	        $str .= substr($CHARS,((rand() * $L) % $L),1);
	}
        return $str;}



sub utils_get_dir {
        my ($w,$URL)=(0,shift);

	return undef if(!defined $URL);

	substr($URL,$w,length($URL)-$w)='' if( ($w=index($URL,'?')) >= 0);
	substr($URL,$w,length($URL)-$w)='' if( ($w=index($URL,'#')) >= 0);

	if( ($w=rindex($URL,'/')) >= 0){
		$URL = substr($URL,0,$w+1);
	} else {
		if(substr($URL,-1,1) ne '/'){
			$URL.='/';}
	}
        return $URL; 
}




sub utils_port_open {  # this should be platform-safe
        my ($target,$port)=@_;

	return 0 if(!defined $target || !defined $port);

        if(!(socket(S,PF_INET,SOCK_STREAM,0))){ return 0;}
        if(connect(S,sockaddr_in($port,inet_aton($target)))){
                close(S); return 1;
        } else { return 0;}}




sub utils_split_uri {
	my ($uri,$work,$w)=(shift,'',0);
	my ($hr)=shift;
	my @res=(undef,'http',undef,80,undef,undef,undef,undef);

	return undef if(!defined $uri);

	# handle mailto's (people miswrite them as mailto:email@host)
	if(index($uri,'mailto:',0) == 0){
		$res[1]='mailto';
		($res[0]=$uri)=~s/^mailto:[\/]{0,2}//;
		return @res; }

	# handle absolute urls
	if(index($uri,'://',0) > 0 ){ # fastpath check
	 if($uri=~m#^([a-zA-Z]+)://([^/]*)(.*)$#){
		$res[1]=lc($1); 	# protocol
		$res[2]=$2;	    	# host
		$res[0]=$3;		# uri

		if($res[1] eq 'https') 	{ $res[3]=443; }

		while(($w=rindex($res[2],'@')) >=0){
			# SPEEDUP
			# $work=substr($res[2],0,$w,'');
			$work=substr($res[2],0,$w);
			substr($res[2],0,$w)='';
			$res[2]=~tr/@//d;
			if(($w=index($work,':',0)) >=0){
				$res[6]=substr($work,0,$w);
				$res[7]=substr($work,$w+1,length($work)-$2);
			} else {
				$res[6]=$work; }
		}
		
		# check for port in host
		if(($w=index($res[2],':',0)) >=0){
			# SPEEDUP
			# $res[3]=substr($res[2],$w,length($res[2])-$w,'');
			($res[2],$res[3])=split(':',$res[2],2);
			$res[3]=~tr/0-9//cd;
		}

		$res[3]||=80;
		
		$res[0]||='/'; # in case they left off URI or end slash

	 } else { $res[0]=$uri; }  # note that if the URL isn't formed
	} else { $res[0]=$uri; }   # perfectly, we make it all a URI  :/

	# remove fragments
	if(($w=index($res[0],'#',0)) >=0){
		# SPEEDUP
		# $res[5]=substr($res[0],$w+1,length($res[0])-$w,'');
		# $res[0]=~tr/#//d;
		($res[0],$res[5])=split('#',$res[0],2);
	}

	# remove parameters
	if(($w=index($res[0],'?',0)) >=0){
		# SPEEDUP
		# $res[4]=substr($res[0],$w+1,length($res[0])-$w,'');
		# $res[0]=~tr/?//d; 
		($res[0],$res[4])=split(/\?/,$res[0],2);
	}

	if(defined $hr && ref($hr) && ( $res[1] eq 'http' ||
			$res[1] eq 'https') ){
		if(defined $res[0]){
			$$hr{whisker}->{uri}=$res[0]; }
		if($res[1] eq 'https'){
			$$hr{whisker}->{ssl}=1; }
		if(defined $res[2]){
			$$hr{whisker}->{host}=$res[2]; }
		$$hr{whisker}->{port}=$res[3];
		if(defined $res[4]){
			$$hr{whisker}->{uri_param}=$res[4]; }
		if(defined $res[6]){
			$$hr{whisker}->{uri_user}=$res[6]; }
		if(defined $res[7]){
			$$hr{whisker}->{uri_password}=$res[7]; }
	}
		
	return @res;
}


sub utils_lowercase_headers {
	my $href=shift;

	return if(!(defined $href && ref($href)));

	while( my ($key,$val)=each %$href ){
		delete $$href{$key};
		$$href{lc($key)}=$val;
	}
}


sub utils_lowercase_hashkeys {
	goto &LW::utils_lowercase_headers;
}



sub utils_find_lowercase_key {
	my ($href,$key)=(shift,lc(shift));

	return undef if(!(defined $href && ref($href)));
	return undef if(!defined $key);	

	while( my ($k,$v)=each %$href ){
		return $v if(lc($k) eq $key);
	}
	return undef;
}



sub utils_join_uri {
	my @V=@_;
	my $URL="$V[1]://$V[2]";
	$URL .= ":$V[3]" if defined $V[3];
	$URL.=$V[0];
	$URL .= "?$V[4]" if defined $V[4];
	$URL .= "#$V[5]" if defined $V[5];
	return $URL;
}



{ $POS=0;
sub utils_getline {
	my ($dr, $rp)=@_;

	return undef if(!(defined $dr && ref($dr)));
	$POS=$rp if(defined $rp);

	my $where=index($$dr,"\n",$POS);
	return undef if($where==-1);

	my $str=substr($$dr,$POS,$where-$POS);
	$POS=$where+1;

	return $str;
}}



{ $POS=0;
sub utils_getline_crlf {
	my ($dr, $rp)=@_;

	return undef if(!(defined $dr && ref($dr)));
	$POS=$rp if(defined $rp);

	my $tpos=$POS;
	while(1){
		my $where=index($$dr,"\n",$tpos);
		return undef if($where==-1);

		if(substr($$dr,$where-1,1) eq "\r"){
			my $str=substr($$dr,$POS,$where-$POS-1);
			$POS=$where+1;
			return $str;
		} else {
			$tpos=$where+1;
		}
	}
}}



sub utils_absolute_uri {
        my ($uri, $buri, $norm)=@_;
        return undef if(!defined $uri || !defined $buri);
	return $uri if($uri=~m#^[a-zA-Z]+://#);

	if(substr($uri,0,1) eq '/'){
		if($buri=~m#^[a-zA-Z]+://#){
			my @p=utils_split_uri($buri);
			$buri="$p[1]://$p[2]";
			$buri.=":$p[3]" if($p[3]!=80);
			$buri.='/';
		} else { # ah suck, base URI isn't absolute...
			return $uri;
		}
	} else {
		$buri.='/' if($buri=~m#^[a-z]+://[^/]+$#i);
		$buri=~s#/[^/]*$#/#;
	}
	return utils_normalize_uri("$buri$uri") 
		if(defined $norm && $norm > 0);
        return $buri.$uri;
}



sub utils_normalize_uri {
	my ($host,$uri, $win)=('',@_);

	$uri=~tr#\\#/# if(defined $win && $win>0);
	if($uri=~s#^([a-z]+://[^/]+)##i){
		$host=$1; }
	return "$host/" if($uri eq '' || $uri eq '/');

	# fast path check
	$uri=~s#/\.{0,1}/#/#g; # quickie
	return "$host$uri" if(index($uri,'/.')==-1);

	my $f='';
	$f='/' if($uri=~m#/\.{1,2}$#);

	my @final=();
	my @dirs=split('/',$uri);

	foreach (@dirs){
		next if($_ eq '.');
		next if($_ eq '');
		if($_ eq '..'){
			pop(@final);
		} else {
			push(@final,$_);
	}	} 
	$f='' if(scalar @final == 0);
	return "$host/".join('/',@final).$f;
}



sub utils_save_page {
	my ($file, $hr)=@_;
	return 1 if(!ref($hr) || ref($file));
	return 0 if(!defined $$hr{'whisker'} || 
		!defined $$hr{'whisker'}->{'data'});
	open(OUT,">$file") || return 1;
	print OUT $$hr{'whisker'}->{'data'};
	close(OUT);
	return 0;
}



sub utils_getopts {
        my ($str,$ref)=@_;
        my (%O,$l);
        my @left;

        return 1 if($str=~tr/-:a-zA-Z0-9//c);

        while($str=~m/([a-z0-9]:{0,1})/ig){
                $l=$1;
                if($l=~tr/://d){        $O{$l}=1;
                } else {                $O{$l}=0; }
        }

        while($l=shift(@ARGV)){
                push(@left,$l)&&next if(substr($l,0,1) ne '-');
                push(@left,$l)&&next if($l eq '-');
                substr($l,0,1)='';
                if(length($l)!=1){
                        %$ref=();
                        return 1; }
                if($O{$l}==1){
                        my $x=shift(@ARGV);
                        $$ref{$l}=$x;
                } else { $$ref{$l}=1; }
        }

        @ARGV=@left;
        return 0;
}



sub utils_unidecode_uri {
        my $str = $_[0];
        return $str if($str!~tr/!-~//c); # fastpath
        my ($lead,$count,$idx);
        my $out='';
        my $len = length($str);
        my ($ptr,$no,$nu)=(0,0,0);

        while($ptr < $len){
                my $c=substr($str,$ptr,1);
                if( ord($c) >= 0xc0 && ord($c) <= 0xfd){
                        $count=0;
                        $c=ord($c)<<1;
                        while( ($c & 0x80) == 0x80){
                                $c<<=1;
                                last if($count++ ==4);
                        }
                        $c = ($c & 0xff);
                        for( $idx=1; $idx<$count; $idx++){
                                my $o=ord(substr($str,$ptr+$idx,1));
                                $no=1 if($o != 0x80);
                                $nu=1 if($o <0x80 || $o >0xbf);
                        }
                        my $o=ord(substr($str,$ptr+$idx,1));
                        $nu=1 if( $o < 0x80 || $o > 0xbf);
                        if($nu){
                                $out.=substr($str,$ptr++,1);
                        } else {
                                if($no){
                                        $out.="\xff"; # generic replacement char
                                } else {
                                        my $prior=ord(substr($str,$ptr+$count-1,1))<<6;
                                        $out.= pack("C", (ord(substr($str,$ptr+$count,1) )&0x7f)+$prior);
                                }
                                $ptr += $count+1;
                        }
                        $no=$nu=0;
                } else {
                        $out.=$c;
                        $ptr++;
                }
        }
        return $out;
}



sub utils_text_wrapper {
        my ($out,$w,$str,$crlf,$width)=('',0,@_);
	$crlf||="\n";	$width||=76;
        $str.=$crlf if($str!~/$crlf$/);
        return $str if(length($str)<=$width);
        while(length($str)>$width){
                my $w1=rindex($str,' ',$width);
                my $w2=rindex($str,"\t",$width);
                if($w1>$w2){ $w=$w1; } else { $w=$w2; }
                if($w==-1){	$w=$width;
	        } else {	substr($str,$w,1)=''; }
                $out.=substr($str,0,$w,'');
                $out.=$crlf;
        }
        return $out.$str;
}


1;
