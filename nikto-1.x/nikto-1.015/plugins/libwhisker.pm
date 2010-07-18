# libwhisker vpr4
# libwhisker is a collection of routines used by whisker
# THIS IS A PREVIEW RELEASE!  THAT MEANS THINGS MAY BE BROKEN!
#
# libwhisker copyright 2000,2001 rain forest puppy (rfp@wiretrip.net)
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

package lw;
$VERSION="pr4";

####### external module tests ###################################

BEGIN {

## lw module manager stuff ##

	%available=();
	$LW_HAS_SOCKET=$LW_HAS_SSL=$LW_SSL_LIB=0;

## encode subpackage ##
	eval "require MIME::Base64";
	if(!defined $INC{'MIME/Base64.pm'}){ 
        	*encode_base64 = \&encode_base64_perl; 
	        *decode_base64 = \&decode_base64_perl; 
	} else{ 
		$available{'mime::base64'}=$MIME::Base64::VERSION;
        	*encode_base64 = \&MIME::Base64::encode_base64;
        	*decode_base64 = \&MIME::Base64::decode_base64;}

## http subpackage ##
        eval "use Socket"; # do we have socket support?
        if(!defined $INC{'Socket.pm'}){ $LW_HAS_SOCKET=0; }
        else  { $LW_HAS_SOCKET=1; 
		$available{'socket'}=$Socket::VERSION;}

        eval "use Net::SSLeay"; # do we have SSL support?
        if(!defined $INC{'Net/SSLeay.pm'}){ $LW_HAS_SSL=0; }
        else  { $LW_HAS_SSL=1;
                $LW_SSL_LIB=1;
		$available{'net::ssleay'}=$Net::SSLeay::VERSION;
		Net::SSLeay::load_error_strings();
		Net::SSLeay::randomize(); # added for Nikto to stop Solaris 2.7 error
                Net::SSLeay::SSLeay_add_ssl_algorithms();}

        if(!$LW_HAS_SSL){
                eval "use Net::SSL"; # different SSL lib
                if(!defined $INC{'Net/SSL.pm'}){ $LW_HAS_SSL=0; }
                else  { $LW_HAS_SSL=1;
                        $LW_SSL_LIB=2;
			$available{'net::ssl'}=$Net::SSL::VERSION;}
        }

## binary helper ##
	eval "use lw::bin"; # do we have libwhisker binary helpers?
	if(defined $INC{'lw/bin.pm'}){
		$available{'lw::bin'}=$lw::bin::VERSION;}

}

####### package variables #######################################

## crawl subpackage ##
	%crawl_config=(		'save_cookies'	=> 0,
				'reuse_cookies'	=> 1,
				'save_offsites'	=> 0,
				'follow_moves'	=> 1,
				'url_limit'	=> 1000,
				'use_params'	=> 0,
				'params_double_record' => 0,
				'skip_ext'	=> '.gif .jpg ',
				'save_skipped'	=> 0,
				'callback'	=> 0
			);

	@crawl_urls=();;
	%crawl_server_tags=();
	%crawl_offsites=();
	@crawl_cookies=();
	%crawl_forms=();
	%crawl_temp=();

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


sub auth_brute_force {
 my ($auth_method, $hrin, $user, $pwordref)=@_;
 my ($P,%hout);
 local $_;

 map {
    ($P=$_)=~tr/\r\n//d; next if($P eq '');
    &lw::auth_set_header($auth_method,$hrin,$user,$P);
    &lw::http_do_request($hrin,\%hout);
    if($hout{'whisker'}->{'http_resp'} ne 401){
        return $P;}
 } @$pwordref;

 return '';}

sub auth_set_header {
 my ($method, $href, $user, $pass)=(lc(shift),@_);

 if($method eq 'basic'){
	$$href{'Authorization'}='Basic '.&lw::encode_base64($user.':'.$pass,'');
 }

}
sub auth_do_request {

 # THIS FUNCTION IS NOT YET WORKING
 return;

 my ($meth, $hrin, $user, $P)=(lc(shift),shift,shift,shift);

 if($meth eq 'basic'){
	$$hrin{'Authorization'}='Basic '.&lw::encode_base64($user.':'.$P,'');
	return 0;
 }

 # everything else requires the binary helper
 return undef if(!defined $lw::available{'lw::bin'});

 if($meth eq 'ntlm'){
	# oh boy, this is going to suck.  This code is largely based
	# on yeza's IIS-auth tarball.  Thanks yeza.

	my (%copy,%hout) = %$hrin;

	($wgroup,$domain)=(shift,shift);

	my $hdr = pack("LccccSSLSSL", 1,7,146,0,0,length($wgroup),
		length($wgroup),($wgroup eq ''?0:32),0,0,0);
	my $token = &lw::encode_base64("NTLMSSP\0$hdr$wgroup");

	$copy{'whisker'}->{'http_ver'}='1.1';
	$copy{'Connection'}->{'Keep-Alive'};
	$copy{'Authorization'}->{'NTLM $token'};
	&lw::http_fixup_request(\%copy);

	if(&lw::http_do_request(\%copy,\%hout)){
		return 1; }

	if($hout{'http_resp'}!=200 && $hout{'http_resp'}!=401){
		return 1; }

	if(!defined($hout{'www-authenticate'})){
		return 1; }
	
	my @p = split(' ', $hout{'www-authenticate'});	
	$p[0]=lc($p[0]);

	if($p[0] eq 'basic'){ # whoa, easy
		$$hrin{'Authorization'}='Basic '.&lw::encode_base64($user.':'.$P,'');
		return 0; 
	} elsif($p[0] eq 'ntlm'){ # ok, continuing

	}

 } else {
	# hmmm...what do we do here?  Normally we don't modify $hin,
	# but we can't return it, since how would the user know if it's
	# a password or an error (they're both strings)...dilemna
	$$hrin{'whisker'}->{'error'}= "Unknown authentication method type: '$meth'";
	return undef;
 }
}



# '/', 0, \@dir.split, \@valid, \&func, \%track, \%arrays   
sub utils_recperm { local $_;
 my ($p, $pp, $pn, $r, $fr, $dr, $ar)=(shift,shift,@_);
 if($pp >= @$pn) { push @$r, $p unless $$dr{$p}[1]!=1;
 } else { my $c=$$pn[$pp];
  if($c!~/^\@/){ utils_recperm($p.$c.'/',$pp+1,@_) if(&$fr($p.$c.'/'));
  } else {       map { if(&$fr($p.$_.'/')){
                  utils_recperm($p.$_.'/',$pp+1,@_);}}
                 @{$c=~tr/\@//d&&$$ar{$c}}; }}}

sub utils_array_shuffle { # fisher yates shuffle....w00p!
        my $array=shift; my $i;
        for ($i = @$array; --$i;){
                my $j = int rand ($i+1);
                next if $i==$j;
                @$array[$i,$j]=@$array[$j,$i];
}} # end array_shuffle, from Perl Cookbook (rock!)

sub utils_randstr {
        my $str;
        my $drift=((rand() * 10) % 10)+10;
        for(1..$drift){
        $str .= chr(((rand() * 26) % 26) + 97);} # yes, we only use a-z
        return $str;}

sub utils_get_dir {
        my ($w,$URL)=('',shift);

	if( ($w=index($URL,'?')) >= 0){
		substr($URL,$w,length($URL)-$w,'');
	}

	if( ($w=rindex($URL,'/')) >= 0){
		$URL = substr($URL,0,$w+1);
	} else {
		if(substr($URL,-1,1) ne '/'){
			$URL.='/';}
	}

        return $URL; }

sub utils_port_open {  # this should be platform-safe
        my ($target,$port)=@_;
        if(!(socket(S,PF_INET,SOCK_STREAM,0))){ return 0;}
        if(connect(S,sockaddr_in($port,inet_aton($target)))){
                close(S); return 1;
        } else { return 0;}}

sub utils_split_uri {
	my ($uri,$work,$w)=(shift,'',0);
	my @res=(undef,'http',undef,80,undef,undef,undef,undef);

	# handle mailto's (people miswrite them as mailto:email@host)
	if(index($uri,'mailto:',0) == 0){
		$res[1]='mailto';
		($res[0]=$uri)=~s/^mailto:[\/]{0,2}//;
		return @res; }

	# handle absolute urls
	if(index($uri,'://',0) > 0 ){ # fastpath check
	 if($uri=~m#^([a-z]+)://([^/]*)(.*)$#i){
		$res[1]=lc($1); 	# protocol
		$res[2]=$2;	    	# host
		$res[0]=$3;		# uri

		# check for port in host
		if(($w=index($res[2],':',0)) >=0){
			$res[3]=substr($res[2],$w,length($res[2])-$w,'');
			$res[3]=~tr/0-9//cd;
		}

		if($res[1] eq 'https') 	{ $res[3]||=443; }
		else 			{ $res[3]||=80;  }

		while(($w=rindex($res[2],'@')) >=0){
			$work=substr($res[2],0,$w,'');
			$res[2]=~tr/@//d;
			if(($w=index($work,':',0)) >=0){
				$res[6]=substr($work,0,$w);
				$res[7]=substr($work,$w+1,length($work)-$2);
			} else {
				$res[6]=$work; }
		}
		
		$res[0]||='/'; # in case they left off URI or end slash

	 } else { $res[0]=$uri; }  # note that if the URL isn't formed
	} else { $res[0]=$uri; }   # perfectly, we make it all a URI  :/

	# remove fragments
	if(($w=index($res[0],'#',0)) >=0){
		$res[5]=substr($res[0],$w+1,length($res[0])-$w,'');
		$res[0]=~tr/#//d; }

	# remove parameters
	if(($w=index($res[0],'?',0)) >=0){
		$res[4]=substr($res[0],$w+1,length($res[0])-$w,'');
		$res[0]=~tr/?//d; }
		
	return @res;
}

sub utils_lowercase_headers {
	my $href=shift;

	while( ($key,$val)=each %$href ){
		delete $$href{$key};
		$$href{lc($key)}=$val;
	}
}

sub utils_join_uri {
	my @V=@_;
	my $URL="$V[1]://$V[2]:$V[3]$V[0]?$V[4]";
	return $URL;
}

sub utils_page_content_changes {
 my ($hreq,$times)=@_;
 my ($temp,%hout);

 &lw::http_do_request($hreq,\%hout);
 $temp=$hout{'whisker'}->{'data'};

 for(1..$times){
	&lw::http_do_request($hreq,\%hout);
	if($temp ne $hout{'whisker'}->{'data'}){ return 1; }
 }
 return 0;
}

sub utils_vuln_reveals_source { # returns 1 if yes, 0 if no
 my ($hnorm, $hcheck, $stype)=@_; # takes normal hash, vuln hash,
 my (%hout,$temp);                # and optional server type

 &lw::http_do_request($hnorm,\%hout);
 $temp=$hout{'whisker'}->{'data'};

 # shitty situation: original page has source element(s)
 if($stype eq ''?utils_contains_source(\$temp,$stype):
	utils_contains_source(\$temp)){ return 0;}

 &lw::http_do_request($hcheck,\%hout);
 $temp=$hout{'whisker'}->{'data'};
 if($stype eq ''?utils_contains_source(\$temp,$stype):
	utils_contains_source(\$temp)){ return 1;}

 return 0;
}

sub utils_contains_source {
 my ($S,$dref,$stype)=(0,shift,shift);

 if($stype eq '' || $stype=~/iis/){
 #### IIS source checks ####
 # ASPs
  if($$dref=~/<%/){ $S++; }
  if($$dref=~/<script[^>]+runat=("server"|server)[^>]*>/i){ $S++; }
 }

 if($stype eq '' || $stype=~/php/){
 #### PHP source checks ####
  if($$dref=~/<\?/){ $S++; }
  if($$dref=~/<%/){ $S++; }
 }

 if($stype eq '' || $stype=~/cgi/){	
 #### CGI source checks ####
  if($$dref=~m@^#\!/usr/(local/bin|bin)/perl@){ $S++; }
  if($$dref=~m@^#\!/bin/sh@){ $S++; }
 }

 return $S;
}


sub bruteurl {
 my ($hin, $upre, $upost, $arin, $arout)=@_;
 my ($U,%hout);
 local $_;

 &lw::http_fixup_request($hin);

 map {
  ($U=$_)=~tr/\r\n//d; next if($U eq '');
  if(!&lw::http_do_request($hin,\%hout,{'uri'=>$upre.$U.$upost})){
    if(	$hout{'whisker'}->{'http_resp'}==200 ||
	$hout{'whisker'}->{'http_resp'}==403){
	push(@{$arout},$U);
    }
  }
 } @$arin;
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


sub cookie_read {
 my ($count,$jarref,$href)=(0,@_);
 local $_;

 my $target = $$href{'lowercase_incoming_headers'} == 1 
	? 'set-cookie' : 'Set-Cookie';

 if(!defined $$href{$target}){
	return 0;}

 if(ref($$hout{$target})){ # multiple headers
	foreach ($$href{$target}){
		&lw::cookie_parse($jarref,$_);
		$count++; }
 } else { # single header
	&lw::cookie_parse($jarref,$$href{$target});
	$count=1; }

 return $count;
}

sub cookie_parse {
 my ($jarref, $header)=@_;
 my ($del,$part,@parts,@construct,$cookie_name)=(0);

 @parts=split(/;/,$header);

 foreach $part (@parts){
	if($part=~/^(.+)=(.*)$/){
		my ($name,$val)=($1,$2);
		if($name=~/^domain$/i){		
			$val=~s#^http://##;
			$val=~s#/.*$##;
			$construct[1]=$val;
		} elsif($name=~/^path$/i){
			$val=~s#/$##;
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

 $override=$override||0;
 $$hin{'whisker'}->{'ssl'}=$$hin{'whisker'}->{'ssl'}||0;

 foreach $name (keys %$jarref){
	next if($name eq '');
	next if($$hin{'whisker'}->{'ssl'}>0 && $$jarref{$name}->[4]==0);
	if($override || 
          ($$hin{'whisker'}->{'host'}=~/$$jarref{$name}->[1]$/i &&
	   $$hin{'whisker'}->{'uri'}=~/$$jarref{$name}->[2]/i)){
		$out.="$name=$$jarref{$name}->[0];";
 }	}

 if($out ne ''){ $$hin{'Cookie'}=$out; }

}

sub cookie_get {
 my ($jarref,$name)=@_;

 if(defined $$jarref{$name}){
	return @{$$jarref{$name}};}

 return undef;
}

sub cookie_set {
 my ($jarref,$name,$value,$domain,$path,$expire,$secure)=@_;
 my @construct;

 return if($name eq '');
 if($value eq ''){
	delete $$jarref{$name};
	return;}
 $path=$path||'/';
 $secure=$secure||0;

 @construct=($value,$domain,$path,$expire,$secure);
 $$jarref{$name}=\@construct; 
}


sub http_init_request { # doesn't return anything
 my ($hin)=shift;
 $$hin{'whisker'}=(); # clear control hash

# control values
 $$hin{'whisker'}->{'req_spacer'}=' ';
 $$hin{'whisker'}->{'req_spacer2'}=' ';
 $$hin{'whisker'}->{'http_ver'}='1.1'; # notice it is now default!
 $$hin{'whisker'}->{'method'}='GET';
 $$hin{'whisker'}->{'method_postfix'}='';
 $$hin{'whisker'}->{'port'}=80;
 $$hin{'whisker'}->{'uri'}='/';
 $$hin{'whisker'}->{'uri_prefix'}='';
 $$hin{'whisker'}->{'uri_postfix'}='';
 $$hin{'whisker'}->{'uri_param_sep'}='?';
 $$hin{'whisker'}->{'host'}='localhost';
 $$hin{'whisker'}->{'http_req_trailer'}='';
 $$hin{'whisker'}->{'timeout'}=10; # seconds
 $$hin{'whisker'}->{'include_host_in_uri'}=0;
 $$hin{'whisker'}->{'ignore_duplicate_headers'}=1;
 $$hin{'whisker'}->{'normalize_incoming_headers'}=1;
 $$hin{'whisker'}->{'lowercase_incoming_headers'}=0;
 $$hin{'whisker'}->{'ssl'}=0; # use SSL for this request?
 $$hin{'whisker'}->{'http_eol'}="\r\n";
 $$hin{'whisker'}->{'INITIAL_MAGIC'}=31337;
 
# default header values
 $$hin{'Connection'}='Keep-Alive'; # notice it is now default!
 $$hin{'User-Agent'}='Mozilla/7.3'; # heh
}

sub http_do_request {
 my ($hin, $hout, $hashref)=@_;
 my ($temp,$vin,$resp,$S,$a,$b,$vout,@c,$c)=(1,'');
 local $_;

 %$hout=(); # clear output hash

 if($LW_HAS_SOCKET==0){
	$$hout{'whisker'}->{'error'}='Socket support not available';
	return 1;}

 if(!defined $$hin{'whisker'} || 
    !defined $$hin{'whisker'}->{'INITIAL_MAGIC'} ||
    $$hin{'whisker'}->{'INITIAL_MAGIC'}!=31337 ){
	$$hout{'whisker'}->{'error'}='Input hash not initialized';
	return 1;
 }

 if(defined $hashref){
	foreach (keys %$hashref){
		$$hin{'whisker'}->{$_}=$$hashref{$_};}}

 if($$hin{'whisker'}->{'ssl'}>0 && $LW_HAS_SSL!=1){
	$$hout{'whisker'}->{'error'}='SSL not available';
	return 1;}

 $TIMEOUT=$$hin{'whisker'}->{'timeout'}||10;

 my $cache_key = defined $$hin{'whisker'}->{'proxy_host'} ?
	"$$hin{'whisker'}->{'proxy_host'}:$$hin{'whisker'}->{'proxy_port'}" :
	"$$hin{'whisker'}->{'host'}:$$hin{'whisker'}->{'port'}" ;

 if(!defined $http_host_cache{$cache_key}){
	# make new entry
	push(@{$http_host_cache{$cache_key}},
		undef, 	# SOCKET		$Z[0]
		0,	# $SOCKSTATE		$Z[1]
		undef,	# INET_ATON		$Z[2]
		undef,	# $SSL_CTX		$Z[3]
		undef,	# $SSL_THINGY		$Z[4]
		'',	# $OUTGOING_QUEUE	$Z[5]
		'',	# $INCOMING_QUEUE	$Z[6]
		0,	# $STATS_SYNS		$Z[7]
		0 )	# $STATS_REQS		$Z[8]
 }

 # this works, but is it 'legal'?  notice it's not declared 'my'
 *Z=$http_host_cache{$cache_key};

 # use $chost/$cport for actual server we are connecting to
 my ($chost,$cport,$cwhat,$PROXY)=('',80,'',0);

 if(defined $$hin{'whisker'}->{'proxy_host'}){
    $chost=$$hin{'whisker'}->{'proxy_host'};
    $cport=$$hin{'whisker'}->{'proxy_port'}||80;
    $cwhat='proxy';
    $PROXY=1;

    if($$hin{'whisker'}->{'ssl'}>0 && $LW_SSL_LIB==2){
	$ENV{HTTPS_PROXY} ="$$hin{'whisker'}->{'proxy_host'}:";
	$ENV{HTTPS_PROXY}.=$$hin{'whisker'}->{'proxy_port'}||80; }

 } else {
    $chost=$$hin{'whisker'}->{'host'};
    $cport=$$hin{'whisker'}->{'port'};
    $cwhat='host';
 }

 if($Z[1]>0){
 	vec($vin,fileno($Z[0]),1)=1; # is socket still good?
 	if(!select(undef,$vin,undef,.01)){
		$Z[1]=0;
		sock_close($Z[0],$Z[4]);}
 else { $Z[1]=0; }  # CS MOD -- Chris Sullo for Nikto
 }

 if($Z[1]==0){
	if(!socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp')||0)){
		$$hout{'whisker'}->{'error'}='Socket() problems'; 
		return 1;}

	$Z[0]=S; # lame hack to get perl to take variable for socket

	if($$hin{'whisker'}->{'ssl'}>0){ # ssl setup stuff

	    if($LW_SSL_LIB==1){
		if(! ($Z[3] = Net::SSLeay::CTX_new()) ){
			$$hout{'whisker'}->{'error'}="SSL_CTX error: $!";
			return 1;}
		if(! ($Z[4] = Net::SSLeay::new($Z[3])) ){
			$$hout{'whisker'}->{'error'}="SSL_new error: $!";
			return 1;}
	    }
	}

	if(!defined $Z[2]){ $Z[2]=inet_aton($chost); }

	if($$hin{'whisker'}->{'ssl'}>0 && $LW_SSL_LIB==2){
		# proxy set in ENV; we always connect to host
		$Z[4]= Net::SSL->new(
			PeerAddr => $$hin{'whisker'}->{'host'},
			PeerPort => $$hin{'whisker'}->{'port'},
			Timeout => $TIMEOUT );
		if($@){ $$hout{'whisker'}->{'error'}="Can't connect via SSL: $@[0]";
			return 1;}
		$Z[4]->autoflush(1);
	} else {
		if(!connect($Z[0],sockaddr_in($cport,$Z[2]))){
			$$hout{'whisker'}->{'error'}="Can't connect to $cwhat";
			return 1;}

		# same as IO::Handle->autoflush(1), without importing 1000+ lines
		my $S=select($Z[0]); $|++; select($S);
	}

	$Z[1]=1; $Z[7]++;

	if($$hin{'whisker'}->{'ssl'}>0){
	    if($LW_SSL_LIB==1){

	        if($PROXY){ # handle the proxy CONNECT stuff...
		    my $SSL_CONNECT = "CONNECT $$hin{'whisker'}->{'host'}".
			":$$hin{'whisker'}->{'port'} HTTP/1.0\n\n";
		    syswrite($Z[0],$SSL_CONNECT,length($SSL_CONNECT)); }

		&Net::SSLeay::set_fd($Z[4], fileno($Z[0]));
		if(! (Net::SSLeay::connect($Z[4])) ){
			$$hout{'whisker'}->{'error'}="SSL_connect error: $!";
			sock_close($Z[0],$Z[4]); return 1;}
	    }

	} else {
		$Z[4]=undef;
	}
 }

 if(defined $$hin{'whisker'}->{'ids_session_splice'} &&
            $$hin{'whisker'}->{'ids_session_splice'}>0 &&
		$$hin{'whisker'}->{'ssl'}==0){ # no session_spice over ssl
	setsockopt($Z[0],SOL_SOCKET,SO_SNDLOWAT,1);
	@c=split(//, &http_req2line($hin));
	# notice we bypass queueing here, in order to trickle the packets
	foreach $c (@c){ syswrite($Z[0],$c,1); select(undef,undef,undef,.1);}
 } else {
	 http_queue(&http_req2line($hin));}

 # send the initial request
 if($res=http_queue_send($Z[0],$Z[4])){
	$$hout{'whisker'}->{'error'}="Error sending request to server: $res";
	sock_close($Z[0],$Z[4]); $Z[1]=0; return 1;}

 $Z[8]++;

 if($$hin{'whisker'}->{'http_ver'} ne '0.9'){

    foreach (keys %$hin){
	next if($_ eq '' || $_ eq 'whisker');
	if(ref($$hin{$_})){ # header with multiple values
		my $key=$_;
		foreach (@{$$hin{$key}}){
		  http_queue("$key: $_$$hin{'whisker'}->{'http_eol'}");}
	} else { # normal header
		http_queue("$_: $$hin{$_}$$hin{'whisker'}->{'http_eol'}");
	}
    }

    if(defined $$hin{'whisker'}->{'raw_header_data'}){
	http_queue($$hin{'whisker'}->{'raw_header_data'});}

    http_queue($$hin{'whisker'}->{'http_eol'});

    if(defined $$hin{'whisker'}->{'data'} && $$hin{'whisker'}->{'meth'}
		ne 'HEAD'){ # PUT, POST, etc
	http_queue($$hin{'whisker'}->{'data'});}

    # all data is wrangled...actually send it now
    if($res=http_queue_send($Z[0],$Z[4])){
	$$hout{'whisker'}->{'error'}="Error sending data to server: $res";
	sock_close($Z[0],$Z[4]); $Z[1]=0; return 1;}

 } # http 0.9 support

 if(defined $Z[4]){
	if($LW_SSL_LIB==1){ # Net::SSLeay
 		shutdown $Z[0], 1; 
	} else { # Net::SSL
		shutdown $Z[4], 1;
	}
 }

 vec($vin,fileno($Z[0]),1)=1; # wait only so long to read...
 if(!select($vin,undef,undef,$TIMEOUT)){
	$$hout{'whisker'}->{'error'}="Server read timed out";
	sock_close($Z[0],$Z[4]); $Z[1]=0; return 1;}

my ($LC,$CL,$TE,$CO)=('',-1,'',''); # extra header stuff

$$hout{'whisker'}->{'lowercase_incoming_headers'} = 
	$$hin{'whisker'}->{'lowercase_incoming_headers'};

if($$hin{'whisker'}->{'http_ver'} ne '0.9'){

 do { # catch '100 Continue' responses
  ($resp=sock_getline($Z[0],$Z[4]))=~tr/\r\n//d;

  if($resp!~/^HTTP\/([0-9.]{3}) (\d+)[ ]{0,1}(.*)/){
	$$hout{'whisker'}->{'error'}="Invalid HTTP response: $resp";
	# let's save the incoming data...we might want it
	$$hout{'whisker'}->{'data'}=$resp;
	while($_=sock_getline($Z[0],$Z[4])){ 
		$$hout{'whisker'}->{'data'}.=$_;}
	sock_close($Z[0],$Z[4]); $Z[1]=0; # otherwise bad crap lingers
	return 1;}

  ($$hout{'whisker'}->{'http_ver'},$$hout{'whisker'}->{'http_resp'},
	$$hout{'whisker'}->{'http_resp_message'})=($1,$2,$3);

  while($_=sock_getline($Z[0],$Z[4])){ # check pertinent headers

	my $W=rindex($_,"\r") || rindex($_,"\n"); 
	last if ($W < 2); # acceptable assumption case?

	my $W2=index($_,':'); # this is faster than regex
	$a=substr($_,0,$W2); 
	$b=substr($_,$W2+2,$W-$W2-2);

	$LC = lc($a);
	next         if($LC eq 'whisker');
	$TE = lc($b) if($LC eq 'transfer-encoding');
	$CL = $b     if($LC eq 'content-length');
	$CO = lc($b) if($LC eq 'connection');

	if($$hin{'whisker'}->{'lowercase_incoming_headers'}>0){
		$a=$LC;
	} elsif($$hin{'whisker'}->{'normalize_incoming_headers'}>0){
# reinsert
	}

	if(defined $$hout{$a} && 
		$$hin{'whisker'}->{'ignore_duplicate_headers'}!=1){
	  if(!ref($$hout{$a})){
	    my $temp=$$hout{$a};
	    delete $$hout{$a};
	    push(@{$$hout{$a}},$temp);
	  }
	  push(@{$$hout{$a}},$b);
	} else {
	  $$hout{$a}=$b;
  }	}

 } while($$hout{'whisker'}->{'http_resp'}==100);

} else { # http ver 0.9, we need to fake it
 $$hout{'whisker'}->{'http_ver'}='0.9';
 $$hout{'whisker'}->{'http_resp'}='200';
 $$hout{'whisker'}->{'http_resp_message'}='';
}

 if($$hin{'whisker'}->{'method'} ne 'HEAD' && 
	$$hout{'whisker'}->{'http_resp'}!=206 &&
	$$hout{'whisker'}->{'http_resp'}!=102){
  if ($TE eq 'chunked') { 
	$a=sock_getline($Z[0],$Z[4]);
	$CL=hex($a); 
	while($CL!=0) { # chunked sucks
		if(!defined ($temp=sock_get($Z[0],$Z[4],$CL))){
			$$hout{'whisker'}->{'error'}='Error reading data';
			sock_close($Z[0],$Z[4]); $Z[1]=0; return 1;}
		$$hout{'whisker'}->{'data'}=$$hout{'whisker'}->{'data'} . $temp;
		$temp=sock_getline($Z[0], $Z[4]);
		($temp=sock_getline($Z[0], $Z[4])) if($temp=~/^[\r\n]*$/);
		$CL=hex($temp);}
	while($_=sock_getline($Z[0],$Z[4])){ tr/\r\n//d; last if($_ eq ''); }
  } else {
 	if ($CL != -1) {
		if(!defined ($temp=sock_get($Z[0],$Z[4],$CL))){
			$$hout{'whisker'}->{'error'}='Error reading data';
			sock_close($Z[0],$Z[4]); $Z[1]=0; return 1;}
	} else { $temp=''; while($_=sock_getline($Z[0],$Z[4])){$temp.=$_;}}
	$$hout{'whisker'}->{'data'}=$temp; 
  }
 } # /method ne HEAD && http_resp ne 206 or 102/

 if($CO ne 'keep-alive') {
	$$hout{'Connection'}='Close';
	$Z[1]=0; sock_close($Z[0],$Z[4]); } 

 $$hout{'whisker'}->{'sockstate'}=$Z[1];
 $$hout{'whisker'}->{'stats_reqs'}=$Z[8];
 $$hout{'whisker'}->{'stats_syns'}=$Z[7];
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

	eval "close($fd)";
	if(defined $ssl){
	    if($LW_SSL_LIB==1){ # Net::SSLeay
		eval "&Net::SSLeay::free($ssl)";
		eval "&Net::SSLeay::CTX_free($Z[3])";
	    } else { # Net::SSL
		eval "close($ssl)"; # is that right for Net::SSL?
	    }
	}

	$Z[4]=undef;
}

sub sock_getline { # read from socket w/ timeouts
        my ($fd,$ssl) = @_;
        my ($str,$t)=('','');

        $t = index($Z[6],"\n",0);

        while($t < 0){
                return undef if &http_queue_read($fd,$ssl);
                $t=index($Z[6],"\n",0);
        }

        return substr($Z[6],0,$t+1,'');
}

sub sock_get { # read from socket w/ timeouts
        my ($fd,$ssl,$amount) = @_;
        my ($str,$t)=('','');

	while($amount > length($Z[6])){
                return undef if &http_queue_read($fd,$ssl);
	}

	return substr($Z[6],0,$amount,'');
}

sub http_queue_read {
	my ($fd,$ssl)=@_;
	my ($vin, $t)=('');

	if(defined $ssl){
	    if($LW_SSL_LIB==1){ # Net::SSLeay
        	if(!($Z[6].=Net::SSLeay::ssl_read_all($ssl))){
			return 1;}
	    } else { # Net::SSL
		if(!$ssl->read($t,1024)){ return 1;
		} else { $Z[6].=$t;}
	    }
	} else {
		vec($vin,fileno($fd),1)=1; # wait only so long to read...
		if(!select($vin,undef,undef,$TIMEOUT)){
			return 1;}
               	if(!sysread($fd,$t,1024)){	return 1;
		} else {			$Z[6].=$t;}
	}

	return 0;
}

sub http_queue_send { # write to socket
	my ($fd,$ssl)=@_;
	my ($v,$wrote,$error)=('');

	if(defined $ssl){
	    if($LW_SSL_LIB==1){ # Net::SSLeay
		($wrote,$err)=Net::SSLeay::ssl_write_all($ssl,$Z[5]);
		return "SSL_write error: $err" unless $wrote;
	    } else { # Net::SSL
		$ssl->print($Z[5]);
	    }
	} else {
        	vec($v,fileno($fd),1)=1;
 		if(!select(undef,$v,undef,.01)){ 
			return 'Socket write test failed'; }
		syswrite($fd,$Z[5],length($Z[5]));
	}
	$Z[5]=''; return undef;
}

sub http_queue {
	$Z[5].= shift;
}

sub http_fixup_request {
 my $hin=shift;

 if($$hin{'whisker'}->{'http_ver'} eq '1.1' && !defined $$hin{'Host'}){
	$$hin{'Host'}=$$hin{'whisker'}->{'host'};}

 if(defined $$hin{'whisker'}->{'data'} && $$hin{'whisker'}->{'meth'} ne 'HEAD'
		&& !defined $$hin{'Content-Length'}){
	$$hin{'Content-Length'}=length($$hin{'whisker'}->{'data'});}

 if(defined $$hin{'whisker'}->{'proxy_host'}){
	$$hin{'whisker'}->{'include_host_in_uri'}=1;}

}

sub http_reset {
 my $key;

 foreach $key (keys %http_host_cache){
 	*Z=$http_host_cache{$key};
	sock_close($http_host_cache{$key}->[0],
			$http_host_cache{$key}->[4]);
	delete $http_host_cache{$key};
 }
}


sub crawl {
 my ($START, $MAX_DEPTH, $hrtrack, $hrin)=@_;
 my (%hout, %jar);
 my (@ST, @links, @tlinks, @vals, @ERRORS);

 # $ST[0]=HOST  $ST[1]=URL  $ST[2]=CWD  $ST[3]=HTTPS  $ST[4]=SERVER
 # $ST[5]=PORT  $ST[6]=DEPTH

 @vals=&lw::utils_split_uri($START);
 $ST[1]=$vals[0]; 	# uri
 $ST[0]=$vals[2]; 	# host
 $ST[5]=$vals[3]||80; 	# port
 $ST[4]=undef;		# server tag

 # some various informationz...
 $crawl_config{'host'}=$ST[0];
 $crawl_config{'port'}=$ST[5];
 $crawl_config{'start'}=$ST[1];

 $$hrin{'whisker'}->{'host'}=$ST[0];
 $$hrin{'whisker'}->{'lowercase_incoming_headers'}=1; # makes life easier

 # this is so callbacks can access internals via references
 $crawl_config{'ref_links'}=\@links;
 $crawl_config{'ref_jar'}=\%jar;
 $crawl_config{'ref_hin'}=\%hin;
 $crawl_config{'ref_hout'}=\%hout;

 push @links, \@{[$ST[1],1,($vals[1] eq 'https')?1:0]};

 while(@links){
  my $C=shift @links;
  $ST[1]=$C->[0]; # url
  $ST[6]=$C->[1]; # depth
  $ST[3]=$C->[2]; # https

  next if(defined $$hrtrack{$ST[1]} && $$hrtrack{$ST[1]} ne '?');

  if($ST[6] > $MAX_DEPTH){
	if($crawl_config{'save_skipped'}>0){
		$$hrtrack{$ST[1]}='?'; }
	next;
  }

  $ST[2]=&lw::utils_get_dir($ST[1]);

  if(&lw::http_do_request($hrin,\%hout,{'uri'=>$ST[1],'ssl'=>$ST[3]})){
	push @ERRORS, "Error on making request for '$ST[1]': $hout{'whisker'}->{'error'}";
	next;
  }

  $$hrtrack{$ST[1]}=$hout{'whisker'}->{'http_resp'};

  if(defined $hout{'server'}){ 
   if(!defined $ST[4]){ # server tag
	$ST[4]=$hout{'server'}; }
   $server_tags{$hout{'server'}}++;
  }

  next if(scalar @links > $crawl_config{'url_limit'});

  if((index($hout{'content-type'},'text/htm',0)==0) &&
	$hout{'whisker'}->{'http_resp'}==200){

	if(defined $hout{'set-cookie'}){

#		if($crawl_config{'save_cookies'}>0){
#			# how should we save cookies? }

		if($crawl_config{'reuse_cookies'}>0){
			&lw::cookie_read(\%jar,\%hout); }
	}

	%lw::crawl_forms=(); # reset any form targets

	&lw::html_find_tags(\$hout{'whisker'}->{'data'},
		\&lw::crawl_extract_links_test);

	$crawl_config{'stats_html'}++; # count how many pages we've parsed

 	foreach $T (@lw::crawl_urls){

	 $T=~tr/\0\r\n//d; # the NULL character is a bug that's somewhere
	 next if (length($T)==0);

	 if($crawl_config{'callback'} != 0){
		next if &{$crawl_config{'callback'}}($T,@ST); }

	 @vals=lw::utils_split_uri($T);

	 if( (defined $vals[2] && $vals[2] ne $ST[0]) || 
			(defined $vals[3] && $vals[3] != $ST[5]) ||
			(defined $vals[1] && ($vals[1] ne 'http' 
				&& $vals[1] ne 'https'))){
		if($crawl_config{'save_offsites'}>0){
			$lw::crawl_offsites{lw::utils_join_uri(@vals)}++; }
		next; }

	 # save absolute form locations into lw::crawl_temp
	 if(defined $lw::crawl_forms{$vals[0]}){
	 	if(substr($vals[0],0,1) ne '/'){
			$lw::crawl_temp{$ST[2].$vals[0]}++;
		} else {$lw::crawl_temp{$vals[0]}++; }
	 }

	 if(substr($vals[0],0,1) ne '/'){
		$vals[0]=$ST[2].$vals[0]; }

#	 $vals[0]=~s#[^/]{0,1}\./##g; # removes '/./'

	 my $where=rindex($vals[0],'.');
	 my $EXT='';
	 if($where >= 0){
	   $EXT = substr($vals[0], $where+1, length($vals[0])-$where); }

	 if($crawl_config{'skip_ext'}=~/\.$EXT /i){
		if($crawl_config{'save_skipped'}>0){
			$$hrtrack{$vals[0]}='?'; }
	 	next; }

	 if(defined $vals[4] && $crawl_config{'use_params'}>0){
		if($crawl_config{'params_double_record'}>0 &&
				!defined $$hrtrack{$vals[0]}){
			$$hrtrack{$vals[0]}='?'; }
		$vals[0]=$vals[0].'?'.$vals[4];	
	 }

	 next if(defined $$hrtrack{$vals[0]});

	 push @links, \@{[$vals[0],$ST[6]+1, ($vals[1] eq 'https')?1:0]};

	 } # for

	@lw::crawl_urls=(); # reset for next round

  # handle move requests
  } elsif($crawl_config{'follow_moves'} >0 &&
		$hout{'whisker'}->{'http_resp'} <308 &&
		$hout{'whisker'}->{'http_resp'} >300){

     if(defined($hout{'location'})){

	 @vals=lw::utils_split_uri($hout{'location'});

	 if( (defined $vals[2] && $vals[2] ne $ST[0]) || 
			(defined $vals[3] && $vals[3] != $ST[5]) ||
			(defined $vals[1] && ($vals[1] ne 'http' 
				&& $vals[1] ne 'https'))){
		if($crawl_config{'save_offsites'}>0){
			$lw::crawl_offsites{lw::utils_join_uri(@vals)}++; }
		next; }

	 # save absolute form locations into lw::crawl_temp
	 if(defined $lw::crawl_forms{$vals[0]}){
	 	if(substr($vals[0],0,1) ne '/'){
			$lw::crawl_temp{$ST[2].$vals[0]}++;
		} else {$lw::crawl_temp{$vals[0]}++; }
	 }

	 if(substr($vals[0],0,1) ne '/'){
		$vals[0]=$ST[2].$vals[0]; }

	 my $where=rindex($vals[0],'.');
	 my $EXT='';
	 if($where >= 0){
	   $EXT = substr($vals[0], $where+1, length($vals[0])-$where); }

	 if($crawl_config{'skip_ext'}=~/\.$EXT /i){
		if($crawl_config{'save_skipped'}>0){
			$$hrtrack{$vals[0]}='?'; }
	 	next; }

	 if(defined $vals[4] && $crawl_config{'use_params'}>0){
		if($crawl_config{'params_double_record'}>0 &&
				!defined $$hrtrack{$vals[0]}){
			$$hrtrack{$vals[0]}='?'; }
		$vals[0]=$vals[0].'?'.$vals[4];	
	 }

	 next if(defined $$hrtrack{$vals[0]});

	 push @links, \@{[$vals[0],$ST[6]+1, ($vals[1] eq 'https')?1:0]};
     } # if(location header)
  } # if/elsif
 } # while

 my $key;
 foreach $key (keys %crawl_config){
 	delete $crawl_config{$key} if (substr($key,0,4) eq 'ref_');}

 # move all the saved form values into the right place
 %lw::crawl_forms = %lw::crawl_temp;

 $crawl_config{'stats_reqs'}=$hout{'whisker'}->{'stats_reqs'};
 $crawl_config{'stats_syns'}=$hout{'whisker'}->{'stats_syns'};

} # end sub crawl

sub crawl_get_config {
	my $key=shift;
	return $crawl_config{$key};
}

sub crawl_set_config {
	$crawl_config{lc($_[0])}=$_[1];
}

sub crawl_extract_links_test { # tags know to have links
	my ($TAG, $hr, $dr, $start, $len)=(lc(shift),@_);
	my @temp; local $_;

	return if(!scalar %$hr); # fastpath quickie

	while( ($key,$val)= each %$hr){ # normalize element values
#		next if($key eq '');
#		delete $$hr{$key}; # actually don't have to delete
		$$hr{lc($key)} = $val;
	}

	if($TAG eq 'a'){
		if(defined $$hr{'href'}){
			push(@lw::crawl_urls,$$hr{'href'}); }
		return; }

	if($TAG eq 'img'){
		@temp=('src','usemap','lowsrc');
		map { if(defined $$hr{$_}){ 
			push(@lw::crawl_urls,$$hr{$_});}} @temp;
		return; }

	if($TAG eq 'form'){
		if(defined $$hr{'action'}){ 
			push(@lw::crawl_urls,$$hr{'action'});}
			# special: form actions are almost always dynamic
			$lw::crawl_forms{$$hr{'action'}}++;
		return; }

	if($TAG eq 'applet'){ 
		@temp=('archives','codebase','code');
		map { if(defined $$hr{$_}){ 
			push(@lw::crawl_urls,$$hr{$_});}} @temp;
		return;}

	if($TAG eq 'object'){
		@temp=('classid','codebase','data','archive','usemap');
		map { if(defined $$hr{$_}) {
			push(@lw::crawl_urls,$$hr{$_});}} @temp;
		return;}

	if($TAG eq 'embed'){
		if(defined $$hr{'src'}){ 
			push(@lw::crawl_urls,$$hr{'src'});}
		if(defined $$hr{'pluginspage'}){ 
			push(@lw::crawl_urls,$$hr{'pluginspage'});}
		return;}

	if($TAG eq 'frame'){
		if(defined $$hr{'src'}){ 
			push(@lw::crawl_urls,$$hr{'src'});}
		if(defined $$hr{'longdesc'}){ 
			push(@lw::crawl_urls,$$hr{'longdesc'});}
		return;}

	if($TAG eq 'iframe'){
		if(defined $$hr{'src'}){ 
			push(@lw::crawl_urls,$$hr{'src'});}
		if(defined $$hr{'longdesc'}){ 
			push(@lw::crawl_urls,$$hr{'longdesc'});}
		return;}

	if($TAG eq 'isindex'){
		if(defined $$hr{'action'}){ 
			push(@lw::crawl_urls,$$hr{'action'});}
			# special: isindex are typically dynamic
			$lw::crawl_forms{$$hr{'action'}}++;
		return;}

	# leftover tags
	if(defined $$hr{'href'}){ @temp=('area','base','link','xmp');
		map { if($TAG eq $_){
			push(@lw::crawl_urls,$$hr{'href'});}} @temp;}

	if(defined $$hr{'src'}){
		@temp=('bgsound','input','layer','script');
		map { if($TAG eq $_){
			push(@lw::crawl_urls,$$hr{'src'});}} @temp;}

	if(defined $$hr{'background'}){ 
		@temp=('body','ilayer','layer','table','td','th');
		map { if($TAG eq $_){ 
			push(@lw::crawl_urls,$$hr{'background'});
			return; }} @temp;}

	if(defined $$hr{'cite'}){ @temp=('blockquote','del','ins','q');
		map { if($TAG eq $_){ 
			push(@lw::crawl_urls,$$hr{'cite'});
			return; }} @temp;}

	return;}


sub html_find_tags {
 if(defined $available{'lw::bin'}){ # use faster binary helper
	goto &lw::bin::html_find_tags; }

 my ($dataref, $callbackfunc)=@_;
 my ($CURTAG, $ELEMENT, $VALUE, $c, $cc);
 my ($INCOMMENT,$INTAG)=(0,0);
 my (%TAG, $ret, $start, $tagstart, $commstart);

 for ($c=0; $c<length($$dataref); $c++){

	$cc=substr($$dataref,$c,1);

	if(!$INCOMMENT && !$INTAG && $cc ne '>' && $cc ne '<'){
		next;}

        if($cc eq '<'){
                if(substr($$dataref,$c+1,1) eq '!' && 
				substr($$dataref,$c+2,1) eq '-' && 
				substr($$dataref,$c+3,1) eq '-'){
                        $INCOMMENT=1; $commstart=$c; $c+=3;
		} else {
    	                $INTAG=1; $tagstart=$c; $c++;
			while(substr($$dataref,$c,1)!~/[ \t\r\n>]/){ 
				$c++;}
			$CURTAG=substr($$dataref,$tagstart+1,
				$c-$tagstart-1);
		}	
		$cc=substr($$dataref,$c,1); # refresh current char (cc)
	}

        if($cc eq '>'){
		if(!$INCOMMENT){ 
			$INTAG=0; 
			$ret=&$callbackfunc(lc($CURTAG),\%TAG, $dataref,
				$start, $c-$start+1);
			if(defined $ret && $ret != 0){
				$c+=$ret;}
			%TAG=();}
                if($INCOMMENT && substr($$dataref,$c-1,1) eq '-' && 
				substr($$dataref,$c-2,1) eq '-'){
                        $INCOMMENT=0; 
			$TAG{'='}=substr($$dataref,$commstart+4,
				$c-$commstart+1);
			$ret=&$callbackfunc('!--',\%TAG, $dataref,
				$commstart, $c-$commstart+1);
			if(defined $ret && $ret != 0){
				$c+=$ret;}
			next;}}

        if($INCOMMENT){ next; }

        if($INTAG){

                $ELEMENT=''; $VALUE='';
		while(substr($$dataref,$c,1)=~/[ \t\r\n]/i){ $c++;}

		$start=$c;
		while(substr($$dataref,$c,1)!~/[ \t\r\n=>]/i){ 
			$c++;}
		$ELEMENT=substr($$dataref,$start,$c-$start);

		while(substr($$dataref,$c,1)=~/[ \t\r\n]/i){ $c++;}

                if(substr($$dataref,$c,1) eq '='){ $c++;
			$start=$c;
                        if(substr($$dataref,$c,1) eq '"'){ $c++; $start++;
	                        while(substr($$dataref,$c,1) ne '"'){ 
					$c++; }
				$VALUE=substr($$dataref,$start,$c-$start);
                                $c++; 
			} else {
                                while(substr($$dataref,$c,1)!~/[ \t\r\n\>]/){
                                        $c++;}
				$VALUE=substr($$dataref,$start,$c-$start);
			}

                	while(substr($$dataref,$c,1)=~/[ \t\r\n]/){$c++;}
                } 
		$c--;
		$TAG{lc($ELEMENT)}=$VALUE; # save element in the hash
	}
}}


sub dav_do_propfind {
	my ($hin,$hout,@props)=(@_);
	my %hout;

	if($props[0] eq ''){push @props,'displayname';}

	$$hin{'whisker'}->{'method'}='PROPFIND';
	$$hin{'Content-Type'}='text/xml';
	delete($$hin{'Content-Length'});
	$$hin{'whisker'}->{'data'}='<?xml version ="1.0"?>'.
		'<propfind xmlns="DAV:"><prop>';
	map { $$hin{'whisker'}->{'data'}.='<'.$_.'/>';} @props;
	$$hin{'whisker'}->{'data'}.='</prop></propfind>';

	&lw::http_do_request($hin,$hout);
}

sub do_search { # this is IIS specific
	my ($hin,$hout,$sql)=($_);
	my %hout;

	$$hin{'whisker'}->{'method'}='SEARCH';
	$$hin{'Content-Type'}='text/xml';
	delete($$hin{'Content-Length'});
	$$hin{'whisker'}->{'data'}='<?xml version ="1.0"?>'.
		'<g:searchrequest xmlns:g="DAV:">'.
		'<g:sql>' . $sql . '</g:sql>'.
		'</g:searchrequest>';
	&lw::http_do_request($hin,$hout);
}

sub dav_do_mkcol {
	my ($rin,$rout)=(@_);
	$$rin{'whisker'}->{'method'}='MKCOL';
	delete($rin{'Content-Length'});
	&lw::http_do_request($rin,$rout);
}

sub do_copy {
	my ($rin,$rout,$to)=(@_);
	$$rin{'whisker'}->{'method'}='COPY';
	$$rin{'Destination'}='http://'.
		$$rin{'whisker'}->{'host'}.$to;
	delete($rin{'Content-Length'});
	&lw::http_do_request($rin,$rout);
}	

sub do_move {
	my ($rin,$rout,$to)=(@_);
	$$rin{'whisker'}->{'method'}='MOVE';
	$$rin{'Destination'}='http://'.
		$$rin{'whisker'}->{'host'}.$to;
	delete($rin{'Content-Length'});
	&lw::http_do_request($rin,$rout);
}	

1;
