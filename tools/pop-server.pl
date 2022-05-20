#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Long qw(:config posix_default bundling);
use IO::Socket::INET;
BEGIN { unshift @INC,$1 if $0 =~m{(.*)/}s; }


my $DEBUG = 1;
my $listen = '127.0.0.1:1110';
my $chuser = ($< == 0) ? 'nobody':undef;

sub usage {
    print STDERR "ERROR: @_\n" if @_;
    print STDERR <<'USAGE';

Simple, single threaded POP3 server.
Mails are read from given mailbox. Any kind of authorization is accepted.

Usage: $0 [options] mailbox
Options
  -h           Help (this info)
  -d           Debug
  -L|listen A  listen on addr:port A (default $listen)
  --index      create message 1 as summary (incl. hash) of all messages
USAGE
    exit(2);
}

my $with_index;
GetOptions(
    'h|help'     => sub { usage() },
    'd|debug!'   => \$DEBUG,
    'L|listen=s' => \$listen,
    'U|user=s'   => \$chuser,
    'index'      => \$with_index,
) or usage('bad option');
my $mbox = shift(@ARGV) or usage('missing mbox argument');
@ARGV and usage('too much arguments');
$mbox = MBox->new($mbox,$with_index) or die "failed to open mbox $mbox";

my $srv = IO::Socket::INET->new( 
    LocalAddr => $listen, 
    Listen => 10, 
    Reuse => 1 
) or die "cannot listen: $!";
debug( "listening at $listen" );

if ($chuser) {
    my $uid = getpwnam($chuser);
    ($<,$>) = ($uid,$uid);
    debug("running with uid=$<, euid=$>");
}


while (1) {
    my $cl = $srv->accept or next;
    debug("new connection from ".$cl->peerhost);
    POP->new($cl,$mbox)->MainLoop;
}


sub debug  { 
    $DEBUG or return;
    my $msg = shift;
    $msg = sprintf($msg,@_) if @_;
    print STDERR "DEBUG: $msg\n";
}



######################################################################

package POP;
BEGIN { *debug  = \&::debug }

sub new {
    my ($class,$cl,$mbox) = @_;
    return bless {
	sock => $cl,
	handler => \&do_command,
	mbox => $mbox,
    },$class;
}


sub out     { shift->{sock}->print( "@_\r\n" ) }
sub OK      { shift->out( "+OK @_" ) }
sub ERR     { shift->out( "-ERR @_" ) }
sub outml {
    my $self = shift;
    $self->out($_) for (@_);
    $self->out('.');
}


sub MainLoop {
    my $self = shift;
    $self->OK("Please login") or return;
    while (defined( my $l = $self->{sock}->getline)) {
	my $rv = $self->{handler}->($self,$l);
	return if ! defined $rv;   # error
	return 1 if !$rv;          # finished
    }
}

sub do_command {
    my ($self,$line) = @_;
    my ($cmd,$arg) = $line =~m{^(\w+)(?:\s+(\S.*?))?\s*\z} 
	or return $self->ERR('bad command');
    $cmd = uc($cmd);
    $arg = '' if ! defined $arg;
    debug("cmd=$cmd arg=$arg");

    return $self->OK('') if $cmd eq 'NOOP';
    if ($cmd eq 'QUIT') {
	$self->OK('bye');
	return 0; # end
    }

    if ($cmd eq 'USER') {
	$self->{logged_in} = 0;
	$self->{user} = $arg;
	return $self->OK("Please send Password");
    } 
    
    if ($cmd eq 'PASS') {
	$self->{logged_in} = 1;
	return $self->OK('Logged in');
    } 
    
    if ($cmd eq 'AUTH') {
	if ( $arg=~m{\S} ) { 
	    # send challenge, change handler to auth
	    $self->{handler} = \&do_auth;
	    return $self->out( "+ sdfghjdasghsda37ndh2" );
	} else {
	    # list available methods
	    $self->OK("Following are supported SASL mechanisms");
	    return $self->outml( "LOGIN","KERBEROS-V5","BLA-FASEL-1" );
	}
    }

    # everything else only after logging in
    return $self->ERR('Please login first') if ! $self->{logged_in};

    my $mails = $self->{mbox}->mails;
    return $self->OK(int(@$mails)." ".$self->{mbox}->size)
	if $cmd eq 'STAT';

    if ($cmd eq 'DELE') {
	my $id = $arg-1;
	if ( $id>=0 and $mails->[$id] ) {
	    $mails->[$id][4] = 1; # mark for deletion
	    return $self->OK('');
	}
	return $self->ERR( 'invalid id' );
    }

    if ( $cmd eq 'RSET' ) {
	$_->[4] = 0 for(@$mails);
	return $self->OK('');
    }

    if ($cmd eq 'LIST') {
	if ($arg =~m{\S}) {
	    my $id = $arg-1;
	    return $self->ERR('no such message') 
		if $id<0 or !$mails->[$id] or $mails->[$id][4];
	    return $self->OK("$arg $mails->[$id][3]");
	} else {
	    $self->OK('scan listing follows');
	    for(my $i=0;$i<@$mails;$i++) {
		$mails->[$i][4] and next;
		$self->out( ($i+1)." $mails->[$i][3]");
	    }
	    return $self->out('.');
	}
    }

    if ($cmd eq 'RETR') {
	my ($fh,$size) = $mbox->openmail($arg);
	return $self->ERR('no such message') if ! $fh;
	$self->OK('Message follows');
	my $start = tell($fh);
	while (defined( my $line = <$fh>)) {
	    last if tell($fh) - $start > $size;
	    $line =~s{\r?\n\z}{};
	    $line =~s{^\.}{..};
	    $self->out($line);
	}
	return $self->out('.');
    }

    if ($cmd eq 'TOP') {
	my ($id,$lines) = split(' ',$arg);
	my ($fh,$size) = $mbox->openmail($arg);
	return $self->ERR('no such message') if ! $fh;
	$self->OK('Message follows');
	my $start = tell($fh);
	my $body_lines;
	while (defined( my $line = <$fh>)) {
	    last if tell($fh) - $start > $size;
	    $line =~s{\r?\n\z}{};
	    $line =~s{^\.}{..};
	    $self->out($line);
	    if (defined $body_lines) {
		$body_lines++;
		last if $body_lines >= $lines;
	    } else {
		$body_lines = 0  if $line eq ''
	    }
	}
	return $self->out('.');
    }

    $self->ERR("unsupported cmd $cmd");
}
	    
    
sub do_auth {
    my ($self,$line) = @_;
    return $self->OK("auth canceled") if $line =~m{^\*\s*$};
    # last response
    $self->{handler} = \&do_command;
    $self->{logged_in} = 1;
    return $self->OK('Logged in');
}


package MBox;
BEGIN { *debug = \&::debug }
use File::Find;

sub new {
    my ($class,$mbox,$with_index) = @_;
    if ($with_index) {
	require MimeGen::Common;
	$with_index = \&MimeGen::Common::mail_chksum;
    }
    my (@mail,$fh); 
    my $self = bless {
	mails => \@mail,
	size => 0,
    },$class;

    if ( -f $mbox and open(my $fh,'<',$mbox)) {
	debug( "Reading Mailbox $mbox" );
	my ($begin,$end); 
	while (defined(my $line = <$fh>)) {
	    if ($line =~m{^From\s+.*\s+\d{4}\s*$}) {  # mbox delimiter
		push @mail,{
		    fh     => $fh,
		    offset => $begin,
		    size   => $end-$begin,
		} if $begin;
		$end = $begin = tell($fh);
	    } else {
		$end = tell($fh);
	    }
	}
	push @mail, {
	    fh     => $fh,
	    offset => $begin,
	    size   => $end-$begin,
	} if $begin and $begin != $end;
    
    } elsif ( -d $mbox) {
	debug("Using Mailfolder $mbox");
	find(sub {
	    -f $_ or return;
	    my $size = -s _ or return;
	    push @mail, {
		file => $File::Find::name,
		offset => 0,
		size => $size,
	    };
	}, $mbox);

    } else { 
	die "cannot read $mbox";
    }

    if ($with_index) {
	my $index = "To: me\nFrom: you\nSubject: INDEX\n\n";
	for(my $i=0;$i<@mail;$i++) {
	    my ($fh,$size) = $self->openmail($i+1);
	    read($fh, my $buf, $size);
	    $index .= sprintf("%s %s\n", $with_index->($buf),
		$hdr =~m{^Subject:\s*([^\n]*)}mi && $1);
	}

	unshift @mail, {
	    data => $index,
	    size => length($index),
	};
    }
    
    my $mbxsize = 0; 
    $mbxsize+= $_->{size} for @mail;
    debug("mbox <%s> %d messages %d octets",$mbox,~~@mail,$mbxsize);
    $self->{size} = $mbxsize;

    return $self;
}
    
    
sub mails { shift->{mails} };
sub size  { shift->{size} };

sub openmail {
    my ($self,$id) = @_;
    return if $id<0;
    my $mail = $self->{mails}[$id-1] or return;
    debug( "retrieve message $id" );
    if (my $fh =  $mail->{fh}) {
	seek($fh,$mail->{offset},0) or die "seek failed: $!";
	return ($fh,$mail->{size})
    } elsif (my $file =  $mail->{file}) {
	open(my $fh,'<',$file) or die "open $file: $!";
	seek($fh,$mail->{offset},0) if $mail->{offset};
	return ($fh,$mail->{size})
    } elsif (my $data = $mail->{data}) {
	open(my $fh,'<',\$data);
	return ($fh,$mail->{size});
    } else {
	die "bad mail";
    }
}



