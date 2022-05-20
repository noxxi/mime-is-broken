#!/usr/bin/perl

use strict;
use warnings;

# ----- configuration - adapt as needed ---------------------------------------
my $addr = '0.0.0.0:25';     # where to listen
my $chguser = 'work';        # user to change to if started as root
my $outdir = 'delivered-mails/new';   # output directory, must be writable by $chguser
my $cert = undef; # 'cert.pem';       # cert + key as PEM if SSL should be offered
my $hostname = 'mail.example.com';   # hostname in welcome message
# -----------------------------------------------------------------------------


use IO::Socket::SSL;
use File::Temp 'tempfile';
use POSIX 'setuid';

my $INETCLASS;
BEGIN {
    $INETCLASS = 
	eval "use IO::Socket::IP; 'IO::Socket::IP'" ||
	eval "use IO::Socket::INET6; 'IO::Socket::INET6'" ||
	'IO::Socket::INET';
}

-d $outdir or die "$outdir: no such directory";

my $sslctx;
if ($cert) {
    $sslctx = IO::Socket::SSL::SSL_Context->new(
	SSL_server => 1,
	SSL_cert_file => $cert,
	SSL_key_file => $cert,
    ) or die "failed to create SSL context: $SSL_ERROR";
}

my $srv = $INETCLASS->new(
    LocalAddr => $addr,
    Listen => 10,
    ReuseAddr => 1,
) or die "listen on $addr failed: $!";

if ($chguser && $< == 0) {
    my $uid = getpwnam($chguser) // die "no such user $chguser";
    setuid($uid);
    -w $outdir or die "$outdir: not writable for $chguser";
}

$SIG{CHLD} = 'IGNORE'; # auto-reap
while (1) {
    my $cl = $srv->accept or next;
    defined( my $pid = fork() ) or die "fork failed: $!";
    next if $pid;  # parent
    child($cl);
    exit(0);
}

sub child {
    my $cl = shift;
    my $mode = '';
    my $mail = {};
    while (1) {
	alarm(10);
	if (!$mode) {
	    print $cl "220 welcome $hostname\r\n";
	    $mode = 'cmd';
	} elsif ($mode eq 'cmd') {
	    defined(my $cmd = <$cl>) or return;
	    ($cmd,my $arg) = split(' ',$cmd,2);
	    $cmd = uc($cmd);
	    my $sub = UNIVERSAL::can(__PACKAGE__,"_cmd_$cmd");
	    my $reply = $sub && $sub->($mail,$cmd,$arg,$cl) 
		|| '500 bad command';
	    if ($cmd eq 'DATA' && $reply =~m{^3}) {
		$mode = 'data';
		$mail->{data} = '';
	    }
	    $reply =~s{\r?\n}{\r\n}g;
	    print $cl "$reply\r\n";
	    return if $cmd eq 'QUIT';
	} elsif ($mode eq 'data') {
	    (my $line = <$cl>) =~s{\r}{}g;
	    if ($line eq ".\n") {
		$mode = 'cmd';
		my ($fh,$file) = tempfile('mailXXXXXX', DIR => $outdir);
		print $fh $mail->{data};
		my ($id) = 
		    $mail->{data} =~m{^X-Payload-Id:\s*(\S+)}mi ? $1 :
		    $mail->{data} =~m{^Message-Id:\s*(\S+)}mi ? $1 :
		    '<??>';
		print $cl "250 ok\r\n";
		warn "received $id - $file\n";
		$mail = {};
	    } else {
		$line =~s{\A\.}{};
		$mail->{data} .= $line;
	    }
	}
    }
}

sub _cmd_HELO { "250 $hostname" }
sub _cmd_EHLO { $sslctx ? "250-$hostname\n250 STARTTLS" : "250 $hostname" }
sub _cmd_STARTTLS {
    my $cl = $_[3];
    return "500 unsupported" if ! $sslctx;
    return "220 ok" if IO::Socket::SSL->start_SSL($cl,
	SSL_server => 1,
	SSL_reuse_ctx => $sslctx,
    );
    return "500 starttls failed";
}

sub _cmd_MAIL { "250 ok" }
sub _cmd_RCPT { "250 ok" }
sub _cmd_DATA { "354 ok" }

sub _cmd_RSET { my $mail = shift; %$mail = (); "250 ok" }
sub _cmd_QUIT { "250 ok" }
