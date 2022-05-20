#!/usr/bin/perl
use strict;
use warnings;

# ----- configuration - adapt as needed ---------------------------------------
#my $dst = '127.0.0.1:1025';     # target mail server or firewall
my $dst = '172.19.16.16:25';    # target mail server or firewall
my $ssl = '';                   # ''|'starttls'|'ssl'
my $user = '';                  # optional authentication user ...
my $pass = '';                  # ... and authentication password
my $from = 'me@example.com';    # sender
my $to = 'you@example.com';     # recipient
my $host = 'example.com';       # hostname argument for HELO|EHLO
# -----------------------------------------------------------------------------

my $DEBUG = 0;


use Net::SMTP;
die "need Authen::SASL" if $user && ! require Authen::SASL;
if ($ssl) {
    die "need Net::SMTP>= 3.0" if ! defined &Net::SMTP::starttls;
    die "need IO::Socket::SSL" if ! Net::SMTP->can_ssl;
}


my $id = sprintf("%08x",time());
warn "ID: $id\n";

my @files = @ARGV or die "no files given";
my $msgi = 0;
while (my $file = shift @files) {
    if (-d $file) {
	unshift @files, glob("$file/*");
	next;
    }
    -f $file or next;

    my $data = do {
	open(my $fh,'<',$file) or die "failed to open $file: $!";
	local $/;
	<$fh>;
    };

    $data =~s{^(Message-Id|From|To):.*(?:\n[ \t].*)*\n}{}mig;
    $data = sprintf("Message-Id: <testid_%s.%07d\@%s>\nFrom: %s\nTo: %s\n",
	$id,++$msgi,$host,$from,$to) . $data;
    $data =~s{\r?\n}{\r\n}g;
    my $subj = 
	$data =~m{^X-Payload-Id:\s*(\S+)}mi ? $1 :
	$data =~m{^Subject:\s*(.*?)\r\n}mi ? $1 :
	'-';

    my $smtp = Net::SMTP->new($dst, 
	Hello => $host, 
	SSL => $ssl && $ssl eq 'ssl', 
	Debug => $DEBUG
    ) or do {
	die "can not connect to $dst: $!\n";
    };

    my $must_succeed = sub {
	my ($cmd,@arg) = @_;
	$smtp->$cmd(@arg) and return 1;
	die "fatal SMTP error in $cmd: ".$smtp->message;
    };

    if ($user) {
	$smtp->starttls() or die "starttls failed: $IO::Socket::SSL::SSL_ERROR"
	    if $ssl && $ssl eq 'starttls';
	$must_succeed->('auth',$user,$pass);
    }

    $must_succeed->('mail',$from);
    $must_succeed->('to',$to);
    $must_succeed->('data');

    if ($smtp->datasend($data) && $smtp->dataend) {
	my ($reply) = $smtp->message =~m{([^\r\n]+)[\r\n]*\Z};
	warn "send $file ($subj) ok: $reply\n";
    } else {
	warn "send $file ($subj) failed: ".$smtp->message;
    }
    $smtp->quit;
}

