use strict;
use warnings;
use Net::POP3;
use Getopt::Long qw(:config posix_default bundling);
use Digest::MD5;
use File::Temp 'tempfile';
BEGIN { unshift @INC,$1 if $0 =~m{(.*)/}s; }

sub usage {
    print STDERR "ERROR: @_\n" if @_;
    print STDERR <<'USAGE';

Read mails from given POP server and store in mbox format (stdout).
If --changed is given it will expect the first mail to be an index containing hash
of each following mail. In this case it will write to stderr the status of the
mail ('change' or 'match') and also add a header to the mail in the target mbox.

Usage: $0 [options] host[:port]
Options
  -h             Help (this info)
  -d             Debug
  -U|--user U    login as user
  -P|--user P    login with pass
  -c|--changed   use mail#1 as index to check for modifications
                 Default: checks content of first mail
		 To switch off that check use --no-changed
  -w|--write M   target maildir/mailbox instead of stdout
USAGE
    exit(2);
}

my $user = 'test';
my $pass = 'secret';
my $changed = -1;
my $DEBUG;
my $dst;
GetOptions(
    'h|help'     => sub { usage() },
    'd|debug!'   => \$DEBUG,
    'U|user=s'   => \$user,
    'P|pass=s'   => \$pass,
    'c|changed!' => \$changed,
    'w|write=s'  => \$dst,
) or usage('bad option');
my $addr = $ARGV[0] || die "no host given";


my $mbfh = 
    ! $dst ? \*STDOUT :
    ! -d $dst ? do { open(my $fh,'>',$dst) or die $!; $fh } :
    undef;

my $mkchksum;
my $index;
my $cl;
for(my $i=1;1;$i++) {
    if (!$cl) {
	$cl = Net::POP3->new($addr, Debug => $DEBUG) or die "connect failed: $@";
	$cl->login($user,$pass) or die "login failed: ".$cl->message;
    }
    my ($msg) = $cl->get($i);
    my ($status,$subject);
    if (!$msg) {
	# either end of message or broken
	if ($index) {
	    my $idx = $index->[$i-2] or last; # no more messages expected?
	    $status = 'lost';
	    $subject = $idx->[1];
	    $msg = [ 
		"X-Status: lost message $i\n", 
		"Subject: $idx->[1]\n",
		"\n",
		$cl->message."\n",
	    ];
	    $cl = undef;
	} elsif (!defined fileno($cl)) {
	    $status = 'lost';
	    $subject = '?';
	    $msg = [ "X-Status: lost message $i\n", "\n","eof\n" ];
	    $cl = undef;
	} elsif ($cl->code == 500) {
	    # -ERR, probably no more messages
	    last;
	} else {
	    die "no message but code=".$cl->code." message=".$cl->message;
	}
    }
    $msg or last;
    $msg = join('',@$msg);
    if ($changed && $i == 1) {
	if ($msg =~m{\nSubject:[ ]*INDEX\n}is) {
	    (my $body = $msg) =~s{^.*?(\r?\n)\1}{}s;
	    $index = [];
	    for(split(m{\r?\n},$body)) {
		my ($chksum,$subject) = split(' ',$_,2);
		push @$index, [$chksum, $subject];
	    }
	}
	die "got no index" if !$index && $changed>0;
	next;
    }

    if ($index && !$status) {
	my $x = $index->[$i-2] or die "no data for message ".($i-2)." in index";
	(my $chksum_orig,$subject) = @$x;
	$mkchksum ||= do {
	    require MimeGen::Common;
	    \&MimeGen::Common::mail_chksum;
	};
	$status = $md5_orig eq $mkchksum->($msg) ? 'match' : 'change';
    }

    if ($status) {
	$status = sprintf("%6s | %s",$status,$subject);
	print STDERR "$status\n";
	$msg = "X-Transfer-Modification: $status\n" . $msg;
    }

    if ($mbfh) {
	print $mbfh "From - Mon Jan  2 01:01:01 2000\n",$msg;
    } else {
	my ($fh) = tempfile("mailXXXX", DIR => -d "$dst/new" ? "$dst/new" : $dst);
	print $fh $msg;
    }
}
