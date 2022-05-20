use strict;
use warnings;
package MimeGen::Base64;
use MimeGen::Common;
use MIME::Base64 'encode_base64';
use Exporter 'import';
our @EXPORT = 'base64';

sub _basic {
    my @body = @_;
    return [ ESSENTIAL, 'basic', map { encode_base64($_) } @body ];
}

# Prefer this one in more complex tests to deter autodetection heuristics
# of base64 in antivirus. Treat as VALID instead of UNCOMMON so that it
# gets used.
sub _mixedlen {
    my @body = @_;
    my @newbody;
    for my $body (@body) {
	$body = encode_base64($body,'');
	my $newbody = '';
	my @order = (4,4,8,8,16,16,32,32,64);
	while ($body ne '') {
	    my $l = shift(@order);
	    push @order,$l;
	    $newbody .= substr($body,0,$l,'')."\n";
	}
	push @newbody, $newbody;
    }
    return [ VALID, 'mixedlen', @newbody ];
}

sub _whitespace {
    my @body = map { encode_base64($_) } @_;
    my @r;
    for(
	[ 'emptyline', sub { s{\n}{\n\n}g } ],
	[ 'space',     sub { s{(.)}{$1 }g } ],
	[ 'tab',       sub { s{(.)}{$1\t}g } ],
	[ 'vtab',      sub { s{(.)}{$1\013}g } ],
	[ 'cr',        sub { s{(.)}{$1\r}g } ],
	[ 'char+nlnl',  sub { s{(.)}{$1\n\n}g } ],
	[ '2char+nlnl', sub { s{(..)}{$1\n\n}g } ],
	[ '3char+nlnl', sub { s{(...)}{$1\n\n}g } ],
    ) {
	my ($id,$sub) = @$_;
	push @r, [ UNCOMMON, $id, map { local $_=$_; &$sub; $_ } @body ]
    }
    return traverse_sub(ESSENTIAL,'ws',\@r);
}

sub _junk {
    my @body = map { encode_base64($_) } @_;
    my @r;
    for(
	[ 'hash', sub { s{(.)}{$1#}g } ],
	[ 'colon', sub { s{(.)}{$1:}g } ],
	[ 'dot', sub { s{(.)}{$1.}g } ],
	[ 'percent', sub { s{(.)}{$1%}g } ],
	[ 'minus', sub { s{(.)}{$1-}g } ],
	[ 'underscore', sub { s{(.)}{$1_}g } ],
	[ 'b64header', sub {
	    $_ = "begin-base64 744 foobar.pdf\n$_====\n";
	}],
	[ '4tuple+hash+b64nl', sub { s{^(....)}{$1#abce01234567fghj\n}mg } ],
	[ '3tuple+hash+b64nl', sub { s{^(...)}{$1#abce01234567fghj\n}mg } ],
	[ '1j64+nlnl+real64',  sub { $_ = "A\n\n" . $_ } ],
	[ '2j64+nlnl+real64',  sub { $_ = "AB\n\n" . $_ } ],
	[ '3j64+nlnl+real64',  sub { $_ = "ABC\n\n" . $_ } ],
    ) {
	my ($id,$sub) = @$_;
	push @r, [ INVALID, $id, map { local $_=$_; &$sub; $_ } @body ]
    }
    return traverse_sub(ESSENTIAL,'junk',\@r);
}

sub _xtraeq {
    my @body = map { encode_base64($_) } @_;
    my @r;
    for(
	[ 'eodata', sub { s{\n\z}{=\n} } ],
	[ 'eoline', sub { 
	    s{(....)}{$1\n} if !m{\n.}; # make multiline if its not yet
	    s{\n}{=\n}g 
	}],
	[ 'singleline', sub { s{^}{=\n} } ],
	[ 'singleline4', sub { s{^}{====\n} } ],
	[ 'eoquad', sub { s{([\w+/]{4})}{$1=}g } ],
	[ 'insidequad', sub { s{([\w+/]{2})([\w+/]{2})}{$1=$2}g } ],
	[ 'linestart', sub { s{^}{=}mg } ],
	[ 'linestart4', sub { s{^}{====}mg } ],
    ) {
	my ($id,$sub) = @$_;
	push @r, [ INVALID, $id, map { local $_=$_; &$sub; $_ } @body ]
    }

    @body = ();
    for (@_) {
	my $body = '';
	for(m{(.)}sg) {
	    # XX== -> XX=
	    ( my $e = encode_base64($_,'') ) =~s{==}{=};
	    $body .= $e;
	}
	$body =~s{(.{1,76}=)}{$1\n}g;
	push @body, $body;
    }
    push @r, [ INVALID, 'miss1of2', @body ];

    @body = ();
    for (@_) {
	my $body = '';
	for(m{(.)}sg) {
	    # XX== -> XX=
	    ( my $e = encode_base64($_,'') ) =~s{==}{=\n};
	    $body .= $e;
	}
	$body =~s{(.{1,76}=)}{$1\n}g;
	push @body, $body;
    }
    push @r, [ INVALID, 'miss1of2.nl', @body ];

    return traverse_sub(ESSENTIAL,'xtraeq',\@r);
}

sub _linelength {
    my @body = map { encode_base64($_,'') } @_;
    my @r;
    for(
	[ UNCOMMON, '3', sub { s{(.{1,3})}{$1\n}g } ],
	[ VALID, '4', sub { s{(.{1,4})}{$1\n}g } ],
	[ UNCOMMON, '5', sub { s{(.{1,5})}{$1\n}g } ],
	[ UNCOMMON, '6', sub { s{(.{1,6})}{$1\n}g } ],
	[ INVALID, '4X', sub { s{(.{1,4})}{$1X\n}g } ],
	[ INVALID, '4XX', sub { s{(.{1,4})}{$1XX\n}g } ],
	[ INVALID, '4XXX', sub { s{(.{1,4})}{$1XXX\n}g } ],
	[ INVALID, '4=', sub { s{(.{1,4})}{$1=\n}g } ],
    ) {
	my ($valid,$id,$sub) = @$_;
	push @r, [ $valid, $id, map { local $_=$_; &$sub; $_ } @body ]
    }
    return traverse_sub(ESSENTIAL,'linelen',\@r);
}

sub _badeq {
    my @body = @_;
    my @r = (
	# two chars encoded into ABC= and then transformed to:
	[ INVALID, 'tuple0', ],   # =ABC
	[ INVALID, 'tuple1', ],   # A=BC
	[ INVALID, 'tuple2', ],   # AB=C
	[ INVALID, 'tupleE', ],   # ABC=
	# in the above case we can have multiple tuples in one line
	# tupleLE has only a single ABC= tuple per line
	[ INVALID, 'tupleLE', ],
    );
    for(@body) {
	my @p = map { encode_base64($_,'') } m{(.{1,2})}sg;
	my $line0 = join('', map { local $_=$_; s{(.*)=$}{=$1}g; $_ } @p);
	my $line1 = join('', map { local $_=$_; s{(.)(.*)=$}{$1=$2}g; $_ } @p);
	my $line2 = join('', map { local $_=$_; s{(..)(.*)=$}{$1=$2}g; $_ } @p);
	my $lineE = join('', @p);
	my $lineLE = join('',map { "$_\n" } @p);
	s{(.{1,60})}{$1\n}g for ($line0,$line1,$line2,$lineE);
	push @{$r[0]}, $line0;
	push @{$r[1]}, $line1;
	push @{$r[2]}, $line2;
	push @{$r[3]}, $lineE;
	push @{$r[4]}, $lineLE;
    }

    # Thunderbird treats = in the middle of a 4-tuple like 'A' but still
    # strips the number of occured '=' from the end of the deocoded result
    # This means wie can encode all single bytes of form 0bxxxxxx00 with
    # encode_base64 into ?A== and then change it to ?==A or ?=A= without
    # affecting the result :)
    my @newbody;
    for (@body) {
	my @bytes = unpack('C*',$_);
	my $raw = my $enc = '';
	while (@bytes) {
	    my $c = shift(@bytes);
	    if ($c % 4 == 0) {
		# $c is 0bxxxxxx00 and can be encoded in a special way
		if ($raw ne '') {
		    $enc .= encode_base64($raw);
		    $raw = '';
		}
		my $b64 = encode_base64(chr($c));
		$b64 =~s{A==}{=A=};
		$enc .= $b64;
	    } else {
		$raw .= chr($c);
	    }
	}
	$enc .= encode_base64($raw) if $raw ne '';
	push @newbody, $enc;
    }
    push @r, [INVALID, 'X=A=', @newbody];

    # Safari treats '=' in the middle same as 'A', i.e. 'XYZ=0123' is the
    # same as 'XYZA0123'. Thus try to replace all A inside with '='.
    # But don't change the last quadruple!
    push @r, [INVALID, 'Ax2=x', map {
	my $x = encode_base64($_);
	$x =~s{A(.)}{=$1}g;
	while ($x =~s{=([a-zA-Z0-9/+].{0,2}\n)\z}{A$1}) {}
	$x;
    } @body];

    return traverse_sub(ESSENTIAL,'badeq',\@r);
}

sub _more_after_eq {
    my @body = @_;
    my @r;

    # first real data, than junk data
    my $more = <<'BASE64'; # test.zip with innocent test.txt inside
UEsDBAoAAAAAAO6Tn0m2hH8nEwAAABMAAAAIABwAdGVzdC50eHRVVAkAA3DrZ1iZbGlYdXgLAAEE
6QMAAATpAwAAaW5ub2NlbnQgdGVzdCBmaWxlClBLAQIeAwoAAAAAAO6Tn0m2hH8nEwAAABMAAAAI
ABgAAAAAAAEAAAC0gQAAAAB0ZXN0LnR4dFVUBQADcOtnWHV4CwABBOkDAAAE6QMAAFBLBQYAAAAA
AQABAE4AAABVAAAAAAA=
BASE64
    my @newbody;
    for (@body) {
	my $body = encode_base64($_);
	$body .= '====' if !m{=};
	$body .= $more;
	push @newbody, $body;
    }
    push @r, [ INVALID, 'junk_after_eq', @newbody ];

    # only real data but split into two chunks where first ends with '='
    @newbody = ();
    for (@body) {
	my $l0 = int(int(length($_)/2)/3)*3+2;
	my $body = encode_base64(substr($_,0,$l0));
	$body .= encode_base64(substr($_,$l0));
	push @newbody, $body;
    }
    push @r, [ INVALID, 'split:1=2', @newbody ];

    # only real data but split into two chunks where first ends with '=='
    @newbody = ();
    for (@body) {
	my $l0 = int(int(length($_)/2)/3)*3+1;
	my $body = encode_base64(substr($_,0,$l0));
	$body .= encode_base64(substr($_,$l0));
	push @newbody, $body;
    }
    push @r, [ INVALID, 'split:1==2', @newbody ];

    return @r;
}

sub base64 {
    my @body = @_;
    return traverse_sub(ESSENTIAL, 'base64', [
	_mixedlen(@body), # in front so that this gets used for complex tests
	_basic(@body),
	_whitespace(@body),
	_junk(@body),
	_xtraeq(@body),
	_linelength(@body),
	_badeq(@body),
	_more_after_eq(@body),
    ]);
}

1;
