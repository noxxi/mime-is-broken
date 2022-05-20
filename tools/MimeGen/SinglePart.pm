use strict;
use warnings;
package MimeGen::SinglePart;

use MimeGen::Common;
use MimeGen::Base64;
use MimeGen::QuotedPrint;
use MIME::Base64 'encode_base64';
use MIME::Decoder;
use Compress::Zlib 'memGzip';
use Exporter 'import';
our @EXPORT = qw(singleparts);

my $default_base64 = \&MimeGen::Base64::_mixedlen;

sub _single_noencoding {
    my @parts = @_;
    return [ 
	merge_validity( map { 
	    # INVALID if any non-ASCII or control characters are used
	    $_->[1] =~m{[\x00-\x08\x0b-\x1f\x7f-\xff]} ? INVALID : ESSENTIAL 
	} @parts),
	'noenc', 
	map { "$_->[0]\n$_->[1]\n" } @parts 
    ];
}

sub _single_base64  {
    my @parts = @_;
    my @r;
    my $H = 'Content-Transfer-Encoding';

    # All base64 variantes only for basic.
    my $b64subs = base64(map { $_->[1] } @parts);
    push @r, sub {
	my $b64 = $b64subs->() or return;
	return [
	    $b64->[0],
	    "basic-$b64->[1]",
	    map { "$parts[$_][0]$H: base64\n\n".$b64->[2+$_] } (0..$#parts)
	]
    };

    my $b64_default = $default_base64->(map { $_->[1] } @parts);
    # All the other tests only with $base64_valid payload and not with all the
    # other base64 variants
    for my $test (
	[ ESSENTIAL, 'nospace',       "$H:base64\n" ],
	[ VALID,     'tab',           "$H:\tbase64\n" ],
	[ INVALID,   'vtab',          "$H:\013base64\n" ],
	[ INVALID,   'cr',            "$H:\rbase64\n" ],
	[ VALID,     'baSE64',        "$H: baSE64\n" ],
	[ INVALID,   'x-base64',      "$H: x-base64\n" ],
	[ VALID,     'fold',          "$H:\n base64\n" ],
	[ VALID,     '2fold',         "$H:\n \n base64\n" ],
	[ INVALID,   'ws2000_base64', "$H: ".(' ' x 2000)."base64\n" ],
	[ INVALID,   'quote',         "$H: \"base64\"\n" ],
	[ INVALID,   'escape',        "$H: base\\64\n" ],
	[ INVALID,   'rfc2047b',      "$H: =?UTF-8?B?YmFzZTY0?=\n" ],
	[ INVALID,   'rfc2047q',      "$H: =?UTF-8?Q?base64\n" ],
	[ INVALID,   'comment-enc',   "$H: (xx) base64\n" ],
	[ INVALID,   'enc-comment-oding', "$H: bas()e64\n" ],
	[ INVALID,   'enc-foldcomment-oding', "$H: bas(\n )e64\n" ],
	[ INVALID,   'enc-comment',   "$H: base64 (xx)\n" ],
	[ INVALID,   'xx-enc',        "$H: xx base64\n" ],
	[ INVALID,   'enc-xx',        "$H: base64 xx\n" ],
	[ INVALID,   'xxenc',         "$H: xxbase64\n" ],
	[ INVALID,   'encxx',         "$H: base64xx\n" ],
	[ INVALID,   'enc-comma',     "$H: base64,\n" ],
	[ INVALID,   'comma-enc',     "$H: ,base64\n" ],
	[ INVALID,   'enc-semicolon', "$H: base64;\n" ],
	[ INVALID,   'semicolon-enc', "$H: ;base64\n" ],
	[ INVALID,   'space-colon',   "$H : base64\n" ],
	[ INVALID,   'double-colon',  "$H\:: base64\n" ],
	[ INVALID,   'space-key',     " $H: base64\n" ],
	[ INVALID,   'cr-key',        "\r$H: base64\n" ],
	[ INVALID,   'onlycr-key',    "X-Foo: bar\r$H: base64\n" ],
	[ INVALID,   'nocolon',       "$H base64\n" ],
	[ INVALID,   'qp64',          "$H: quoted-printable\n$H: base64\n" ],
	[ INVALID,   '64qp',          "$H: base64\n$H: quoted-printable\n" ],
	[ INVALID,   'qp_ws_64',      "$H: quoted-printable base64\n" ],
	[ INVALID,   '64_ws_qp',      "$H: base64 quoted-printable\n" ],
	[ INVALID,   'qp,64',         "$H: quoted-printable,base64\n" ],
	[ INVALID,   '64,qp',         "$H: base64,quoted-printable\n" ],
	[ INVALID,   'empty64',       "$H: \n$H: base64\n" ],
	[ INVALID,   '64empty',       "$H: base64\n$H: \n" ],
	[ INVALID,   'junk64',        "$H: xxx\n$H: base64\n" ],
	[ INVALID,   '64junk',        "$H: base64\n$H: xxx\n" ],
	[ INVALID,   'pfx:junkline',  "XXXXXXXXXX\n$H: base64\n" ],
	[ INVALID,   'pfx:junkline8bit',"\001\002\003\n$H: base64\n" ],
	[ INVALID,   'pfx:spaceline', " \n$H: base64\n" ],
    ) {
	my ($valid,$id,$h) = @$test;
	my $done;
	push @r, sub {
	    return if $done++;
	    return [
		merge_validity($b64_default->[0],$valid),
		"$id-$b64_default->[1]",
		map { $parts[$_][0].$h."\n".$b64_default->[2+$_] } (0..$#parts)
	    ]
	};
    }
    return traverse_sub(ESSENTIAL,'b64h',\@r);
}

sub _single_qp  {
    my @parts = @_;
    my @r;
    my $H = 'Content-Transfer-Encoding';

    # All QP variantes only for basic. The first valid variant returned
    # by this is used as payload for the following tests.
    my $qpsubs = quotedprint(map { $_->[1] } @parts);
    my $qp_valid;
    push @r, sub {
	my $qp = $qpsubs->() or return;
	$qp_valid ||= $qp->[0] >= VALID && $qp;
	return [
	    $qp->[0],
	    "basic-$qp->[1]",
	    map { "$parts[$_][0]$H: quoted-printable\n\n".$qp->[2+$_] } (0..$#parts)
	]
    };

    # All the other tests only with $qp_valid payload and not with all the
    # other qp variants
    for my $test (
	[ INVALID,   'x-qp',          "$H: x-quoted-printable\n" ],
	[ INVALID,   'qp64',          "$H: quoted-printable\n$H: base64\n" ],
	[ INVALID,   '64qp',          "$H: base64\n$H: quoted-printable\n" ],
	[ INVALID,   'qp_ws_64',      "$H: quoted-printable base64\n" ],
	[ INVALID,   '64_ws_qp',      "$H: base64 quoted-printable\n" ],
	[ INVALID,   'qp,64',         "$H: quoted-printable,base64\n" ],
	[ INVALID,   '64,qp',         "$H: base64,quoted-printable\n" ],
	[ INVALID,   'emptyQP',       "$H: \n$H: quoted-printable\n" ],
	[ INVALID,   'QPempty',       "$H: quoted-printable\n$H: \n" ],
	[ INVALID,   'junkQP',        "$H: xxx\n$H: quoted-printable\n" ],
	[ INVALID,   'QPjunk',        "$H: quoted-printable\n$H: xxx\n" ],
	[ INVALID,   'abbr0',         "$H: quoted-printabl\n" ],
	[ INVALID,   'abbr1',         "$H: quoted-print\n" ],
	[ INVALID,   'abbr2',         "$H: quotedprint\n" ],
    ) {
	my ($valid,$id,$h) = @$test;
	my $done;
	push @r, sub {
	    return if $done++;
	    return [ 
		merge_validity($qp_valid->[0],$valid), 
		"$id-$qp_valid->[1]", 
		map { $parts[$_][0].$h."\n".$qp_valid->[2+$_] } (0..$#parts)
	    ];
	};
    }
    return traverse_sub(ESSENTIAL,'qph',\@r);
}

sub _single_uu {
    my @parts = @_;
    my @rv;
    for my $cte (qw(uuencode x-uuencode uue x-uue x-uu)) {
	push @rv, [ INVALID, $cte, map { 
	    "$_->[0]Content-Transfer-Encoding: $cte\n\n".pack("u",$_->[1]) 
	} @parts ];
	push @rv, [ INVALID, "$cte.begin", map { 
	    "$_->[0]Content-Transfer-Encoding: $cte\n\nbegin 644 file.bin\n".pack("u",$_->[1]) 
	} @parts ];
	push @rv, [ INVALID, "$cte.begin.end", map { 
	    "$_->[0]Content-Transfer-Encoding: $cte\n\nbegin 644 file.bin\n".pack("u",$_->[1])."`\nend\n" 
	} @parts ];
    }
    return @rv;
}

sub _single_yenc {
    my @parts = @_;
    my @rv;
    for my $cte (qw(x-yencode)) {
	push @rv, [ INVALID, $cte, map { 
	    "$_->[0]Content-Transfer-Encoding: $cte\n\n".yenc_encode("file.bin",$_->[1]) 
	} @parts ];
    }
    return @rv;
}

sub _single_binhex {
    my $binhex = MIME::Decoder->new('binhex');
    my @parts;
    for(@_) {
	push @parts,[ $_->[0],'' ];
	open(my $in,'<',\$_);
	open(my $out,'>',\$parts[-1][1]);
	$binhex->encode($in,$out);
    }
    return ([
	INVALID,
	'binhex',
	map { "$_->[0]Content-Transfer-Encoding: binhex\n\n$_->[1]" } @parts
    ], [
	INVALID,
	'binhex40',
	map { "$_->[0]Content-Transfer-Encoding: binhex40\n\n$_->[1]" } @parts
    ], [
	INVALID,
	'mac-binhex40',
	map { "$_->[0]Content-Transfer-Encoding: mac-binhex40\n\n$_->[1]" } @parts
    ], [
	INVALID,
	'mac-binhex',
	map { "$_->[0]Content-Transfer-Encoding: mac-binhex\n\n$_->[1]" } @parts
    ]);
}

sub _single_base64_bad_header_body_break  {
    my @parts = @_;
    my (undef,$sid,@body) = @{ $default_base64->(map { $_->[1] } @parts) };
    for(my $i=0;$i<@parts;$i++) {
	$parts[$i] = [
	    $parts[$i][0] . "Content-Transfer-Encoding: base64\n",
	    $body[$i]."\n"
	];
    }
    return traverse_sub(ESSENTIAL,'b64_HB_delim', [[
	INVALID,
	"none-$sid",
	map { $_->[0].$_->[1] } @parts,
    ], [
	INVALID,
	"space_nl-$sid",
	map { $_->[0]." \n".$_->[1] } @parts,
    ], [
	INVALID,
	"2x_space_nl-$sid",
	map { $_->[0]." \n \n".$_->[1] } @parts,
    ], [
	INVALID,
	"tab_nl-$sid",
	map { $_->[0]."\t\n".$_->[1] } @parts,
    ], [
	INVALID,
	"vt_nl-$sid",
	map { $_->[0]."\013\n".$_->[1] } @parts,
    ], [
	INVALID,
	"2x_vt_nl-$sid",
	map { $_->[0]."\013\n\013\n".$_->[1] } @parts,
    ], [
	INVALID,
	"4B_nl-$sid",
	map { $_->[0].substr($_->[1],0,4)."\n\n".substr($_->[1],4) } @parts,
    ], [
	INVALID,
	"4JB_nl-$sid",
	map { $_->[0]."ABCD\n\n".$_->[1] } @parts,
    ], [
	INVALID,
	"JB=_nl-$sid",
	map { $_->[0]."ABC=\n\n".$_->[1] } @parts,
    ], [
	INVALID,
	"4JB_wsnl-$sid",
	map { $_->[0]."ABCD\n \n".$_->[1] } @parts,
    ], [
	INVALID,
	"JB=_wsnl-$sid",
	map { $_->[0]."ABC=\n \n".$_->[1] } @parts,
    ], [
	INVALID,
	"4JB_nonl-$sid",
	map { $_->[0]."ABCD\n".$_->[1] } @parts,
    ], [
	INVALID,
	"JB=_nonl-$sid",
	map { $_->[0]."ABC=\n".$_->[1] } @parts,
    ], [
	INVALID,
	"4JB_4JB_nl-$sid",
	map { $_->[0]."ABCD\nABCD\n\n".$_->[1] } @parts,
    ], [
	INVALID,
	"JB=JB=_nl-$sid",
	map { $_->[0]."ABC=\nABC=\n\n".$_->[1] } @parts,
    ], [
	INVALID,
	"none_nl_junkB-$sid",
	map { $_->[0].$_->[1]."\n".<<'BASE64_ZIP' } @parts,
UEsDBAoAAAAAAO6Tn0m2hH8nEwAAABMAAAAIABwAdGVzdC50eHRVVAkAA3DrZ1iZbGlYdXgLAAEE
6QMAAATpAwAAaW5ub2NlbnQgdGVzdCBmaWxlClBLAQIeAwoAAAAAAO6Tn0m2hH8nEwAAABMAAAAI
ABgAAAAAAAEAAAC0gQAAAAB0ZXN0LnR4dFVUBQADcOtnWHV4CwABBOkDAAAE6QMAAFBLBQYAAAAA
AQABAE4AAABVAAAAAAA=
BASE64_ZIP
    ]]);
}

sub _single_base64_bad_header_start  {
    my @parts = @_;
    my (undef,$sid,@body) = @{ $default_base64->(map { $_->[1] } @parts) };
    for(my $i=0;$i<@parts;$i++) {
	$parts[$i] = "Content-Transfer-Encoding: base64\n$parts[$i][0]\n$body[$i]\n";
    }
    return traverse_sub(ESSENTIAL,'hdrstart_b64', [
	[ INVALID, "cr-$sid", map { "\r$_" } @parts ],
	[ INVALID, "nl-$sid", map { "\n$_" } @parts ],
	[ INVALID, "vt-$sid", map { "\013$_" } @parts ],
	[ INVALID, "spacenl-$sid", map { " \n$_" } @parts ],
	[ INVALID, "colonnl-$sid", map { ":\n$_" } @parts ],
    ]);
}

sub _single_gzip64 {
    my @parts = @_;
    $_ = [ $_->[0], encode_base64(memGzip($_->[1])) ] for @parts;
    return ([
	UNCOMMON, 
	"gzip64", 
	map { "$_->[0]Content-Transfer-Encoding: gzip64\n\n$_->[1]" } @parts
    ], [
	UNCOMMON, 
	"x-gzip64", 
	map { "$_->[0]Content-Transfer-Encoding: x-gzip64\n\n$_->[1]" } @parts
    ]);
}

sub _single_not_multi {
    my @parts = @_;
    my (undef,$sid,@body) = @{ $default_base64->(map { $_->[1] } @parts) };
    my @r;
    for (
	[ "multipart-$sid", 'multipart/mixed; boundary=foo' ],
	[ "multipart.s-$sid", 'multiparts/mixed; boundary=foo' ],
	[ "x.multipart-$sid", 'x-multipart/mixed; boundary=foo' ],
	[ "single.boundary-$sid", sub { 
	    my ($key,$ct,$rest) = @_; 
	    return sprintf('%s%s; boundary=foo%s',$key,$ct,$rest);
	}],
	[ "multipart.invalid-$sid", 'multipart/invalid; boundary=foo' ],
	[ "multipart.none-$sid", 'multipart/; boundary=foo' ],
	[ "multipart.noslash-$sid", 'multipart; boundary=foo' ],
	[ "multipart.noboundary-$sid", 'multipart/mixed' ],
	[ "multi.escape.part-$sid", 'multi\\part/mixed; boundary=foo' ],
	[ "multipart.bound*=-$sid", "multipart/mixed; boundary*=''foo" ],
	[ "multipart.bound*0-$sid", "multipart/mixed; boundary*0=''foo" ],
	[ "multipart.bound*0*-$sid", "multipart/mixed; boundary*0*=''foo" ],
	[ "fold-multipart-$sid", "\n multipart/mixed; boundary=foo" ],
	[ "cr-multipart-$sid", "\rmultipart/mixed; boundary=foo" ],
	[ "ct:single.multi-$sid", sub {
	    my ($key,$ct,$rest) = @_; 
	    return sprintf("%s%s%s\nContent-type: multipart/mixed; boundary=foo", $key,$ct,$rest);
	}],
	[ "ct:multi.single-$sid", sub {
	    my ($key,$ct,$rest) = @_; 
	    return sprintf("Content-type: multipart/mixed; boundary=foo\n%s%s%s", $key,$ct,$rest);
	}],
    ) {
	my ($id,$mod) = @$_;
	my @p;
	for(my $i=0;$i<@parts;$i++) {
	    my $hdr = $parts[$i][0];
	    $hdr =~s{^(Content-type:\s*)(\S+)(.*)}{ (ref($mod) ? $mod->($1,$2,$3) : $1.$mod.$3) }mieg;
	    push @p, "${hdr}Content-Transfer-Encoding: base64\n\n$body[$i]\n";
	}
	push @r, [ INVALID, $id, @p ];
    }
    return @r;
}


sub singleparts {
    my @parts = @_;
    return traverse_sub(ESSENTIAL, 'singlepart', [
	_single_base64(@parts),  # use this as first to make more tests with encoding
	_single_noencoding(@parts),
	_single_qp(@parts),
	_single_uu(@parts),
	_single_yenc(@parts),
	_single_binhex(@parts),
	_single_base64_bad_header_body_break(@parts),
	_single_base64_bad_header_start(@parts),
	_single_gzip64(@parts),
	_single_not_multi(@parts),
    ]);
}


1;
