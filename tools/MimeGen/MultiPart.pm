use strict;
use warnings;
package MimeGen::MultiPart;

use MIME::Base64 'encode_base64';
use MimeGen::Common;
use MimeGen::SinglePart;
use Exporter 'import';
our @EXPORT = qw(multipart uuencode yenc);

my $default_base64 = \&MimeGen::Base64::_mixedlen;
my $default_qp = \&MimeGen::Base64::_mixedlen;

sub _mkbody {
    my $boundary = shift;
    return join('', map { "--$boundary\n$_" } @_).  "--$boundary--\n";
}

sub _multi_basic {
    my ($type,$valid,$sid,@parts) = @_;
    my $boundary = sprintf("boundary_%x",rand(2**32));
    return [
	$valid,
	"basic-$sid", 
	"Content-type: multipart/$type; boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ];
}

sub _multi_foldetc {
    my ($type,$valid,$sid,@parts) = @_;
    my $boundary = sprintf("boundary_%x",rand(2**32));
    return traverse_sub($valid,'', [[
	VALID,
	"key.fold-$sid", 
	"Content-type:\n multipart/$type; boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [ 
	UNCOMMON,
	"key.2fold-$sid", 
	"Content-type:\n \n multipart/$type; boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [ 
	VALID,
	"ct.fold-$sid", 
	"Content-type: multipart/$type;\n boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [ 
	UNCOMMON,
	"ct.2fold-$sid", 
	"Content-type: multipart/$type;\n \n boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [ 
	INVALID,
	"key.space.colon-$sid", 
	"Content-type : multipart/$type; boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [ 
	INVALID,
	"key.2colon-$sid", 
	"Content-type:: multipart/$type; boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ]]); 
}

sub _escape {
    my ($type,$valid,$sid,@parts) = @_;
    my $boundary = sprintf("boundary_%x",rand(2**32));
    (my $esc = $boundary) =~s{_}{\\_}g;
    return ([ 
	merge_validity($valid,UNCOMMON),
	"escape_def-$sid", 
	"Content-type: multipart/$type; boundary=$esc\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"escape_both-$sid", 
	"Content-type: multipart/$type; boundary=$esc\n\n".
	_mkbody($esc,@parts)
    ], [
	INVALID,
	"wrong_key-$sid", 
	"Content-type: multipart/$type; oundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"escape_key-$sid", 
	"Content-type: multipart/$type; bou\\ndary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"escape_multict-$sid", 
	"Content-type: multi\\part/$type; boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"hidehdr_cr-$sid", 
	"X-Foo:bar\rContent-type: multipart/$type; boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"hidehdr_key_ws_colon_cont-$sid", 
	"X-Foo :bar\n Content-type: multipart/$type; boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"hidehdr_wskey_ws_colon_cont-$sid", 
	"X-Foo Bar:bar\n Content-type: multipart/$type; boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"hidehdr_junk_cont-$sid", 
	"X-Foo-bar\n Content-type: multipart/$type; boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ]);
}

sub _space_around_eq {
    my ($type,$valid,$sid,@parts) = @_;
    my $boundary = sprintf("boundary_%x",rand(2**32));
    my $body = _mkbody($boundary,@parts);
    my @r;
    for (
	[ INVALID, 'space.eq', "boundary =" ],
	[ INVALID, 'tab.eq', "boundary\t=" ],
	[ INVALID, 'nl.eq', "boundary\n =" ],
	[ INVALID, 'esc.eq', "boundary\\=" ],
	[ INVALID, 'eq.space', "boundary= " ],
	[ INVALID, 'eq.tab', "boundary=\t" ],
	[ INVALID, 'eq.nl', "boundary=\n " ],
	[ UNCOMMON, 'eq.esc', "boundary=\\" ],
	[ INVALID, 'nl.eq.nl', "boundary\n =\n " ],
    ) {
	my ($valid,$id,$beq) = @$_;
	push @r, [ 
	    $valid, 
	    "$id-$sid", 
	    "Content-type: multipart/$type; $beq$boundary\n\n$body" 
	];
    }
    return traverse_sub($valid,'',\@r);
}

sub _double_boundary {
    my ($type,$valid,$sid,@parts) = @_;
    my @r;
    my $boundary = sprintf("boundary_%x",rand(2**32));
    my $boundary_bad = sprintf("boundary_%x",rand(2**32));
    my $body = 
	"--$boundary_bad\nContent-type: text/plain\n\n" .
	_mkbody($boundary,@parts) .
	"--$boundary_bad--\n";
    push @r, 
	[ INVALID, "ctb:good,ctb:bad-$sid", 
	    "Content-type: multipart/$type; boundary=$boundary\n" .
	    "Content-type: multipart/$type; boundary=$boundary_bad\n" .
	    "\n$body"
	],
	[ INVALID, "ctb:bad,ctb:good-$sid", 
	    "Content-type: multipart/$type; boundary=$boundary_bad\n" .
	    "Content-type: multipart/$type; boundary=$boundary\n" .
	    "\n$body"
	],
	[ INVALID, "ctb:good,bad-$sid", 
	    "Content-type: multipart/$type; boundary=$boundary; boundary=$boundary_bad\n" .
	    "\n$body"
	],
	[ INVALID, "ctb:bad,good-$sid", 
	    "Content-type: multipart/$type; boundary=$boundary_bad; boundary=$boundary\n" .
	    "\n$body"
	],
	# RFC2231 should in theory take preference but we still consider all of this bad
	[ INVALID, "ctb:rfc2231_good,bad-$sid", 
	    "Content-type: multipart/$type; boundary*=''$boundary; boundary=$boundary_bad\n" .
	    "\n$body"
	],
	[ INVALID, "ctb:rfc2231_bad,good-$sid", 
	    "Content-type: multipart/$type; boundary*=''$boundary_bad; boundary=$boundary\n" .
	    "\n$body"
	],
	[ INVALID, "ctb:bad,rfc2231_good-$sid", 
	    "Content-type: multipart/$type; boundary=$boundary_bad; boundary*=''$boundary\n" .
	    "\n$body"
	],
	[ INVALID, "ctb:good,rfc2231_bad-$sid", 
	    "Content-type: multipart/$type; boundary=$boundary; boundary*=''$boundary_bad\n" .
	    "\n$body"
	];
    return traverse_sub($valid, 'double_boundary', \@r);
}

sub _space_boundary {
    my ($type,$valid,$sid,@parts) = @_;
    my @r;
    for(
	[ before => sprintf(" boundary_%x",rand(2**32)) ],
	[ inside => sprintf("boundary %x", rand(2**32)) ],
	[ after  => sprintf("boundary_%x ",rand(2**32)) ],
    ) {
	my ($id,$boundary) = @$_;
	my $body = _mkbody($boundary,@parts);
	(my $rfc2231_boundary = "''$boundary") =~s{ }{%20}g;
	push @r, 
	    [ UNCOMMON, "$id:dquote-$sid", 
		"Content-type: multipart/$type; boundary=\"$boundary\"\n" .
		"\n$body"
	    ],
	    [ UNCOMMON, "$id:squote-$sid", 
		"Content-type: multipart/$type; boundary=\'$boundary\'\n" .
		"\n$body"
	    ],
	    [ INVALID, "$id:noquote-$sid", 
		"Content-type: multipart/$type; boundary=$boundary;\n" .
		"\n$body"
	    ],
	    [ UNCOMMON, "$id:rfc2231-$sid", 
		"Content-type: multipart/$type; boundary*=$rfc2231_boundary;\n" .
		"\n$body"
	    ];
    }

    # lets see how space at the end gets handled in case it does not exist in
    # boundary definition or actual boundary
    my $boundary = sprintf("boundary_%x",rand(2**32));
    push @r,([ 
	INVALID, "after:onlydef-$sid", 
	"Content-type: multipart/$type; boundary=\"$boundary \"\n\n" .
	_mkbody($boundary,@parts)
    ], [ 
	INVALID, "after:onlyuse-$sid", 
	"Content-type: multipart/$type; boundary=$boundary\n\n" .
	_mkbody("$boundary ",@parts)
    ], [ 
	INVALID, "different_after-$sid", 
	"Content-type: multipart/$type; boundary=\"$boundary XXX\"\n\n" .
	_mkbody("$boundary YYY",@parts)
    ], [ 
	INVALID, "different_after_fold-$sid", 
	"Content-type: multipart/$type; boundary=\"$boundary\n XXX\"\n\n" .
	_mkbody("$boundary YYY",@parts)
    ], [ 
	INVALID, "aftercr-$sid", 
	"Content-type: multipart/$type; boundary=\"$boundary\r\"\n\n" .
	_mkbody("$boundary\r",@parts)
    ], [ 
	INVALID, "aftercr:onlydef-$sid", 
	"Content-type: multipart/$type; boundary=\"$boundary\r\"\n\n" .
	_mkbody($boundary,@parts)
    ]);

    push @r,([ 
	INVALID, 
	"empty-$sid",
	"Content-type: multipart/$type; boundary=\"\"\n\n" .
	_mkbody("",@parts)
    ],[
	INVALID, 
	"spaceonly-$sid",
	"Content-type: multipart/$type; boundary=\" \"\n\n" .
	_mkbody(" ",@parts)
    ]);

    return traverse_sub($valid, 'space_boundary', \@r);
}

sub _rfc2231_boundary {
    my ($type,$valid,$sid,@parts) = @_;
    my @r;
    my @boundary = ("boundary_",sprintf("%x",rand(2**32)));
    my $boundary = join('',@boundary);
    my $body = _mkbody($boundary,@parts);
    my @enc_boundary = ("boundary%5F", $boundary[1]);

    ( my $utf16be_bstr_enc = $boundary) =~s{(.)}{%00$1}sg;
    ( my $utf16le_bstr_enc = $boundary) =~s{(.)}{$1%00}sg;
    push @r,([ 
	UNCOMMON, "enc*-utf16le-$sid", 
	"Content-type: multipart/$type; boundary*=UTF-16''$utf16le_bstr_enc\n" .
	"\n$body"
    ], [ UNCOMMON, "enc*-utf16be-$sid", 
	"Content-type: multipart/$type; boundary*=UTF-16''$utf16be_bstr_enc\n" .
	"\n$body"
    ]);
    for(
	[ 'plain', \@boundary, $boundary ],
	[ 'enc', \@enc_boundary, join('',@enc_boundary) ]
    ) {
	my ($id,$barr,$bstr) = @$_;
	push @r, 
	    [ UNCOMMON, "$id*-$sid", 
		"Content-type: multipart/$type; boundary*=''$bstr\n\n" .
		$body
	    ],
	    [ UNCOMMON, "$id*:prebdr-$sid", 
		"Content-type: multipart/$type; boundary*=''$bstr\n\n".
		"--fake-boundary-in-preamble\nContent-type: text/plain\n\n".
		$body.
		"--fake-boundary-in-preamble--\n"
	    ],
	    [ UNCOMMON, "$id*0*-$sid", 
		"Content-type: multipart/$type; boundary*0*=''$bstr\n\n" .
		$body
	    ],
	    [ UNCOMMON, "$id*0*:prebdr-$sid", 
		"Content-type: multipart/$type; boundary*0*=''$bstr\n\n" .
		"--fake-boundary-in-preamble\nContent-type: text/plain\n\n".
		$body.
		"--fake-boundary-in-preamble--\n"
	    ],
	    [ UNCOMMON, "$id*M*-$sid", 
		"Content-type: multipart/$type; boundary*0*=''$barr->[0]; boundary*1*=$barr->[1]\n" .
		"\n$body"
	    ],
	    [ INVALID, "$id*MR*-$sid", 
		"Content-type: multipart/$type; boundary*1*=$barr->[1]; boundary*0*=''$barr->[0];\n" .
		"\n$body"
	    ],
	    [ INVALID, "$id*MRL*-$sid", 
		"Content-type: multipart/$type; boundary*1*=''$barr->[0]; boundary*0*=$barr->[1]\n" .
		"\n$body"
	    ],
	    [ INVALID, "$id*MD:gb*-$sid", 
		"Content-type: multipart/$type; boundary*0*=''$barr->[0]; boundary*0*=''foo; boundary*1*=$barr->[1]\n" .
		"\n$body"
	    ],
	    [ INVALID, "$id*MD:bg*-$sid", 
		"Content-type: multipart/$type; boundary*0*=''foo; boundary*0*=''$barr->[0]; boundary*1*=$barr->[1]\n" .
		"\n$body"
	    ],
	    [ $id eq 'enc' ? INVALID : UNCOMMON, "$id*0-$sid", 
		"Content-type: multipart/$type; boundary*0=$bstr\n" .
		"\n$body"
	    ],
	    [ $id eq 'enc' ? INVALID : UNCOMMON, "$id*M-$sid", 
		"Content-type: multipart/$type; boundary*0=$barr->[0]; boundary*1=$barr->[1]\n" .
		"\n$body"
	    ],
	    [ INVALID, "$id*MR-$sid", 
		"Content-type: multipart/$type; boundary*1=$barr->[1]; boundary*0=$barr->[0];\n" .
		"\n$body"
	    ],
	    [ INVALID, "$id*MRL-$sid", 
		"Content-type: multipart/$type; boundary*1=''$barr->[0]; boundary*0=$barr->[1]\n" .
		"\n$body"
	    ],
	    [ INVALID, "$id*MD:gb-$sid", 
		"Content-type: multipart/$type; boundary*0=$barr->[0]; boundary*0=foo; boundary*1=$barr->[1]\n" .
		"\n$body"
	    ],
	    [ INVALID, "$id*MD:bg-$sid", 
		"Content-type: multipart/$type; boundary*0=foo; boundary*0=$barr->[0]; boundary*1=$barr->[1]\n" .
		"\n$body"
	    ];
    }

    return traverse_sub($valid, 'rfc2231', \@r);
}

sub _rfc2047_boundary {
    my ($type,$valid,$sid,@parts) = @_;
    my $boundary = sprintf("boundary_%x",rand(2**32));
    my $body = _mkbody($boundary,@parts);
    return [
	INVALID,
	"rfc2047:qp-$sid",
	"Content-type: multipart/$type; boundary=\"=?us-ascii?Q?$boundary?=\"\n\n".
	$body
    ], [
	INVALID,
	"rfc2047:b64-$sid",
	"Content-type: multipart/$type; boundary=\"=?us-ascii?B?".encode_base64($boundary,'')."?=\"\n\n".
	$body
    ];
}

sub _semicolon_boundary {
    my ($type,$valid,$sid,@parts) = @_;
    my @barr = (sprintf("b_%x",rand(2**32)),';',sprintf("%x",rand(2**32)));
    my $bstr = join('',@barr);
    return traverse_sub($valid,'',[[
	INVALID,
	"semicolon_inside:defonly,escaped-$sid",
	"Content-type: multipart/$type; boundary=$barr[0]\\$barr[1]$barr[2]\n\n" .
	_mkbody("$barr[0]",@parts)
    ], [
	INVALID,
	"semicolon_inside:defmostly,escaped-$sid",
	"Content-type: multipart/$type; boundary=$barr[0]\\$barr[1]$barr[2]\n\n" .
	_mkbody("$barr[0]\\",@parts)
    ], [
	UNCOMMON,
	"semicolon_inside:escaped-$sid",
	"Content-type: multipart/$type; boundary=$barr[0]\\$barr[1]$barr[2]\n\n" .
	_mkbody($bstr,@parts)
    ], [
	INVALID,
	"semicolon_inside:escaped,keepescape-$sid",
	"Content-type: multipart/$type; boundary=$barr[0]\\$barr[1]$barr[2]\n\n" .
	_mkbody("$barr[0]\\$barr[1]$barr[2]",@parts)
    ], [
	INVALID,
	"semicolon_inside:defonly,notescaped-$sid",
	"Content-type: multipart/$type; boundary=$bstr\n\n" .
	_mkbody("$barr[0]",@parts)
    ], [
	INVALID,
	"semicolon_inside:notescaped-$sid",
	"Content-type: multipart/$type; boundary=$bstr\n\n" .
	_mkbody($bstr,@parts)
    ]]);
}

sub _quote_boundary {
    my ($type,$valid,$sid,@parts) = @_;
    my @r;

    # first quote inside, another at end - both escaped
    my @barr = (sprintf("b_%x",rand(2**32)),'"',sprintf("%x",rand(2**32)),'"');
    my $bstr_escaped = "$barr[0]\\$barr[1]$barr[2]\\$barr[3]";
    my $bstr = join('',@barr);
    push @r, ([
	ESSENTIAL,
	"quoted-$sid",
	"Content-type: multipart/$type; boundary=\"$barr[0]\"\n\n" .
	_mkbody($barr[0],@parts)
    ], [
	INVALID,
	"quote_escaped-$sid",
	"Content-type: multipart/$type; boundary=$bstr_escaped\n\n" .
	_mkbody($bstr,@parts)
    ], [
	INVALID,
	"quote_escaped,before-$sid",
	"Content-type: multipart/$type; boundary=$bstr_escaped\n\n" .
	_mkbody($barr[0],@parts)
    ], [
	INVALID,
	"quote_escaped,before1-$sid",
	"Content-type: multipart/$type; boundary=$bstr_escaped\n\n" .
	_mkbody("$barr[0]\\",@parts)
    ], [
	INVALID,
	"quote_escaped,inside-$sid",
	"Content-type: multipart/$type; boundary=$bstr_escaped\n\n" .
	_mkbody($barr[2],@parts)
    ], [
	INVALID,
	"quote_escaped,inside1-$sid",
	"Content-type: multipart/$type; boundary=$bstr_escaped\n\n" .
	_mkbody("$barr[2]\\",@parts)
    ], [
	INVALID,
	"quote_escaped,keepescape-$sid",
	"Content-type: multipart/$type; boundary=$bstr_escaped\n\n" .
	_mkbody($bstr_escaped,@parts)
    ], [
	INVALID,
	"bound.fold.ary-$sid",
	"Content-type: multipart/$type; boundary=\"$barr[0]\n $barr[2]\"\n\n" .
	_mkbody("$barr[0] $barr[2]",@parts)
    ]);

    # unescaped quotes, first inside and another at the end
    push @r, ([
	INVALID,
	"quote_ME:full-$sid",
	"Content-type: multipart/$type; boundary=$bstr\n\n" .
	_mkbody($bstr,@parts)
    ], [
	INVALID,
	"quote_ME,first-$sid",
	"Content-type: multipart/$type; boundary=$bstr\n\n" .
	_mkbody($barr[0],@parts)
    ], [
	INVALID,
	"quote_ME:second-$sid",
	"Content-type: multipart/$type; boundary=$bstr\n\n" .
	_mkbody($barr[2],@parts)
    ]);

    # first quote at start, another unquoted inside
    @barr = ('"',sprintf("b_%x",rand(2**32)),'"',sprintf("%x",rand(2**32)));
    $bstr = join('',@barr);
    push @r, ([
	INVALID,
	"quote_BM:full-$sid",
	"Content-type: multipart/$type; boundary=$bstr\n\n" .
	_mkbody($bstr,@parts)
    ], [
	INVALID,
	"quote_BM:first-$sid",
	"Content-type: multipart/$type; boundary=$bstr\n\n" .
	_mkbody($barr[1],@parts)
    ]);

    # missing end quote
    push @r, ([
	INVALID,
	"quote_noend:inside-$sid",
	"Content-type: multipart/$type; boundary=\"$barr[1]\n\n" .
	_mkbody($barr[1],@parts)
    ], [
	INVALID,
	"quote_noend:full-$sid",
	"Content-type: multipart/$type; boundary=\"$barr[1]\n\n" .
	_mkbody("\"$barr[1]",@parts)
    ]);
    return traverse_sub($valid,'',\@r);
}

sub _miss_boundary_def {
    my ($type,$valid,$sid,@parts) = @_;
    my $bstr = sprintf("boundary_%x",rand(2**32));
    return([
	INVALID,
	"miss:bdrdef-$sid",
	"Content-type: multipart/$type\n\n" . 
	join('', map { "--${bstr}X\n$_" } @parts).  "--$bstr--\n"
    ], [
	INVALID,
	"miss:typedef-$sid",
	"Content-type: boundary=$bstr\n\n" . 
	join('', map { "--${bstr} X\n$_" } @parts).  "--$bstr--\n"
    ], [
	INVALID,
	"miss:anydef-$sid",
	"\n" . 
	join('', map { "--${bstr} X\n$_" } @parts).  "--$bstr--\n"
    ]);
}

sub _substr_boundary {
    my ($type,$valid,$sid,@parts) = @_;
    my $bstr = sprintf("boundary_%x",rand(2**32));
    return([
	INVALID,
	"substr:x-$sid",
	"Content-type: multipart/$type; boundary=$bstr\n\n" . 
	join('', map { "--${bstr}X\n$_" } @parts).  "--$bstr--\n"
    ], [
	INVALID,
	"substr:wsx-$sid",
	"Content-type: multipart/$type; boundary=$bstr\n\n" . 
	join('', map { "--${bstr} X\n$_" } @parts).  "--$bstr--\n"
    ], [
	INVALID,
	"substr:dash-$sid",
	"Content-type: multipart/$type; boundary=$bstr\n\n" . 
	join('', map { "--$bstr-\n$_" } @parts).  "--$bstr--\n"
    ], [
	INVALID,
	"substr:ws-$sid",
	"Content-type: multipart/$type; boundary=$bstr\n\n" . 
	join('', map { "--$bstr \n$_" } @parts).  "--$bstr--\n"
    ], [
	INVALID,
	"substr:tab-$sid",
	"Content-type: multipart/$type; boundary=$bstr\n\n" . 
	join('', map { "--$bstr\t\n$_" } @parts).  "--$bstr--\n"
    ], [
	INVALID,
	"substr:vt-$sid",
	"Content-type: multipart/$type; boundary=$bstr\n\n" . 
	join('', map { "--$bstr\013\n$_" } @parts).  "--$bstr--\n"
    ]);
}

sub _outer_vs_inner_boundary {
    my ($type,$valid,$sid,@parts) = @_;
    my @r;
    my $boundary = sprintf("boundary_%x",rand(2**32));

    # outer end boundary is inner boundary
    push @r, [
	UNCOMMON,
	"outerend_is_inner-$sid",
	"Content-type: multipart/mixed; boundary=$boundary\n\n" .
	"--$boundary\n" .
	"Content-type: multipart/$type; boundary=$boundary--\n\n" .
	_mkbody("$boundary--",@parts) .
	"--$boundary--\n"
    ];
    # outer boundary same as inner boundary
    push @r, [
	UNCOMMON,
	"outer_is_inner-$sid",
	"Content-type: multipart/mixed; boundary=$boundary\n\n" .
	"--$boundary\n" .
	"Content-type: multipart/$type; boundary=$boundary\n\n" .
	_mkbody($boundary,@parts) .
	"--$boundary--\n"
    ];
    # outer boundary same as inner boundary with dummy first part
    push @r, [
	UNCOMMON,
	"outer_is_inner_with_dummy_first-$sid",
	"Content-type: multipart/mixed; boundary=$boundary\n\n" .
	"--$boundary\n" .
	"Content-type: text/plain\n\ndummy part\n--$boundary--\n\n--$boundary\n".
	"Content-type: multipart/$type; boundary=$boundary\n\n" .
	_mkbody($boundary,@parts) .
	"--$boundary--\n"
    ];
    # fake part with inner boundary same as outer boundary, content in outer
    push @r, [
	UNCOMMON,
	"dummy_inner_with_outer_bound-$sid",
	"Content-type: multipart/mixed; boundary=$boundary\n\n" .
	"--$boundary\n" .
	"Content-type: multipart/$type; boundary=$boundary\n\n" .
	"--$boundary\nContent-type: text/plain\n\ndummy part\n--$boundary--\n\n".
	_mkbody($boundary,@parts) .
	"--$boundary--\n"
    ];
    # outer boundary extends inner boundary
    push @r, [
	UNCOMMON,
	"outer_extends_inner-$sid",
	"Content-type: multipart/mixed; boundary=${boundary}_\n\n" .
	"--${boundary}_\n" .
	"Content-type: multipart/$type; boundary=$boundary\n\n" .
	_mkbody($boundary,@parts) .
	"--${boundary}_--\n"
    ];
    # outer boundary extends inner boundary, fake outerX in inner preamble
    push @r, [
	UNCOMMON,
	"outer_extends_inner_dummy_outerX-$sid",
	"Content-type: multipart/mixed; boundary=${boundary}_\n\n" .
	"--${boundary}_\n" .
	"Content-type: multipart/$type; boundary=$boundary\n\n" .
	"--${boundary}_X\n\n" .
	_mkbody($boundary,@parts) .
	"--${boundary}_--\n"
    ];
    # inner boundary extends outer boundary
    push @r, [
	UNCOMMON,
	"inner_extends_outer-$sid",
	"Content-type: multipart/mixed; boundary=$boundary\n\n" .
	"--$boundary\n" .
	"Content-type: multipart/$type; boundary=${boundary}_\n\n" .
	_mkbody($boundary.'_',@parts) .
	"--$boundary--\n"
    ];
    return @r;
}

sub _double_ct {
    my ($type,$valid,$sid,@parts) = @_;
    my $boundary = sprintf("boundary_%x",rand(2**32));
    my $body = _mkbody($boundary,@parts);
    return 
	[ INVALID, "ct:multi,ct:text-$sid", 
	    "Content-type: multipart/$type; boundary=$boundary\n" .
	    "Content-type: text/plain\n" .
	    "\n$body"
	],
	[ INVALID, "ct:text,ct:multi-$sid", 
	    "Content-type: text/plain\n" .
	    "Content-type: multipart/$type; boundary=$boundary\n" .
	    "\n$body"
	];
}

sub _xpart_type {
    my ($type,$valid,$sid,@parts) = @_;
    my $boundary = sprintf("boundary_%x",rand(2**32));
    my $body = _mkbody($boundary,@parts);
    return 
	[ INVALID, "sp_type-$sid", 
	    "Content-type: singlepart/$type; boundary=$boundary\n" .
	    "\n$body"
	],
	[ INVALID, "ulti_type-$sid", 
	    "Content-type: ultipart/$type; boundary=$boundary\n" .
	    "\n$body"
	],
	[ INVALID, "x_multi_type-$sid", 
	    "Content-type: x-multipart/$type; boundary=$boundary\n" .
	    "\n$body"
	],
	[ VALID, "mULti_type-$sid", 
	    "Content-type: mULtipart/$type; boundary=$boundary\n" .
	    "\n$body"
	],
	[ INVALID, "rfc2047_type-$sid", 
	    "Content-type: =?UTF-8?B?bXVsdGlwYXJ0?=/$type; boundary=$boundary\n" .
	    "\n$body"
	],
	[ INVALID, "quoted_type-$sid", 
	    "Content-type: \"multipart/$type\"; boundary=$boundary\n" .
	    "\n$body"
	];
}

sub _boundary_in_partheader {
    my ($type,$valid,$sid,@parts) = @_;
    my $inner = sprintf("boundary_%x",rand(2**32));
    my $inner_body = _mkbody($inner,@parts);
    my $outer = sprintf("boundary:%x",rand(2**32));

    return ([
	INVALID,
	"end_inside_decl_header-$sid",
	"Content-type: multipart/mixed; boundary=\"$outer\"\n" .
	"--$outer--\n\n" .
	"--$outer\n" .
	"Content-type: multipart/$type; boundary=$inner\n\n" .
	$inner_body .
	"--$outer--\n"
    ], [
	INVALID,
	"end_inside_inner_header-$sid",
	"Content-type: multipart/mixed; boundary=\"$outer\"\n\n" .
	"--$outer\n" .
	"Content-type: multipart/$type; boundary=$inner\n" .
	"--$outer--\n\n".
	$inner_body .
	"--$outer--\n"
    ], [
	INVALID,
	"bound_inside_inner_header-$sid",
	"Content-type: multipart/mixed; boundary=\"$outer\"\n\n" .
	"--$outer\n" .
	"Content-type: multipart/$type; boundary=$inner\n" .
	"--$outer\n\n".
	$inner_body .
	"--$outer--\n"
    ]);
}

sub _outer_in_inner_base64 {
    my ($type,$valid,$sid,@parts) = @_;
    my $inner = sprintf("boundary_%x",rand(2**32));

    # construct outer boundary using only characters not in base64
    # and apply at the beginning of each base64 part we find
    my $outer = ( '#' x (rand(20)+5) ) . '+';
    # works only with simple base64 inner parts
    (my $inner_body_with_outer_boundary = _mkbody($inner,@parts)) =~s{^
	(
	    Content-Transfer-Encoding:[ ]*base64[ ]*\n
	    (?:\S.*\n)*
	    \n
	)
	(\S)
    }{$1--$outer\n$2}mgix or return;
    return [
	INVALID,
	"outer_in_inner_base64-$sid",
	"Content-type: multipart/mixed; boundary=$outer\n\n".
	"--$outer\n".
	"Content-type: multipart/$type; boundary=$inner\n\n".
	$inner_body_with_outer_boundary.
	"--$outer--\n"
    ];
}

sub _digest {
    my ($type,$valid,$sid,@parts) = @_;
    my $boundary = sprintf("boundary_%x",rand(2**32));
    my $part = "Content-type: multipart/digest; boundary=$boundary\n\n";
    for(my $i=0;$i<@parts;$i++) {
	$part .= "--$boundary\n";
	$part .= "From: me\nTo: you\nSubject: part $i\n$parts[$i]";
    }
    $part .= "--$boundary--\n";
    return [ UNCOMMON, "digest-$sid", $part ];
}


sub _message {
    my ($type,$valid,$sid,@parts) = @_;
    @parts or return;
    my $body = @parts == 1 ? $parts[0] : do {
	my $boundary = sprintf("boundary_%x",rand(2**32));
	"Content-type: multipart/$type; boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    };

    my (undef,$bid,$b64body) = @{ $default_base64->($body) };

    return ([
	VALID, "rfc822-$sid",
	"Content-type: message/rfc822\n\n$body",
    ], [
	INVALID, "rfc822-b64:$bid-$sid",
	"Content-type: message/rfc822\nContent-Transfer-Encoding: base64\n\n$b64body",
    ], [
	UNCOMMON, "global-$sid",
	"Content-type: message/global\n\n$body",
    ], [
	UNCOMMON, "global-b64:$bid-$sid",
	"Content-type: message/global\nContent-Transfer-Encoding: base64\n\n$b64body",
    ]);
}


sub _hidekey {
    my ($type,$valid,$sid,@parts) = @_;
    my $boundary = sprintf("boundary_%x",rand(2**32));
    return traverse_sub(ESSENTIAL,'hidekey', [[ 
	INVALID,
	"ct.noD-$sid",
	"Content-type: multipart/$type  boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"ct.comma-$sid",
	"Content-type: multipart/$type, boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"kv.noD-$sid",
	"Content-type: multipart/$type; foo=bla boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"kvQb-$sid",
	"Content-type: multipart/$type; foo=bla\"boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"kvED-$sid",
	"Content-type: multipart/$type; foo=bla\\;boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"kQvDbQ-$sid",
	"Content-type: multipart/$type; foo=\"bla;boundary=$boundary\"\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"kQvDbQ.bQ-$sid",
	"Content-type: multipart/$type; foo=\"bla;boundary=$boundary\"\n\n".
	_mkbody("$boundary\"",@parts)
    ], [
	INVALID,
	"kQvDb-$sid",
	"Content-type: multipart/$type; foo=\"bla;boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"kQvEQDb-$sid",
	"Content-type: multipart/$type; foo=\"bla\\\";boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	UNCOMMON,
	"kvEQDb-$sid",
	"Content-type: multipart/$type; foo=bla\\\";boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	UNCOMMON,
	"DBeBeb.B-$sid",
	"Content-type: multipart/$type; boundary=boundary=$boundary\n\n".
	_mkbody("boundary",@parts)
    ], [
	INVALID,
	"DBeBeb.b-$sid",
	"Content-type: multipart/$type; boundary=boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"DBeBeb.Beb-$sid",
	"Content-type: multipart/$type; boundary=boundary=$boundary\n\n".
	_mkbody("boundary=$boundary",@parts)
    ], [
	INVALID,
	"Q_keb_Q.b-$sid",
	"Content-type: multipart/$type; \" boundary=$boundary \"\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"QkebQ.b-$sid",
	"Content-type: multipart/$type; \"boundary=$boundary\"\n\n".
	_mkbody($boundary,@parts)
    ]]);
}

sub _comment {
    my ($type,$valid,$sid,@parts) = @_;
    my $b1 = 'boundary_';
    my $b2 = sprintf("%x",rand(2**32));
    my $boundary = $b1.$b2;

    return traverse_sub(ESSENTIAL,'comment', [[ 
	UNCOMMON,
	"kCeb.b-$sid",
	"Content-type: multipart/$type; boundary()=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	UNCOMMON,
	"keCb.b-$sid",
	"Content-type: multipart/$type; boundary=()$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	UNCOMMON,
	"kebC.b-$sid",
	"Content-type: multipart/$type; boundary=$boundary()\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"kebC.bC-$sid",
	"Content-type: multipart/$type; boundary=$boundary()\n\n".
	_mkbody("$boundary()",@parts)
    ], [
	INVALID,
	"keb1Cb2.b-$sid",
	"Content-type: multipart/$type; boundary=$b1()$b2\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"keb1Cb2.b1-$sid",
	"Content-type: multipart/$type; boundary=$b1()$b2\n\n".
	_mkbody($b1,@parts)
    ], [
	INVALID,
	"keb1Cb2.b1Cb2-$sid",
	"Content-type: multipart/$type; boundary=$b1()$b2\n\n".
	_mkbody("$b1()$b2",@parts)
    ], [
	UNCOMMON,
	"keC2b.b-$sid",
	"Content-type: multipart/$type; boundary=(boundary=$b2)$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"keC2b.b2-$sid",
	"Content-type: multipart/$type; boundary=(boundary=$b2)$boundary\n\n".
	_mkbody($b2,@parts)
    ], [
	INVALID,
	"keC2b.C2b-$sid",
	"Content-type: multipart/$type; boundary=(boundary=$b2)$boundary\n\n".
	_mkbody("(boundary=$b2)$boundary",@parts)
    ], [
	INVALID,
	"k1Ck2eb.b-$sid",
	"Content-type: multipart/$type; boun()dary=$boundary\n\n".
	_mkbody("(boundary=$b2)$boundary",@parts)
    ], [
	UNCOMMON,
	"C_keb.b-$sid",
	"Content-type: multipart/$type; () boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	UNCOMMON,
	"Ckeb.b-$sid",
	"Content-type: multipart/$type; ()boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"CB_keb_CE.b-$sid",
	"Content-type: multipart/$type; ( boundary=$boundary )\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"CBC_keb_CE.b-$sid",
	"Content-type: multipart/$type; (() boundary=$boundary )\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"C_type-$sid",
	"Content-type: () multipart/$type; boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"Ctype-$sid",
	"Content-type: ()multipart/$type; boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"tyCpe-$sid",
	"Content-type: multipar()t/$type; boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ], [
	INVALID,
	"typeC-$sid",
	"Content-type: multipart/$type(); boundary=$boundary\n\n".
	_mkbody($boundary,@parts)
    ]]);
}


sub _missing_end {
    my ($type,$valid,$sid,@parts) = @_;
    my $boundary0 = sprintf("boundary_%x",rand(2**32));
    my $boundary1 = sprintf("boundary_%x",rand(2**32));
    return traverse_sub($valid,'', [[ 
	UNCOMMON,
	"missing_end-$sid",
	"Content-type: multipart/$type; boundary=$boundary0\n\n".
	    join('', map { "--$boundary0\n$_" } @parts),
    ],[
	UNCOMMON,
	"missing_inner_end-$sid",
	"Content-type: multipart/mixed; boundary=$boundary0\n\n".
	    "--$boundary0\n".
	    "Content-type: multipart/$type; boundary=$boundary1\n\n".
	    join('', map { "--$boundary1\n$_" } @parts).
	    "--$boundary0--\n",
    ],[
	UNCOMMON,
	"missing_outer_end-$sid",
	"Content-type: multipart/mixed; boundary=$boundary0\n\n".
	    "--$boundary0\n".
	    "Content-type: multipart/$type; boundary=$boundary1\n\n".
	    _mkbody($boundary1,@parts)
    ]]); 
}

sub _cr_boundary {
    my ($type,$valid,$sid,@parts) = @_;
    my $boundary = sprintf("boundary_%x",rand(2**32));
    return ([ 
	INVALID,
	"nlcr_boundary-$sid",
	"Content-type: multipart/$type; boundary=$boundary\n\n".
	    join('', map { "\n\r--$boundary\n$_" } @parts).
	    "\n--$boundary\nContent-type: text/plain\n\ninnocent\n".
	    "\n--$boundary--\n",
    ],[
	INVALID,
	"wscr_boundary-$sid",
	"Content-type: multipart/$type; boundary=$boundary\n\n".
	    join('', map { " \r--$boundary\n$_" } @parts).
	    "\n--$boundary\nContent-type: text/plain\n\ninnocent\n".
	    "\n--$boundary--\n",
    ],[
	INVALID,
	"boundary_cr-$sid",
	"Content-type: multipart/$type; boundary=$boundary\n\n".
	    join('', map { "\n--$boundary\r$_" } @parts).
	    "\n--$boundary\nContent-type: text/plain\n\ninnocent\n".
	    "\n--$boundary--\n",
    ]); 
}


sub multipart {
    my ($type,$singleparts) = @_;
    my @r;
    my $sp_valid;
    while( my $p = $singleparts->()) {
	my ($valid,$sid,@parts) = @$p;
	$sp_valid ||= $valid>=VALID && $p;
	push @r, _multi_basic($type,$valid,$sid,@parts),
    }
    push @r, (
	_multi_foldetc($type,@$sp_valid),
	_escape($type,@$sp_valid),
	_double_boundary($type,@$sp_valid),
	_space_boundary($type,@$sp_valid),
	_space_around_eq($type,@$sp_valid),
	_rfc2231_boundary($type,@$sp_valid),
	_rfc2047_boundary($type,@$sp_valid),
	_semicolon_boundary($type,@$sp_valid),
	_quote_boundary($type,@$sp_valid),
	_miss_boundary_def($type,@$sp_valid),
	_substr_boundary($type,@$sp_valid),
	_outer_vs_inner_boundary($type,@$sp_valid),
	_double_ct($type,@$sp_valid),
	_xpart_type($type,@$sp_valid),
	_boundary_in_partheader($type,@$sp_valid),
	_outer_in_inner_base64($type,@$sp_valid),
	_digest($type,@$sp_valid),
	_hidekey($type,@$sp_valid),
	_comment($type,@$sp_valid),
	_missing_end($type,@$sp_valid),
	_cr_boundary($type,@$sp_valid),
    );
    return traverse_sub(ESSENTIAL,'', [
	traverse_sub(ESSENTIAL, 'multipart', \@r),
	traverse_sub(ESSENTIAL, 'message', [ _message($type,@$sp_valid) ]),
    ]);
}

sub uuencode {
    my $data = '';
    for(@_) {
	my ($hdr,$body) = @$_;
	if ($hdr =~m{^Content-type:\s*text/}mi) {
	    # inline
	    $data .= "\n$body\n---\n";
	} else {
	    my $name = $hdr =~m{\b(?:file)?name=(?:\"([^"]+)\"|(\S+))}i
		&& ($1||$2) || "unknown.dat";
	    $data .= "begin 644 $name\n".pack("u",$body)."end\n" 
	}
    }
    return [ INVALID, 'multi.uuencode', $data ];
}

sub yenc {
    my $data = '';
    for(@_) {
	my ($hdr,$body) = @$_;
	if ($hdr =~m{^Content-type:\s*text/}mi) {
	    # inline
	    $data .= "\n$body\n---\n";
	} else {
	    my $name = $hdr =~m{\b(?:file)?name=(?:\"([^"]+)\"|(\S+))}i
		&& ($1||$2) || "unknown.dat";
	    $data .= yenc_encode($name,$body);
	}
    }
    return [ INVALID, 'multi.yenc', $data ];
}

1;
