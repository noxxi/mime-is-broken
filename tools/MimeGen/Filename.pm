use strict;
use warnings;
package MimeGen::Filename;
use MimeGen::Common;
use MIME::Base64 'encode_base64';
use Exporter 'import';
our @EXPORT = qw(singlepart_fname);

my $innocent = 'png';


# should not be blocked hopefully
sub _fname_innocent {
    my ($ext,$type,$part) = @_;
    return ([
	ESSENTIAL,
	"ctype.$innocent",
	"Content-type: $type; name=file.$innocent\n$part"
    ], [
	ESSENTIAL,
	"cdisp.$innocent",
	"Content-type: $type\nContent-Disposition: attachment; filename=file.$innocent\n$part"
    ]);
}

sub _fname_only_ctd {
    my ($ext,$type,$part) = @_;
    my $ct = "Content-type: $type";
    my $cd = "Content-Disposition: attachment";
    my @r;
    my $mkr = sub {
	my ($valid,$id,$prefix,$kv) = @_;
	push @r, [ $valid, "ctype$id", "$ct;$prefix$kv\n$part" ];
	push @r, [ $valid, "cdisp$id", "$ct\n$cd;${prefix}file$kv\n$part" ];
    };
    $mkr->(ESSENTIAL,'','',          "name=file.$ext");
    $mkr->(ESSENTIAL,'.QnQ','',      "name=\"file.$ext\"");
    $mkr->(INVALID,  '.SnS','',      "name=\'file.$ext\'");
    $mkr->(UNCOMMON, '.fold',"\n ",  "name=file.$ext");
    $mkr->(UNCOMMON, '.2fold',"\n \n ","name=file.$ext");
    $mkr->(INVALID,  '.space0','',   "name =file.$ext");
    $mkr->(INVALID,  '.space1','',   "name= file.$ext");
    $mkr->(INVALID,  '.nl=','',      "name\n =file.$ext");
    $mkr->(INVALID,  '.=nl','',      "name=\n file.$ext");
    return @r;
}

sub _fname_ctd_differ {
    my ($ext,$type,$part) = @_;
    my $ct = "Content-type: $type";
    my $cd = "Content-Disposition: attachment";
    return ([
	UNCOMMON,
	'ctD',
	"$ct; name=file.$innocent\n$cd; filename=file.$ext\n$part",
    ], [
	UNCOMMON,
	'cTd',
	"$ct; name=file.$ext\n$cd; filename=file.$innocent\n$part",
    ], [
	INVALID,
	'ctxD',
	"$ct; foo=file.$innocent\n$cd; filename=file.$ext\n$part",
    ], [
	INVALID,
	'cTdx',
	"$ct; name=file.$ext\n$cd; foo=file.$innocent\n$part",
    ], [
	UNCOMMON,
	'cDt',
	"$cd; filename=file.$ext\n$ct; name=file.$innocent\n$part",
    ], [
	UNCOMMON,
	'cdT',
	"$cd; filename=file.$innocent\n$ct; name=file.$ext\n$part",
    ], [
	INVALID,
	'cDtx',
	"$cd; filename=file.$ext\n$ct; foo=file.$innocent\n$part",
    ], [
	INVALID,
	'cdxT',
	"$cd; foo=file.$innocent\n$ct; name=file.$ext\n$part",
    ]);
}

sub _fname_only_ctd_dup {
    my ($ext,$type,$part) = @_;
    my $ct = "Content-type: $type";
    my $cd = "Content-Disposition: attachment";
    return ([
	INVALID,
	'ctype.xi',
	"$ct; name=file.$ext; name=file.$innocent\n$part"
    ], [
	INVALID,
	'ctype.ix',
	"$ct; name=file.$innocent; name=file.$ext\n$part"
    ], [
	INVALID,
	'ctype.XI',
	"$ct; name=file.$ext\nContent-type: $type; name=file.$innocent\n$part"
    ], [
	INVALID,
	'ctype.IX',
	"$ct; name=file.$innocent\nContent-type: $type; name=file.$ext\n$part"
    ], [
	INVALID,
	'cdisp.xi',
	"$ct\n$cd; filename=file.$ext; filename=file.$innocent\n$part"
    ], [
	INVALID,
	'cdisp.ix',
	"$ct\n$cd; filename=file.$innocent; filename=file.$ext\n$part"
    ], [
	INVALID,
	'cdisp.XI',
	"$ct\n$cd; filename=file.$ext\n$cd; filename=file.$innocent\n$part",
    ], [
	INVALID,
	'cdisp.IX',
	"$ct\n$cd; filename=file.$innocent\n$cd; filename=file.$ext\n$part",
    ]);
}

sub _fname_rfc2047 {
    my ($ext,$type,$part) = @_;
    my $f2047 = encode_base64("file.$ext",'');
    my $f2047_16be = encode_base64(do { (my $x = "file.$ext") =~s{(.)}{\0$1}sg; $x },'');
    my $f2047_16le = encode_base64(do { (my $x = "file.$ext") =~s{(.)}{$1\0}sg; $x },'');
    return ([
	INVALID,
	'ctype.rfc2047',
	"Content-type: $type; name=\"=?us-ascii?B?$f2047?=\"\n". $part
    ], [
	INVALID,
	'ctype.rfc2047.utf16le',
	"Content-type: $type; name=\"=?utf-16?B?$f2047_16le?=\"\n". $part
    ], [
	INVALID,
	'ctype.rfc2047.utf16be',
	"Content-type: $type; name=\"=?utf-16?B?$f2047_16be?=\"\n". $part
    ], [
	INVALID,
	'cdisp.rfc2047',
	"Content-type: $type\n".
	    "Content-Disposition: attachment; filename=\"=?us-ascii?B?$f2047?=\"\n". 
	    $part
    ], [
	INVALID,
	'cdisp.rfc2047.utf16le',
	"Content-type: $type\n".
	    "Content-Disposition: attachment; filename=\"=?utf-16?B?$f2047_16le?=\"\n". 
	    $part
    ], [
	INVALID,
	'cdisp.rfc2047.utf16be',
	"Content-type: $type\n".
	    "Content-Disposition: attachment; filename=\"=?utf-16?B?$f2047_16be?=\"\n". 
	    $part
    ]);
}

sub _fname_quote_inside {
    my ($ext,$type,$part) = @_;
    my $ct = "Content-type: $type";
    my $cd = "Content-Disposition: attachment";
    my @r;
    for (
	[ INVALID,  'nQx'    => "file\".$ext" ],
	[ INVALID,  'QnQx'   => "\"file\".$ext" ],
	[ INVALID,  'QnQxQ'  => "\"file\".$ext\"" ],
	[ UNCOMMON, 'QnEQxQ' => "\"file\\\".$ext\"" ],
	[ UNCOMMON, 'nEQx'   => "file\\\".$ext" ],
    ) {
	my ($valid,$id,$enc) = @$_;
	push @r, (
	    [ $valid, "ctype.$id", "$ct; name=$enc\n". $part ], 
	    [ $valid, "cdisp.$id", "$ct\n$cd; filename=$enc\n". $part ], 
	);
    }
    return @r;
}

sub _fname_semicolon {
    my ($ext,$type,$part) = @_;
    my $ct = "Content-type: $type";
    my $cd = "Content-Disposition: attachment";
    my @r;
    for (
	[ INVALID,  'n;x'   => "file;.$ext" ],
	[ UNCOMMON, 'nE;x'  => "file\\;.$ext" ],
	[ UNCOMMON, 'Qn;xQ' => "\"file;.$ext\"" ],
    ) {
	my ($valid,$id,$enc) = @$_;
	push @r, (
	    [ $valid, "ctype.$id", "$ct; name=$enc\n$part" ], 
	    [ $valid, "cdisp.$id", "$ct\n$cd; filename=$enc\n$part" ], 
	);
    }
    return @r;
}

sub _fname_rfc2231 {
    my ($ext,$type,$part) = @_;
    my $ct = "Content-type: $type";
    my $cd = "Content-Disposition: attachment";
    (my $enc_ext = $ext) =~s{(.)}{ sprintf("%%%02X",ord($1)) }esg;
    my @r;
    for (
	[ VALID,    '*',         "*=''file.$ext" ],
	[ VALID,    '*E',        "*=''file.$enc_ext" ],
	[ UNCOMMON, '*0',        "*0=file.$ext" ],
	[ UNCOMMON, '*0;*1',     "*0=file.", "*1=$ext" ],
	[ INVALID,  '*0;*2',     "*0=file.", "*2=$ext" ],
	[ INVALID,  '*1;*2',     "*1=file.", "*2=$ext" ],
	[ INVALID,  '*1;*0',     "*1=$ext", "*0=file." ],
	[ INVALID,  '*1;*0r',    "*1=file.", "*0=$ext" ],
	[ INVALID,  '*2;*0',     "*2=$ext", "*0=file." ],
	[ INVALID,  '*2;*1',     "*2=$ext", "*1=file." ],
	[ UNCOMMON, '*0*',       "*0*=''file.$ext" ],
	[ UNCOMMON, '*0*E',      "*0*=''file.$enc_ext" ],
	[ UNCOMMON, '*0*;*1*',   "*0*=''file.", "*1*=$ext" ],
	[ UNCOMMON, '*0*;*1*E',  "*0*=''file.", "*1*=$enc_ext" ],
	[ INVALID,  '*1*;*0*',   "*1*=$ext", "*0*=''file." ],
	[ INVALID,  '*1*;*0*r',  "*1*=''file.", "*0*=$ext" ],
    ) {
	my ($valid,$id,@fp) = @$_;
	my $enc = sub { return join("; ",map { "$_[0]$_" } @fp) };
	push @r, (
	    [ $valid, "ctype.rfc2231.$id", "$ct; ".$enc->('name')."\n$part" ], 
	    [ $valid, "ctype.n+rfc2231.$id", "$ct; name=file.$innocent; ".$enc->('name')."\n$part" ], 
	    [ $valid, "ctype.rfc2231+n.$id", "$ct; ".$enc->('name')."; name=file.$innocent\n$part" ], 
	    [ $valid, "cdisp.rfc2231.$id", "$ct\n$cd; ".$enc->('filename')."\n$part" ], 
	    [ $valid, "cdisp.n+rfc2231.$id", "$ct\n$cd; filename=file.$innocent; ".$enc->('filename')."\n$part" ], 
	    [ $valid, "cdisp.rfc2231+n.$id", "$ct\n$cd; ".$enc->('filename')."; filename=file.$innocent\n$part" ], 
	);
    }

    push @r, (
	[ INVALID, 'ctype.rfc2231.*0nl*1', "$ct; name*0=file.\n$ct; name*1=$ext\n$part" ],
	[ INVALID, 'ctype.rfc2231.*1nl*0', "$ct; name*1=$ext\n$ct; name*0=file.\n$part" ],
	[ INVALID, 'cdisp.rfc2231.*0nl*1', "$ct\n$cd; filename*0=file.\n$ct; filename*1=$ext\n$part" ],
	[ INVALID, 'cdisp.rfc2231.*1nl*0', "$ct\n$cd; filename*1=$ext\n$ct; filename*0=file.\n$part" ],
    );

    ( my $utf16be_enc = "file.$ext") =~s{(.)}{%00$1}sg;
    ( my $utf16le_enc = "file.$ext") =~s{(.)}{$1%00}sg;
    push @r, (
	[ UNCOMMON, 'ctype.rfc2231-utf8', "$ct; name*=UTF-8''file.$ext\n$part" ],
	[ UNCOMMON, 'cdisp.rfc2231-utf8', "$ct\n$cd; filename*=UTF-8''file.$ext\n$part" ],
	[ UNCOMMON, 'cdisp.rfc2231-utf16be', "$ct\n$cd; filename*=UTF-16''$utf16be_enc\n$part" ],
	[ UNCOMMON, 'ctype.rfc2231-utf16le', "$ct; name*=UTF-16''$utf16le_enc\n$part" ],
	[ UNCOMMON, 'cdisp.rfc2231-utf16le', "$ct\n$cd; filename*=UTF-16''$utf16le_enc\n$part" ],
	[ UNCOMMON, 'ctype.rfc2231-utf16be', "$ct; name*=UTF-16''$utf16be_enc\n$part" ],
    );
    return @r;
}

sub _fname_comment {
    my ($ext,$type,$part) = @_;
    my $ct = "Content-type: $type";
    my $cd = "Content-Disposition: attachment";
    my @r;
    my ($x1,$x2) = $ext =~m{^(.)(.+)} or die $ext;
    for (
	[ INVALID,  'kexC'   => "file.$ext()" ],
	[ INVALID,  'kexG'   => "file.$ext(.gif)" ],
	[ INVALID,  'kex1Cx2'   => "file.$x1()$x2" ],
	[ INVALID,  'kex1Gx2'   => "file.$x1(.gif)$x2" ],
    ) {
	my ($valid,$id,$enc) = @$_;
	push @r, (
	    [ $valid, "ctype.$id", "$ct; name=$enc\n$part" ], 
	    [ $valid, "cdisp.$id", "$ct\n$cd; filename=$enc\n$part" ], 
	);
    }
    push @r, (
	[ INVALID, "ctype.kCen", "$ct; name()=file.$ext\n$part" ], 
	[ INVALID, "cdisp.kCen", "$ct\n$cd; filename()=file.$ext\n$part" ], 
	[ INVALID, "ctype.k1Ck2en", "$ct; na()me=file.$ext\n$part" ], 
	[ INVALID, "cdisp.k1Ck2en", "$ct\n$cd; filena()me=file.$ext\n$part" ], 
    );
    return @r;
}

sub singlepart_fname {
    my ($ext,$type,$part) = @_;
    return traverse_sub(ESSENTIAL, 'fname', [
	_fname_innocent($ext,$type,$part),
	_fname_only_ctd($ext,$type,$part),
	_fname_ctd_differ($ext,$type,$part),
	_fname_only_ctd_dup($ext,$type,$part),
	_fname_rfc2047($ext,$type,$part),
	_fname_quote_inside($ext,$type,$part),
	_fname_semicolon($ext,$type,$part),
	_fname_rfc2231($ext,$type,$part),
	_fname_comment($ext,$type,$part),
    ]);
}


1;
