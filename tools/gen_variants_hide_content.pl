use strict;
use warnings;
use File::Temp 'tempfile';
use MIME::Base64 'decode_base64';
use Digest::MD5;
use Getopt::Long qw(:config posix_default bundling);
BEGIN { unshift @INC,$1 if $0 =~m{(.*)/}s; }
use MimeGen::SinglePart;
use MimeGen::MultiPart;
use MimeGen::Common;

my $maildir = 'hide-content.d';
my $title = '';
my @virus;

sub usage() {
    print STDERR <<USAGE;

Generate test mails for hiding content using unusual or invalid MIME

Usage: $0 [options]
 -h|--help    this help
 --maildir D  output to maildir D ($maildir)
 --title S    add subject S to mails
 --virus F    attach virus from file F, can be used multiple times

USAGE
    exit(1)
}

GetOptions(
    'h|help'    => sub { usage() },
    'maildir=s' => \$maildir,
    'title=s'   => \$title,
    'virus=s'   => \@virus,
);
-d "$maildir/new" or die "no maildir $maildir";
@virus = 'eicar.zip' if ! @virus;

my @parts = (
    # this is useful for testing all the variants of quoted-printable and base64
    [ "Content-type: text/plain\n","ABCD\t01234=56789  98765=43210 = =XY Some more text\n" ],
);
for(@virus) {
    my $v = get_virus($_);
    $title .= "$_ ";
    push @parts, [
	"Content-type: $v->[0]\nContent-Disposition: attachment; filename=\"$_\"\n",
	$v->[1]
    ];
}

my @t = localtime();
$title .= sprintf("%04d-%02d-%02d %02d:%02d", $t[5]+1900, $t[4]+1, @t[3,2,1]);

my $next = traverse_sub(ESSENTIAL,'', [
    multipart('mixed', singleparts(@parts)),
    uuencode(@parts),
    yenc(@parts),
]);
while (my $m = $next->()) {
    my ($valid,$id,$data) = @$m;
    my $msgid = sprintf("%x.%x.%x\@example.com",rand(2**32),$$,time());
    my $mail =
	"From: me\nTo: you\n" .
	"Subject: [$valid] $id $title\n" .
	"Mime-Version: 1.0\n".
	"Message-Id: <$msgid>\n".
	"X-Payload-Id: $id valid($valid)  md5(".mail_chksum($data).") $title\n".
	$data;

    my ($fh) = tempfile(
	sprintf("%d.XXXX",time()), 
	DIR => "$maildir/new"
    );
    print $fh $mail;
}

my $predef_virus;
sub get_virus {
    $predef_virus ||= {
	'eicar.txt' => [ 'text/plain', 
	    'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n' ],
	'eicar.zip' => [ 'application/octet-stream', decode_base64('
	    UEsDBBQAAgAIABFKjkk8z1FoRgAAAEQAAAAJAAAAZWljYXIuY29tizD1VwxQdXAMiDa
	    JCYiKMDXRCIjTNHd21jSvVXH1dHYM0g0OcfRzcQxy0XX0C/EM8wwKDdYNcQ0O0XXz9H
	    FVVPHQ9tACAFBLAQIUAxQAAgAIABFKjkk8z1FoRgAAAEQAAAAJAAAAAAAAAAAAAAC2g
	    QAAAABlaWNhci5jb21QSwUGAAAAAAEAAQA3AAAAbQAAAAAA
	')],
    };
    my $want = shift;
    if (-f $want) {
	open(my $fh,'<',$want) or die $!;
	my $data = do { local $/; <$fh> };
	return [ 'application/octet-stream', $data ];
    }
    return $predef_virus->{$want}
	|| die "no such file/predef '$want'";
}
