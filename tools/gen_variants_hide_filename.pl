use strict;
use warnings;
use File::Temp 'tempfile';
use Getopt::Long qw(:config posix_default bundling);
use MIME::Base64 'encode_base64';
BEGIN { unshift @INC,$1 if $0 =~m{(.*)/}s; }
use MimeGen::Filename;
use MimeGen::Common;

my $maildir = 'hide-filename.d';
my $title = '';
my @file;
GetOptions(
    'h|help'    => sub { usage() },
    'maildir=s' => \$maildir,
    'title=s'   => \$title,
    'file=s'    => \@file,
);
-d "$maildir/new" or die "no maildir $maildir";
@file = 'test.zip' if ! @file;
unshift @file, 'test.txt';

my @t = localtime();
$title .= sprintf("%04d-%02d-%02d %02d:%02d", $t[5]+1900, $t[4]+1, @t[3,2,1]);


my $next = do {
    my @psub = map { singlepart_fname(_part($_)) } @file;
    sub { 
	my (@parts,@valid,%id);
	for(@psub) {
	    my $r = $_->() or next;
	    my ($valid,$id,$data) = @$r;
	    $id{$id}++;
	    push @valid,$valid;
	    push @parts,$data;
	}
	return if ! @parts;
	return [
	    merge_validity(@valid),
	    join(".",sort keys %id),
	    @parts
	];
    };
};
    
while (my $r = $next->()) {
    my ($valid,$id,@parts) = @$r;
    my $msgid = sprintf("%x.%x.%x\@example.com",rand(2**32),$$,time());
    my $boundary = "1234567890asdfghjkl";
    my $mail =
	"From: me\nTo: you\n" .
	"Subject: [$valid] $id $title\n" .
	"Mime-Version: 1.0\n".
	"Message-Id: <$msgid>\n".
	"Content-type: multipart/mixed; boundary=$boundary\n".
	"\n".
	join("", map { "--$boundary\n$_" } @parts)."--$boundary--\n";

    my ($fh) = tempfile(
	sprintf("%d.XXXX",time()), 
	DIR => "$maildir/new"
    );
    print $fh "X-Payload-Id: $id valid($valid)  md5("
	. mail_chksum($mail).") $title\n" . $mail;
}

sub _part {
    my $want = shift;
    my $body = -f $want ? do {
	open(my $fh,'<',$want) or die $!;
	local $/; 
	<$fh> 
    } : "This could be a file named '$want'";
    my $ext = $want =~m{\.(\w+)\z} && $1 || die "no valid extension in $want";
    my $type = $want =~m{\.txt$}i ? 'text/plain' : 'application/octet-stream';
    return ($ext, $type, 
	"Content-Transfer-Encoding: base64\n\n".encode_base64($body));
}
