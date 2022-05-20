use strict;
use warnings;
use Getopt::Long qw(:config posix_default bundling);
use File::Find 'find';
use File::Temp 'tempfile';
use Data::Dumper;
BEGIN { unshift @INC,$1 if $0 =~m{(.*)/}s; }
use MimeGen::Common 'mail_chksum';

my $mark;
my $testdir;
GetOptions(
    'h|help' => sub { usage() },
    'testdir=s' => \$testdir,
    'm|mark' => \$mark,
) or die usage('bad option');

my %origtest;
for my $file (@ARGV) {
    -f $file or next;
    open(my $fh,'<',$file) or next;
    my $mail = do { local $/; <$fh> };
    $mail =~m{^X-Payload-Id:\s*(\S+).* md5\(([\w+/=]+)}mi || next;
    my $chksum_expect = $2;
    my $id = $1;
    my $chksum = mail_chksum($mail);
    my $status = $chksum eq $chksum_expect ? 'match' : 'change';
    printf("%6s | %s | %s\n",$status,$id,$file);
    if ($status eq 'change' and $mark and $mail !~m{^X-Payload-Changed:}m) {
	open(my $fh,'>',$file);
	print $fh "X-Payload-Changed: $chksum\n$mail";
    }

    if ($status eq 'change' && $testdir) {
	if (!%origtest) {   
	    find(sub {
		-f $_ or return;
		open(my $fh,'<',$_) or return;
		my $data = do { local $/; <$fh> };
		$data =~s{\A.*^X-Payload-Id:\s*(\S+)[^\n]*\n}{}sm or die $data; 
		( $origtest{$1} = $data ) =~s{\r\n}{\n}g;
	    },$testdir);
	    %origtest or die "cannot use test in $testdir for comparison";
	}
	my $orig = $origtest{$id} || die "no original test for id '$id'";
	(my $this = $mail) =~s{\A.*^X-Payload-Id:[^\n]*\n}{}sm;
	my $ck_body = mail_chksum($this);
	if ($ck_body ne $chksum && $ck_body eq $chksum_expect) {
	    print "** Upper header changed in $id\n";
	} else {
	    $this =~ s{\r\n}{\n}g;
	    my ($fh_orig,$f_orig) = tempfile($id.'-XXXXX');
	    print $fh_orig $orig;
	    close($fh_orig);
	    my ($fh_this,$f_this) = tempfile($id.'-XXXXX');
	    print $fh_this $this;
	    close($fh_this);
	    print "** $id differs:\n";
	    system('diff','-u',$f_orig,$f_this);
	    unlink($f_orig);
	    unlink($f_this);
	}
    }
}
