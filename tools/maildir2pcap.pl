use strict;
use warnings;
use Net::PcapWriter;
use File::Find 'find';
use Getopt::Long qw(:config posix_default bundling);

my ($DEBUG,$out,$manifest);
GetOptions(
    'h|help' => sub { usage() },
    'd|debug' => \$DEBUG,
    'M|manifest=s' => \$manifest,
    'O|out=s' => \$out,
) or usage("bad option");

my @files;
for(@ARGV) {
    if (-d $_) {
	find(sub { push @files,$File::Find::name if -f $_ && -r _ }, $_);
    } elsif (-f $_) {
	push @files, $_
    }
}
die "no files found in @ARGV" if ! @files;

my $gpcap;
if (!$out) {
    $gpcap = Net::PcapWriter->new(\*STDOUT);
} elsif (! -d $out) {
    open( my $fh,'>',$out) or die "open $out: $!";
    $gpcap = Net::PcapWriter->new($fh);
}

if ($manifest) {
    open(my $fh,'>',$manifest) or die "cannot write $manifest: $!";
    $manifest = $fh;
}

my $cport = 10000;
for my $file (@files) {
    my $mail = do {
	open(my $fh,'<',$file) or die "open $file: $!";
	local $/;
	<$fh>
    };
    my $id = 
	$mail =~m{^X-Payload-Id:\s*(\S+)\s+valid\((\d+)}mi && "[$2] $1" ||
	$mail =~m{^Subject:\s*(.*\S)}m && $1 ||
	$file =~m{([^/]+)$} && $1;
    
    my $pcap = $gpcap;
    my $mline;
    if (!$pcap) {
	(my $fname = $id) =~s{[^\w\-=.+*]}{_}g;
	$fname = "$out/$fname.pcap";
	open(my $fh,'>',$fname) or die "cannot write to $fname: $!";
	$pcap = Net::PcapWriter->new($fh);
	$mline = "$cport | $id | $fname";
    } else {
	$mline = "$cport | $id";
    }

    print $manifest $mline,"\n" if $manifest;
    debug($mline);

    my $conn = $pcap->tcp_conn('1.1.1.1',$cport,'9.9.9.9',25);
    $conn->write(1,"220 mail.example.com ESMTP service ready\r\n");
    $conn->write(0,"HELO myhost.example.com\r\n");
    $conn->write(1,"250 mail.example.com\r\n");
    $conn->write(0,"MAIL FROM: me\@example.com\r\n");
    $conn->write(1,"250 ok\r\n");
    $conn->write(0,"RCPT TO: you\@example.com\r\n");
    $conn->write(1,"250 ok\r\n");
    $conn->write(0,"DATA\r\n");
    $conn->write(1,"354 ok\r\n");
    $mail .= "\n" if $mail !~m{\n\z};
    $mail =~s{\r?\n}{\r\n}g;
    $mail =~s{^\.}{^..}mg;
    $conn->write(0,$mail.".\r\n");
    $conn->write(1,"250 ok\r\n");
    $conn->write(0,"QUIT\r\n");
    $conn->write(1,"221 bye\r\n");

    $cport++;
}



sub debug {
    $DEBUG or return;
    print STDERR "@_\n";
}

