use strict;
use warnings;
use MIME::Parser;

# select the test we want to do by commenting out
# my $check = \&_check_eicartxt;
my $check = \&_check_zipname;

my $eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
my @files = @ARGV;
while (my $m = shift @files) {
    if (-d $m) {
	unshift @files, glob("$m/*");
	next;
    } 
    next if ! -f $m;
    my $p = MIME::Parser->new;
    $p->output_to_core(1);
    my ($subj,@files);
    if (!eval {
	my $e = $p->parse_open($m);
	$subj = $e->head->get('Subject') =~m{(\[\d\]\s\S+)} && $1 
	    or die "no subject found";
	for my $part ($e->parts_DFS) {
	    my $bodyh = $part->bodyhandle or next;
	    push @files, [ 
		$part->head->recommended_filename,
		$bodyh->as_string
	    ];
	}
	1;
    }) {
	print STDERR "FAIL $m: $@\n";
	next;
    }
    if (grep { $_->[0] && $check->($_) } @files) {
	print $subj,"\n";
    } else {
	print STDERR "NOT $subj\n";
    }
}

sub _check_zipname {
    my ($name,$content) = @$_;
    return $name =~m{\.zip$};
}

sub _check_eicartxt {
    my ($name,$content) = @$_;
    return if $name !~m{\.txt$};
    return $content =~m{\Q$eicar};
}
