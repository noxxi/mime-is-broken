use strict;
use warnings;
package MimeGen::Common;
use Digest::MD5;

use List::Util 'min';
use Exporter 'import';
our @EXPORT = qw(ESSENTIAL VALID UNCOMMON INVALID merge_validity traverse_sub yenc_encode mail_chksum);

use constant {
    ESSENTIAL => 3,
    VALID     => 2,
    UNCOMMON  => 1,
    INVALID   => 0,
};



sub merge_validity { return min(@_) }
sub traverse_sub {
    my ($valid,$id,$rec) = @_;
    my @subs;
    return sub {
	while (1) {
	    if (!@subs) {
		#warn "XXXX($id) - rearm";
		push @subs, shift(@$rec) || return;
		#warn "XXXX($id) - rearm done";
	    }
	    my $more = pop @subs;
	    if (ref($more) eq 'CODE') {
		#warn "XXXX($id) - have code";
		my @m = $more->() or next;
		#warn "XXXX($id) - code produced @m";
		push @subs, $more, @m;
	    } else {
		my ($sv,$si,@data) = @$more;
		#warn "XXXX($id) - have array ($si)";
		return [
		    merge_validity($sv,$valid),
		    $id ne '' ? "$id-$si" : $si,
		    @data
		];
	    }
	}
    }
}


sub yenc_encode {
    my ($name,$data) = @_;
    my $size = length($data);
    $data =~tr{\x00-\xff}{\x2a-\xff\x00-\x29};
    $data =~s{([\x00\r\n= ])}{ '='.chr(ord($1)+64) }esg;
    $data =~s{(.{1,128})}{$1\r\n}g;
    return "=ybegin line=128 size=$size name=$name\n"
	. $data
	. "=yend size=$size\n";
}

sub mail_chksum {
    my $buf = shift;
    my ($hdr,$body) = $buf =~m{\A(.*?\n\r?\n)(.*)\z}s
	or die "cannot split into hdr and body: $buf";
    my $md5 = Digest::MD5->new;
    s{[ \t]*\r?\n}{\n}g for($hdr,$body);
    my @h;
    while ($hdr =~m{^(Content-Transfer-Encoding|Content-Type):[ \t]*(.*(?:\n[ \t].*)*\n)}mig) {
	my $h = lc($1);
	( my $v = $2 ) =~s{\s+}{ }g;
	push @h,"$h:$v";
    }
    $md5->add(sort @h);
    $body =~s{\s+\z}{};
    $md5->add($body);
    return $md5->b64digest;
}

1;
