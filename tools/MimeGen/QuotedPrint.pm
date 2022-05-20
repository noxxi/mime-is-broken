use strict;
use warnings;
package MimeGen::QuotedPrint;
use MimeGen::Common;
use Exporter 'import';
our @EXPORT = 'quotedprint';


my $default_escape_rx = qr{[\x00-\x20=\x7f-\xff]};
sub _qp {
    my $buf = shift;
    my $escape_rx = shift || $default_escape_rx;
    $buf =~ s{($escape_rx)}{ sprintf("=%02X",ord($1)) }esg;
    my $out = '';
    while (1) {
	$out .= substr($buf,0,75,'');
	if ($buf eq '') {
	    return $out . "=\n\n";
	} elsif ($out =~s{(.)(=.{0,2})\z}{$1=\n}) {
	    $buf = $2 . $buf;
	} else {
	    $out .= "=\n";
	}
    }
}


sub _basic {
    my @body = @_;
    return [ ESSENTIAL, 'basic', map { _qp($_) } @body ];
}

sub _variants {
    my @body = @_;
    my @enc_body = map { _qp($_) } @body;
    my @r;
    for(
	[ VALID, 'cont', sub { s{(=..|[^=\n])}{$1=\n}g } ],
	[ INVALID, '2space', sub { s{( )}{$1 }g } ],
    ) {
	my ($valid,$id,$sub) = @$_;
	my (@newbody,$changed);
	for my $body (@enc_body) {
	    local $_ = $body;
	    &$sub;
	    $changed++ if $_ ne $body;
	    push @newbody, $_
	}
	push @r, [ $valid, $id, @newbody ] if $changed;
    }

    push @r,(
	[ VALID, 'no_tab', map { _qp($_,qr{[\x00-\x08\x0a-\x20=\x7f-\xff]}) } @body ],
	[ VALID, 'no_space', map { _qp($_,qr{[\x00-\x1f=\x7f-\xff]}) } @body ],
	[ UNCOMMON, 'no_nl', map { _qp($_,qr{[\x00-\x09\x0b-\x20=\x7f-\xff]}) } @body ],
    );

    for(
	[ VALID, 'allenc-cont', sub { s{(.)}{ sprintf("=%02X=\n",ord($1)) }eg } ],
	[ VALID, 'allcrnlenc-cont', sub { s{(.)}{ sprintf("=%02X=\n",ord($1)) }seg; $_ .="\n" } ],
	[ UNCOMMON, 'allenc-cont-space', sub { s{(.)}{ sprintf("=%02X= \n",ord($1)) }eg } ],
	[ UNCOMMON, 'allenc-cont-tab', sub { s{(.)}{ sprintf("=%02X=\t\n",ord($1)) }eg } ],
	[ INVALID, 'lcenc', sub { 
	    my $r = '';
	    while ($_ ne '') {
		my $ss = substr($_,0,40,'');
		$ss =~ s{(.)}{ sprintf("=%02x",ord($1)) }esg;
		$ss .= '=' if $_ ne '';
		$r .= $ss ."\n";
	    }
	    $_ = $r;
	}],
	[ INVALID, 'mcenc', sub { 
	    my $r = '';
	    while ($_ ne '') {
		my $ss = substr($_,0,40,'');
		$ss =~ s{(.)}{ '='.ucfirst(sprintf("%02x",ord($1))) }esg;
		$ss .= '=' if $_ ne '';
		$r .= $ss ."\n";
	    }
	    $_ = $r;
	}],
	[ INVALID, 'H2=aH', sub { $_ = _qp($_); s{(?<!=[0-9A-F])([0-9A-F])}{=a$1}g; }],
	[ INVALID, 'O2=O', sub { $_ = _qp($_); s{([^0-9A-Fa-f])}{=$1}g; }],
	[ INVALID, 'O2=HO', sub { $_ = _qp($_); s{([^0-9A-Fa-f])}{=0$1}g; }],
	[ INVALID, '=_allenc-cont', sub { s{(.)}{ sprintf("==%02X=\n",ord($1)) }eg } ],
	[ INVALID, '=H_allenc-cont', sub { s{(.)}{ sprintf("=0=%02X=\n",ord($1)) }eg } ],
	[ INVALID, '=HX_allenc-cont', sub { s{(.)}{ sprintf("=0X=%02X=\n",ord($1)) }eg } ],
	[ INVALID, '=Hh_allenc-cont', sub { s{(.)}{ sprintf("=0a=%02X=\n",ord($1)) }eg } ],
	[ INVALID, '=XX_allenc-cont', sub { s{(.)}{ sprintf("=XX=%02X=\n",ord($1)) }eg } ],
	[ INVALID, '=W_allenc-cont', sub { s{(.)}{ sprintf("= =%02X=\n",ord($1)) }eg } ],
	[ INVALID, '=WW_allenc-cont', sub { s{(.)}{ sprintf("=  =%02X=\n",ord($1)) }eg } ],
	[ INVALID, 'allenc_but=X', sub { s{(=[^0-9A-H\n])|(.)}{ $1 || sprintf("=%02X=\n",ord($2)) }eg } ],
    ) {
	my ($valid,$id,$sub) = @$_;
	my (@newbody,$changed);
	for my $body (@body) {
	    local $_ = $body;
	    &$sub;
	    $changed++ if $_ ne $body;
	    push @newbody, $_
	}
	push @r, [ $valid, $id, @newbody ] if $changed;
    }
    return @r;
}

sub quotedprint {
    my @body = @_;
    my @v = _variants(@body);
    my ($allenc) = grep { $_->[1] eq 'allenc-cont' } @v or die;
    @v = grep { $_->[1] ne 'allenc-cont' } @v;
    return traverse_sub(ESSENTIAL, 'qp', [
	$allenc,
	_basic(@body),
	@v
    ]);
}

1;
