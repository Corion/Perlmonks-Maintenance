#!/usr/bin/env perl
use warnings;
use strict;
use Data::Dump;
use Net::DNS;
use LWP::UserAgent;
require LWP::Protocol::https; # make sure this is installed
use Class::Method::Modifiers qw/around/;
use Getopt::Long;
use POSIX 'strftime';

=head1 NAME

perlmonks-server-check.pl

=head1 PURPOSE

Lists all SSL certificates that the different webservers serve

=cut

GetOptions(
    'q|quiet' => \my $quiet,
    'format=s' => \my $format,
);
$format //= 'text';

my @ADDRS = qw/
	perlmonks.org www.perlmonks.org css.perlmonks.org
	perlmonks.com www.perlmonks.com css.perlmonks.com
	perlmonks.net www.perlmonks.net css.perlmonks.net
	/;

my $DNS = { # As of 2018-07-25:
  "css.perlmonks.com"      => ["216.92.34.251", "66.39.54.27"],
  "css.perlmonks.net"      => ["216.92.34.251", "66.39.54.27"],
  "css.perlmonks.org"      => ["216.92.34.251", "66.39.54.27"],
  "perlmonks.com"          => ["216.92.34.251", "66.39.54.27"],
  "perlmonks.net"          => ["216.92.34.251", "66.39.54.27"],
  "perlmonks.org"          => ["216.92.34.251", "66.39.54.27"],
  #"perlmonks.pairsite.com" => [],
  "www.perlmonks.com"      => ["216.92.34.251", "66.39.54.27"],
  "www.perlmonks.net"      => ["216.92.34.251", "66.39.54.27"],
  "www.perlmonks.org"      => ["216.92.34.251", "66.39.54.27"],
};
if (1) {
	$DNS={};
	my $resolver = new Net::DNS::Resolver(recurse => 1, debug => 0);
	for my $addr (@ADDRS) {
		# figure out the authoritative server
		$resolver->nameservers('8.8.8.8');
		my $packet = $resolver->send($addr, 'SOA');
		my @server = map {$_->mname} grep {$_->type eq 'SOA'}
			$packet->answer;
		unless (@server==1)
			{ warn "Didn't find exactly one SOA record for $addr"
				." (@server)"; next }
		$packet = $resolver->send($server[0], 'A');
		my @nameservers = map {$_->address} grep {$_->type eq 'A'}
			$packet->answer;
		die "@server" unless @nameservers;
		# query the authoritative server
		$resolver->nameservers(@nameservers);
		$packet = $resolver->send($addr, 'A');
		my @ips = sort map {$_->address} grep {$_->type eq 'A'}
			$packet->answer;
		if( ! $quiet) {
        		printf "%23s %-35s %s\n", $addr,
        			"(\@$server[0]/@nameservers)", join ' ', @ips;
		};
		$DNS->{$addr} = \@ips;
	}
	#dd $DNS;
}

our $force_peeraddr;
around 'LWP::Protocol::http::_extra_sock_opts' => sub {
	my $orig = shift;
	die unless wantarray;
	my @rv = $orig->(@_);
	push @rv, PeerAddr => $force_peeraddr if defined $force_peeraddr;
	return @rv;
};
around 'LWP::Protocol::https::_get_sock_info' => sub {
	my $orig = shift;
	my ($self, $res, $sock) = @_;
	my $cert = $sock->get_peer_certificate;
	my @san = $cert->peer_certificate('subjectAltNames');
	while (@san) {
		my ($type_id, $value) = splice @san, 0, 2;
		$res->push_header("Client-SSL-Cert-SubjectAltName"
			=> "$type_id: $value");
	}
	$orig->(@_);
};

our @params = ('node=Newest+Nodes', '');
our @paths = ('/', '/index.pl');

our $last_status = '';
sub status {
    if( ! $quiet) {
        print "\r" . (" "x length $last_status);
        $last_status = "@_";
        print "\r$last_status";
    }
}

my %certs;
my %server_status;
my $ua = LWP::UserAgent->new( ssl_opts => { verify_hostname => 0 } );
for my $addr (sort keys %$DNS) {
    local $| = 1;
    for my $host (sort @{ $DNS->{$addr} }) {
	status( "Requesting $addr from $host...");
        for my $path (@paths) {
            for my $param (@params) {
		my $url = "https://$addr$path?$param";
		my $key = "$url\0$host";
	        status( "Requesting $url from $host...");
		local $force_peeraddr = $host;
		my $res = $ua->get($url);
                if( ! $res->is_success ) {
		    $server_status{ $key } = $res->status_line;
		    warn "Host: $host: " . $res->status_line;
                } elsif( $res->content !~ /\bNODE\.title\b\s*=\s*([^\r\n]+)/ ) {
                    my $title;
                    if( $res->content =~ m!<title>\s*(.*?)\s*</title>!si ) {
                        $title = $1;
                    } else {
                        $title = substr( $res->content, 100 );
                    };
		    $server_status{ $key } = "Didn't get a Perlmonks site from $host as $addr ('$title')";
		    warn "Didn't get a Perlmonks site from $host as $addr ('$title')";
                    #warn $res->content;
                } else {
	            status( "Requested $url from $host ($1)");
		    $server_status{ $key } = 'OK';
                };
		my @peer = $res->header("client-peer");
		die "@peer" unless @peer==1 && $peer[0] eq "$host:443";
		my @issuer = $res->header("client-ssl-cert-issuer");
		my @subject = $res->header("client-ssl-cert-subject");
		my @san = $res->header("client-ssl-cert-subjectaltname");
		my $certstr = "Issuer: @issuer\nSubject: @subject\n"
			."Subject Alt Names: @san\n";
		$certs{$certstr}->{"$host $addr"} = 1;
            }
	}
    }
}
status( "" );

if( $format eq 'text' ) {
    for my $key (sort keys %server_status) {
        my ($url, $addr) = split /\0/, $key;
        my $vis = "$server_status{ $key } ($addr)";
        print sprintf "%-64s - %s\n", $url, $vis;
    }

    for my $cert (sort keys %certs) {
    	print "##### Certificate #####\n", $cert, "### Served by:\n";
    	printf "%15s %s\n", @$_ for map {[split]} sort keys $certs{$cert}->%*;
    }
} elsif( $format eq 'html' ) {
    my $updated = strftime '%Y-%m-%dT%H:%M:%SZ', gmtime;
    binmode STDOUT, ':encoding(UTF-8)';
    print <<HTML;
<!DOCTYPE html>
<html>
<head>
<title>Perlmonks server health</title>
</head>
<body>
<h1>Perlmonks server health</h1>
<small>Updated: $updated</small>
<table>
HTML

    for my $key (sort keys %server_status) {
        my ($url, $addr) = split /\0/, $key;
        print sprintf '<tr><td><a href="%s">%s</a> (%s)</td><td>%s</td></tr>', $url, $url, $addr, $server_status{ $key };
    }

    print <<HTML;
</table>
<footer>
Created by <a href="https://github.com/Corion/Perlmonks-Maintenance">perlmonks-server-check.pl</a>
</footer>
</body>
</html>
HTML
}

=head1 AUTHOR

Contributed by haukex via L<https://perlmonks.com/?node_id=1216823>

=cut

__END__

# As of 2018-06-29:
##### Certificate #####
Issuer: /C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3
Subject: /CN=perlmonks.com
Subject Alt Names: 2: perlmonks.com 2: www.perlmonks.com
### Served by:
209.197.123.153 css.perlmonks.com
209.197.123.153 css.perlmonks.net
209.197.123.153 css.perlmonks.org
209.197.123.153 perlmonks.com
209.197.123.153 perlmonks.net
209.197.123.153 perlmonks.org
209.197.123.153 perlmonks.pairsite.com
209.197.123.153 www.perlmonks.com
209.197.123.153 www.perlmonks.net
209.197.123.153 www.perlmonks.org
##### Certificate #####
Issuer: /C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3
Subject: /CN=perlmonks.org
Subject Alt Names: 2: css.perlmonks.com 2: css.perlmonks.net 2: css.perlmonks.or
g 2: perlmonks.com 2: perlmonks.net 2: perlmonks.org 2: www.perlmonks.com 2: www
.perlmonks.net 2: www.perlmonks.org
### Served by:
  216.92.34.251 css.perlmonks.com
    66.39.54.27 css.perlmonks.com
  216.92.34.251 css.perlmonks.net
    66.39.54.27 css.perlmonks.net
  216.92.34.251 css.perlmonks.org
    66.39.54.27 css.perlmonks.org
  216.92.34.251 perlmonks.com
    66.39.54.27 perlmonks.com
  216.92.34.251 perlmonks.net
    66.39.54.27 perlmonks.net
  216.92.34.251 perlmonks.org
    66.39.54.27 perlmonks.org
  216.92.34.251 www.perlmonks.com
    66.39.54.27 www.perlmonks.com
  216.92.34.251 www.perlmonks.net
    66.39.54.27 www.perlmonks.net
  216.92.34.251 www.perlmonks.org
    66.39.54.27 www.perlmonks.org
