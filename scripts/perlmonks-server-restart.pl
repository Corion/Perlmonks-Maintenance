#!/usr/bin/env perl
use 5.012;
use strict;
use warnings;
use Log::Log4perl ':easy';
use WWW::Mechanize;
use LWP::ConsoleLogger::Everywhere ();
use YAML 'LoadFile';
use Getopt::Long;

Log::Log4perl->easy_init($WARN);

GetOptions(
    'config|f' => \my $config_file,
) or pod2usage(2);

$config_file //= 'credentials.yaml';

my $mech = WWW::Mechanize->new();

my $config = LoadFile( $config_file );

for my $cr (@$config) {
    my $user = $cr->{user};
    my $pass = $cr->{password};

    say "$user/********";
    $mech->get('https://my.pair.com/login');
    my $res = $mech->submit_form(
        with_fields => {
            USERNAME => $user,
            PASSWORD => $pass,
        }
    );

    $mech->follow_link(text => 'Restart Apache');
    say $mech->title;
    $mech->submit_form(
        form_number => 1,
        button => 'Submit'
    );

}
