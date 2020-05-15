#!/usr/bin/perl

use warnings;
use Sys::Hostname;
use Getopt::Long;
use Term::ANSIColor qw(:constants);
use POSIX;
use File::Find;
use Term::ANSIColor;

$ENV{'PATH'} = '/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin';

## OPTIONS ##

my %opts;
my $domain;
my $sent;
my $blacklists;
my $help;

GetOptions(
    \%opts,
    'domain=s'     => \$domain,
    'sent:s'       => \$sent,
    'email:s'      => \$email,
    'blacklists:s' => \$blacklists,
    'help'         => \$help
) or die("Please see --help\n");

## GLOBALS ##



## GUTS ##

if ($domain) {    ## --domain{

    domain_exist();

}

else {    ## No options passed.

    print_normal(
        "There are currently $queue_cnt messages in the Exim queue.\n");

}

## Colors ##

sub print_info {
    my $text = shift;
    print BOLD YELLOW ON_BLACK $text;
    print color 'reset';
}

sub print_warning {
    my $text = shift;
    print BOLD RED ON_BLACK "$text";
    print color 'reset';
}

sub print_normal {
    my $text = shift;
    print BOLD CYAN ON_BLACK "$text";
    print color 'reset';
}





### DOMAIN CHEX ###

sub hostname_check {
    if ( $hostname eq $domain ) {
        print_warning(
"[WARN] * Your hostname $hostname appears to be the same as $domain.  Was this intentional?\n"
        );
    }
}

sub domain_exist {
    open( USERDOMAINS, "/etc/userdomains" );
    while (<USERDOMAINS>) {
        if (/^$domain: (\S+)/i) {
            my $user = $1;
            print_info("\n[INFO] *");
            print_normal(" The domain $domain is owned by $user.\n");
            my $suspchk = "/var/cpanel/suspended/$user";
            if ( -e $suspchk ) {
                print_warning("[WARN] * The user $user is SUSPENDED.\n");
            }
            return;
        }
    }
    print_warning(
        "[WARN] * The domain $domain DOES NOT exist on this server.\n");
    close(USERDOMAINS);
}



 
