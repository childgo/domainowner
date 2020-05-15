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

my $hostname = hostname;
chomp( my $queue_cnt = `exim -bpc` );
my @local_ipaddrs_list = get_local_ipaddrs();
get_local_ipaddrs();

## GUTS ##

if ($domain) {    ## --domain{
    hostname_check();
    domain_exist();
    domain_filters();
    check_local_or_remote();
    mx_check();
    mx_consistency();
    domain_resolv();
    check_spf();
    check_dkim();
}

elsif ($help) {    ##--help
    help();
}

elsif ( defined $sent ) {
    sent_email();
}

elsif ( defined $email ) {
    if ( $email =~
/^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$/
      )
    {
        does_email_exist();
        email_valiases();
        email_filters();
        email_quota();
    }
    else {
        die "Please enter a valid email address\n";
    }
}
elsif ( defined $blacklists ) {
    check_blacklists();
}

else {    ## No options passed.
    is_exim_running();
    print_info("\n[INFO] * ");
    print_normal(
        "There are currently $queue_cnt messages in the Exim queue.\n");
    nobodyspam_tweak();
    check_for_phphandler();
    port_26();
    custom_etc_mail();
    rdns_lookup();
    check_closed_ports();
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



 
