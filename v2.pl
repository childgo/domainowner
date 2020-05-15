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

##INFORMATIONAL CHEX##

sub help {
    print "Usage: ./sse.pl [OPTION] [VALUE]\n",
"Without options:  Run informational checks on Exim's configuration and server status.\n",
"--domain=DOMAIN   Check for domain's existence, ownership, and resolution on the server.\n",
      "--email=EMAIL     Email specific checks.\n",
      "-s                View Breakdown of sent mail.\n",
      "-b		 Checks the Main IP and IPs in /etc/ips for a few blacklists.\n";
}

sub run
{ #Directly ripped run() from SSP; likely more gratuitous than what is actually needed.  Remember to look into IPC::Run.

    my $cmdline = \@_;
    my $output;
    local ($/);
    my ( $pid, $prog_fh );
    if ( $pid = open( $prog_fh, '-|' ) ) {

    }
    else {
        open STDERR, '>', '/dev/null';
        ( $ENV{'PATH'} ) = $ENV{'PATH'} =~ m/(.*)/;
        exec(@$cmdline);
        exit(127);
    }

    if ( !$prog_fh || !$pid ) {
        $? = -1;
        return \$output;
    }
    $output = readline($prog_fh);
    close($prog_fh);
    return $output;
}

sub get_local_ipaddrs
{ ## Ripped from SSP as well.  Likely less gratuitous, but will likely drop the use of run() in the future cuz IPC.
    my @ifconfig = split /\n/, run( 'ifconfig', '-a' );
    for my $line (@ifconfig) {
        if ( $line =~ m{ (\d+\.\d+\.\d+\.\d+) }xms ) {
            my $ipaddr = $1;
            unless ( $ipaddr =~ m{ \A 127\. }xms ) {
                push @local_ipaddrs_list, $ipaddr;
            }
        }
    }
    return @local_ipaddrs_list;
}

### GENERAL CHEX ###

sub custom_etc_mail {
    print_warning("/etc/exim.conf.local (Custom Exim Configuration) EXISTS.\n")
      if -e '/etc/exim.conf.local';
    print_warning("[WARN] * /etc/mailips is NOT empty.\n") if -s '/etc/mailips';
    print_warning("[WARN] * /etc/mailhelo is NOT empty.\n")
      if -s '/etc/mailhelo';
    print_warning("[WARN] * /etc/reversedns (Custom RDNS) EXISTS.\n")
      if -e '/etc/reversedns';
}

sub port_26 { ## You'll need to remove the double /n as more checks are written.
    if (`netstat -an | grep :26`) {
        print_info("[INFO] *");
        print_normal(" Port 26 is ENABLED.\n");
        return;
    }
    else {
        print_warning("[WARN] * Port 26 is DISABLED.\n");
    }
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



        




sub get_doc_root {
    my ( $user, $domain ) = $email =~ /(.*)@(.*)/;
    my %used;
    my $string       = 'grep -3';
    my $domainstring = "www.$domain";
    my $lookupfile   = '/usr/local/apache/conf/httpd.conf';
    @lines    = qx/$string $domainstring $lookupfile/;
    @dlines   = grep( /^.+?(\/.+\/.+$)/, @lines );
    $numlines = scalar( grep { defined $_ } @dlines );
    if ( $numlines > 1 ) {
        pop @dlines;
        foreach $dlines (@dlines) {
            $doc_root = $dlines;
        }
    }
    elsif ( $numlines < 1 ) {
        print_warning("[WARN] * No Document root found\n");
        return;
    }
    else {
        foreach (@dlines) {
            $doc_root = $_;
        }
    }
}




      


