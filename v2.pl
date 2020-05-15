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

sub rdns_lookup {
    my @files = qw(/var/cpanel/mainip /etc/mailips);
    my @ips   = '';

    foreach my $files (@files) {
        open FILE, "$files";
        while ( $lines = <FILE> ) {
            if ( $lines =~ m/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/ )
            {
                $lines = $1;
                my $check = qx/host $lines/;
                chomp($check);
                if ( $check =~ /NXDOMAIN/ ) {
                    print_warning(
                        "[WARN] * $lines does not have a RDNS entry: $check\n");
                }
                else {
                    print_info("[INFO] *");
                    print_normal(" $lines has RDNS entry:   $check\n");
                }
            }
        }
    }
}

sub nobodyspam_tweak {
    my @nobodytweak = split( /=/, `grep nobodyspam /var/cpanel/cpanel.config` );
    chomp( $nobodyspam = pop @nobodytweak );
    print_warning(
        "[WARN] * Nobody user (nobodyspam) is prevented from sending mail.\n")
      if ($nobodyspam);
    if ( !$nobodyspam ) {
        print_info("[INFO] *");
        print_normal(" Nobody user tweak (nobodyspam) is disabled.\n");
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

sub domain_filters {
    print_warning(
"[WARN] * The virtual filter for $domain is NOT empty (/etc/vfilters/$domain).\n"
    ) if -s "/etc/vfilters/$domain";
}

sub check_local_or_remote {

    open my $loc_domain, '<', '/etc/localdomains';
    while (<$loc_domain>) {
        if (/^${domain}$/) {
            print_info("[INFO] *");
            print_normal(" $domain is in LOCALDOMAINS.\n");
        }
    }
    close $loc_domain;

    open my $remote_domain, '<', '/etc/remotedomains';
    while (<$remote_domain>) {
        if (/^${domain}$/) {
            print_info("[INFO] *");
            print_normal(" $domain is in REMOTEDOMAINS.\n");
            last;
        }
    }
    close $remote_domain;
}

sub mx_check {
    @mx_record = qx/dig mx $domain +short/;
    chomp(@mx_record);
    my @dig_mx_ip;

    foreach $mx_record (@mx_record) {
        $dig_mx_ip = qx/dig $mx_record +short/;
        push( @dig_mx_ip, $dig_mx_ip );
        chomp(@dig_mx_ip);

    }

    foreach my $mx_record (@mx_record) {
        print_info("\t \\_ MX Record: $mx_record\n");
    }
    foreach (@mx_record) {
        print_info( "\t\t \\_ " . qx/dig $_ +short/ );

    }
}

sub domain_resolv {
    chomp( $domain_ip = run( 'dig', $domain, '@8.8.4.4', '+short' ) );
    if ( grep { $_ eq $domain_ip } @local_ipaddrs_list ) {
        print_info("[INFO] *");
        print_normal(
            " The domain $domain resolves to IP: \n\t \\_ $domain_ip\n");
        return;
    }
    elsif ( ( !defined $domain_ip ) || ( $domain_ip eq '' ) ) {
        print_warning(
"[WARN] * Domain did not return an A record.  It is likely not registered or not pointed to any IP\n"
        );
    }
    else {
        print_warning(
            "[WARN] * The domain $domain DOES NOT resolve to this server.\n");
        print_warning("\t\\_ It currently resolves to:      $domain_ip \n");
    }

    sub check_blacklists {

        # Way more lists out there, but I'll add them later.
        my %list = (
            'sbl-xbl.spamhaus.org'        => 'Spamhaus',
            'pbl.spamhaus.org'            => 'Spamhaus',
            'sbl.spamhaus.org'            => 'Spamhaus',
            'bl.spamcop.net'              => 'SpamCop',
            'dsn.rfc-ignorant.org'        => 'Rfc-ignorant.org',
            'postmaster.rfc-ignorant.org' => 'Rfc.ignorant.org',
            'abuse.rfc-ignorant.org'      => 'Rfc.ignorant.org',
            'whois.rfc-ignorant.org'      => 'Rfc.ignorant.org',
            'ipwhois.rfc-ignorant.org'    => 'Rfc.ignorant.org',
            'bogusmx.rfc-ignorant.org'    => 'Rfc.ignorant.org',
            'dnsbl.sorbs.net'             => 'Sorbs',
            'badconf.rhsbl.sorbs.net'     => 'Sorbs',
            'nomail.rhsbl.sorbs.net'      => 'Sorbs',
            'cbl.abuseat.org'             => 'Abuseat.org',
            'relays.visi.com'             => 'Visi.com',
            'zen.spamhaus.org'            => 'Spamhaus',
            'bl.spamcannibal.org'         => 'Spamcannibal',
            'ubl.unsubscore.com'          => 'LashBack',
            'b.barracudacentral.org'      => 'Barracuda',
        );

        # Grab the mail addresses

        my @files = qw(/var/cpanel/mainip /etc/mailips);

        my @ips = '';

        foreach my $files (@files) {
            open FILE, "$files";
            while ( $lines = <FILE> ) {
                if ( $lines =~
                    m/([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/ )
                {
                    $lines         = "$1\.$2\.$3\.$4";
                    $reverse_lines = "$4\.$3\.$2\.$1";
                    chomp $lines;
                    chomp $reverse_lines;
                    push @ips,         $lines;
                    push @reverse_ips, $reverse_lines;
                }
            }
            close FILE;
        }

        shift @ips;

        print_info("[INFO] * ");
        print_normal("Checking Blacklists:\n");

        foreach $reverse_ip (@reverse_ips) {
            my $ip = shift @ips;
            while ( ( $key, $value ) = each %list ) {
                my $host = "$reverse_ip.$key\n";
                chomp($host);
                $ret = run( "host", "$host" );
                $ret2 = grep( /(NXDOMAIN|SERVFAIL)/, $ret );
                $status = $ret2 ? "not listed" : "is listed";
                if ( $status eq 'not listed' ) {
                    print "";
                }
                else {
                    print_warning("\t\\_");
                    print_normal(" $ip ");
                    print_warning("$status on $value\n");
                }
            }
        }

        sub check_spf {
            my @check = qx/dig $domain TXT/;
            if ( grep ( m/.*spf.*/, @check ) ) {
                print_info("[INFO] *");
                print_normal(" $domain has the folloiwng SPF records:\n");
                foreach my $check (@check) {
                    if ( $check =~ m/.*spf.*/ ) {
                        print_normal("\t\\_ $check");
                    }
                }
            }
            else {
                return;
            }
        }

        sub check_dkim {
             @check_dkim = qx/dig default._domainkey.$domain TXT +short/;
            if (@check_dkim) {
                foreach my $check_dkim(@check_dkim) {
                        print_info("[INFO] *");
                        print_normal(
                            " $domain has the following domain keys:\n ");
                        print_normal("\t\\_ $check_dkim");

                }
           }

            else {
                print_warning("[WARN] * Domain does not have a DKIM record\n");
            }
        }

        

## Section for current working directories



            close FILE;

        }
    }
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




      


    }
}
