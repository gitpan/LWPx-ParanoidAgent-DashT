#!/usr/bin/perl
#

use strict;
use LWPx::ParanoidAgent::DashT;
use Time::HiRes qw(time);
use Test::More;
use IO::Socket::INET;

my ($t1, $td);
my $delta = sub { printf " %.03f secs\n", $td; };

my $ua = LWPx::ParanoidAgent::DashT->new;

my ($HELPER_IP, $HELPER_PORT) = ("127.66.74.70", 9001);

my $child_pid = fork;

if (defined($child_pid)) {
  plan tests => 7;
} else {
  plan skip_all => q{No fork(), therefore I can't fork our testing webserver.};
}

web_server_mode() if ! $child_pid;
select undef, undef, undef, 0.5;

my $HELPER_SERVER = "http://$HELPER_IP:$HELPER_PORT";


$ua->whitelisted_hosts(
                       $HELPER_IP,
                       );

$ua->blocked_hosts(
                   qr/\.lj$/,
                   "1.2.3.6",
                   );

my $res;

# redirecting to invalid host
$res = $ua->get("$HELPER_SERVER/redir/http://10.2.3.4/");
print $res->status_line, "\n";
ok(! $res->is_success, q{Can't redirect to invalid host});

# redirect with tarpitting
print "4 second redirect tarpit (tolerance 2)...\n";
$ua->timeout(2);
$res = $ua->get("$HELPER_SERVER/redir-4/http://www.danga.com/");
ok(! $res->is_success, q{4 second redirect tarpit, 2 second timeout}) or 
  diag(q{This test can easily fail (it's time-dependent) if other things are running.});

# lots of slow redirects adding up to a lot of time
print "Three 1-second redirect tarpits (tolerance 2)...\n";
$ua->timeout(2);
$t1 = time();
$res = $ua->get("$HELPER_SERVER/redir-1/$HELPER_SERVER/redir-1/$HELPER_SERVER/redir-1/http://www.danga.com/");
$td = time() - $t1;
$delta->();
ok($td < 2.5, q{Less than 2.5 seconds on a 2 second timeout}) or 
  diag(q{This test can easily fail (it's time-dependent) if other things are running.});
ok(! $res->is_success, q{3 1-second redirect tarpits, 2 second timeout}) or 
  diag(q{This test can easily fail (it's time-dependent) if other things are running.});

# redirecting a bunch and getting the final good host
$res = $ua->get("$HELPER_SERVER/redir/$HELPER_SERVER/redir/$HELPER_SERVER/redir/http://www.danga.com/");
ok( $res->is_success && $res->request->uri->host eq "www.danga.com",
   q{Redirect 3 times...}) or diag(q{This test occasionally fails randomly. Try it again.});

# dying in a tarpit
print "5 second tarpit (tolerance 2)...\n";
$ua->timeout(2);
$res = $ua->get("$HELPER_SERVER/1.5");
ok(!  $res->is_success, q{5 second tarpit, 2 second timeout}) or 
  diag(q{This test can easily fail (it's time-dependent) if other things are running.});

# making it out of a tarpit.
print "3 second tarpit (tolerance 4)...\n";
$ua->timeout(4);
$res = $ua->get("$HELPER_SERVER/1.3");
ok(  $res->is_success, q{3 second tarpit, 4 second timeout}) or 
  diag(q{This test can easily fail (it's time-dependent) if other things are running.});

kill 9, $child_pid;

sub web_server_mode {
    my $ssock = IO::Socket::INET->new(Listen    => 5,
                                      LocalAddr => $HELPER_IP,
                                      LocalPort => $HELPER_PORT,
                                      ReuseAddr => 1,
                                      Proto     => 'tcp')
        or die "Couldn't start webserver.\n";

    while (my $csock = $ssock->accept) {
        exit 0 unless $csock;
        fork and next;

        my $eat = sub {
            while (<$csock>) {
                last if ! $_ || /^\r?\n/;
            }
        };

        my $req = <$csock>;
        print STDERR "    ####### GOT REQ:  $req" if $ENV{VERBOSE};

        if ($req =~ m!^GET /(\d+)\.(\d+) HTTP/1\.\d+\r?\n?$!) {
            my ($delay, $count) = ($1, $2);
            $eat->();
            print $csock
                "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n";
            for (1..$count) {
                print $csock "[$_/$count]\n";
                sleep $delay;
            }
            exit 0;
        }

        if ($req =~ m!^GET /redir/(\S+) HTTP/1\.\d+\r?\n?$!) {
            my $dest = $1;
            $eat->();
            print $csock
                "HTTP/1.0 302 Found\r\nLocation: $dest\r\nContent-Length: 0\r\n\r\n";
            exit 0;
        }

        if ($req =~ m!^GET /redir-(\d+)/(\S+) HTTP/1\.\d+\r?\n?$!) {
            my $sleep = $1;
            sleep $sleep;
            my $dest = $2;
            $eat->();
            print $csock
                "HTTP/1.0 302 Found\r\nLocation: $dest\r\nContent-Length: 0\r\n\r\n";
            exit 0;
        }

        print $csock
            "HTTP/1.0 500 Server Error\r\n" .
            "Content-Length: 10\r\n\r\n" .
            "bogus_req\n";
        exit 0;
    }
    exit 0;
}
