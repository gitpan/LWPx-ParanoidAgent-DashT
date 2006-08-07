#!/usr/bin/perl -T
#

use strict;
use LWPx::ParanoidAgent::DashT;
use Test::More tests => 17;
use Net::DNS;

my $ua = LWPx::ParanoidAgent::DashT->new;

$ua->blocked_hosts(
                   qr/\.lj$/,
                   "1.2.3.6",
                   );

my $res;

# hostnames pointing to internal IPs
$res = $ua->get("http://localhost-fortest.danga.com/");
ok(! $res->is_success && $res->status_line =~ /Suspicious DNS results/, 
   q{Can't get http://localhost-fortest.danga.com/ - Suspicious DNS results});

# random IP address forms
$res = $ua->get("http://0x7f.1/");
ok(! $res->is_success && $res->status_line =~ /blocked/, 
   q{Can't get http://0x7f.1/ - blocked});
$res = $ua->get("http://0x7f.0xffffff/");
ok(! $res->is_success && $res->status_line =~ /blocked/, 
   q{Can't get http://0x7f.0xffffff/ - blocked});
$res = $ua->get("http://037777777777/");
ok(! $res->is_success && $res->status_line =~ /blocked/, 
   q{Can't get http://037777777777/ - blocked});
$res = $ua->get("http://192.052000001/");
ok(! $res->is_success && $res->status_line =~ /blocked/, 
   q{Can't get http://192.052000001/ - blocked});
$res = $ua->get("http://0x00.00/");
ok(! $res->is_success && $res->status_line =~ /blocked/, 
   q{Can't get http://0x00.00/ - blocked});

# test the the blocked host above in decimal form is blocked by this non-decimal form:
$res = $ua->get("http://0x01.02.0x306/");
ok(! $res->is_success && $res->status_line =~ /blocked/, 
   q{Can't get http://0x01.02.0x306/ - blocked});

# hostnames doing CNAMEs (this one resolves to "brad.lj", which is verboten)
my $old_resolver = $ua->resolver;
$ua->resolver(Net::DNS::Resolver->new(nameservers => [  qw(66.150.15.140) ] ));
$res = $ua->get("http://bradlj-fortest.danga.com/");
print $res->status_line, "\n";
ok(! $res->is_success, q{Can't get http://bradlj-fortest.danga.com/});
$ua->resolver($old_resolver);

# black-listed via blocked_hosts
$res = $ua->get("http://brad.lj/");
print $res->status_line, "\n";
ok(! $res->is_success, q{Can't get http://brad.lj/});

# can't do octal in IPs
$res = $ua->get("http://012.1.2.1/");
print $res->status_line, "\n";
ok(! $res->is_success, q{Can't get http://012.1.2.1/});

# can't do decimal/octal IPs
$res = $ua->get("http://167838209/");
print $res->status_line, "\n";
ok(! $res->is_success, q{Can't get http://167838209/});

# checking that port isn't affected
$res = $ua->get("http://brad.lj:80/");
print $res->status_line, "\n";
ok(! $res->is_success, q{Can't get http://brad.lj:80/});

# this domain is okay.  bradfitz.com isn't blocked
$res = $ua->get("http://bradfitz.com/");
print $res->status_line, "\n";
ok(  $res->is_success, q{CAN get http://bradfitz.com/} );

# SSL should still work, assuming it would work before.
SKIP: {
  eval { require Crypt::SSLeay };
  my $err1 = @_;
  eval { require IO::Socket::SSL };
  my $err2 = @_;

  skip "Crypt::SSLeay or IO::Socket::SSL not installed", 1 if (defined($err1) && defined($err2));

  $res = $ua->get("https://pause.perl.org/pause/query");
  ok(  $res->is_success && $res->content =~ /Login|PAUSE|Edit/,
    q{CAN get https://pause.perl.org/pause/query});
}

# internal. bad.  blocked by default by module.
$res = $ua->get("http://10.2.3.4/");
print $res->status_line, "\n";
ok(! $res->is_success, q{Can't get http://10.2.3.4/});

# okay
$res = $ua->get("http://danga.com/temp/");
print $res->status_line, "\n";
ok(  $res->is_success, q{CAN get http://danga.com/temp/});

# localhost is blocked, case insensitive
$res = $ua->get("http://LOCALhost/temp/");
print $res->status_line, "\n";
ok(! $res->is_success, q{Can't get http://LOCALhost/temp/});