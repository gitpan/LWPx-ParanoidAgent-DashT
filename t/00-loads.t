#!/usr/bin/perl -T
#

use strict;
use Test::More tests => 4;

require_ok('LWPx::ParanoidAgent::DashT'); # Loads.

my $ua = LWPx::ParanoidAgent::DashT->new;
ok((ref $ua) =~ /LWPx::ParanoidAgent::DashT/, 'The object isa LWPx::ParanoidAgent::DashT');
isa_ok($ua, 'LWPx::ParanoidAgent');
isa_ok($ua, 'LWP::UserAgent');