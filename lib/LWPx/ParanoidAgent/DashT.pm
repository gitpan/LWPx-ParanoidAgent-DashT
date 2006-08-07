package LWPx::ParanoidAgent::DashT;
require LWPx::ParanoidAgent;

LWPx::ParanoidAgent->VERSION('1.02');

use vars qw(@ISA $VERSION);
@ISA = qw(LWPx::ParanoidAgent);
$VERSION = '1.021';

sub new {
    my $class = shift;
    my %opts = @_;

    my $self = LWPx::ParanoidAgent->new( %opts );

    $self = bless $self, $class;
    return $self;
}

sub _resolve {
    my ($self, $host, $request, $timeout, $depth) = @_;
    my $res = $self->resolver;
    $depth ||= 0;

    die "CNAME recursion depth limit exceeded.\n" if $depth > 10;
    die "Suspicious results from DNS lookup" if $self->_bad_host($host);

    # return the IP address if it looks like one and wasn't marked bad
    return ($host) if $host =~ /^\d+\.\d+\.\d+\.\d+$/;

    my $sock = $res->bgsend($host)
        or die "No sock from bgsend";

    my $rin = '';
    vec($rin, fileno($sock), 1) = 1;
    my $nf = select($rin, undef, undef, $self->_time_remain($request));
    die "DNS lookup timeout" unless $nf;

    my $packet = $res->bgread($sock)
        or die "DNS bgread failure";
    $sock = undef;

    my @addr;
    my $cname;
    foreach my $rr ($packet->answer) {
        if ($rr->type eq "A") {
            die "Suspicious DNS results from A record\n" if $self->_bad_host($rr->address);
            push @addr, join(".", ($rr->address =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/));
        } elsif ($rr->type eq "CNAME") {
            # will be checked for validity in the recursion path
            $cname = $rr->cname;
        }
    }

    return @addr if @addr;
    return () unless $cname;
    return $self->_resolve($cname, $request, $timeout, $depth + 1);
}

1;

__END__

=head1 NAME

LWPx::ParanoidAgent::DashT - subclass of LWPx::ParanoidAgent that runs under -T

=head1 SYNOPSIS

 #!perl -T

 require LWPx::ParanoidAgent::DashT;

 my $ua = LWPx::ParanoidAgent::DashT->new;

 # and then just like a normal LWP::UserAgent
 # or a LWPx::ParanoidAgent, because it is one.
 my $response = $ua->get('http://search.cpan.org/');

=head1 DESCRIPTION

"The C<LWPx::ParanoidAgent> is a class subclassing C<LWP::UserAgent>,
but paranoid against attackers.  It's to be used when you're fetching
a remote resource on behalf of a possibly malicious user." -- from the 
C<LWPx::ParanoidAgent> documentation.

Unfortunately, it doesn't check the output of the resolver it uses, 
and so leaves the IP address tainted, and it eventually tries to pass
that tainted IP address into C<connect>, whech then fails when used 
with perl's -T option, which is recommended for use when outside data
could be malicious.

This is true even if the address passed in was originally untainted, 
as long as it wasn't an IP address to start with.

This class replaces the _resolve subroutine with one that breaks 
apart the IP address returned and puts it back together, therefore 
untainting it before returning.

(If you only trust a specific DNS server, set the resolver object 
[a C<Net::DNS::Resolver>] accordingly before calling the get() 
routine, of course.)

=head1 SEE ALSO

See L<LWPx::ParanoidAgent> to see how to use this class.

=head1 AUTHOR

Curtis Jewell <csjewell@cpan.org>

=head1 COPYRIGHT

Copyright 2006 Curtis Jewell

Lot of code from the base classes Copyright 2005 Brad Fitzpatrick 
and Copyright 1995-2004 Gisle Aas.

This library is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.
