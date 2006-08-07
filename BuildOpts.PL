#!perl

# These are the build options that Build.PL actually uses.

%main::opts =
  (
    module_name        => 'LWPx::ParanoidAgent::DashT',
    license            => 'perl',
    dynamic_config     => 0,
    create_makefile_pl => 'traditional',
    requires           => {
      'LWPx::ParanoidAgent'
                       => '1.02',
    },
    build_requires => {
      'Test::More'     => 0,  # core in 5.7.3
      'Time::HiRes'    => 0,
      'Net::DNS'       => 0,  
      'IO::Socket::INET'
                       => 0   # It's core in 5.6.0, but just to be safe...
    },
    recommends => {
      'Crypt::SSLeay'  => 0,  # If you want to be able to use https to check OpenID's.
    },
  );
