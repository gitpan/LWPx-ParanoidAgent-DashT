#!perl
use Module::Build;

do "BuildOpts.PL";

my $build = Module::Build->new(%main::opts);
$build->create_build_script;