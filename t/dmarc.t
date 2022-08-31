#!/usr/bin/perl

use lib '.'; use lib 't';

use Test::More;

use constant HAS_MAILSPF => eval { require Mail::SPF; };
use constant HAS_DKIM_VERIFIER => eval {
  require Mail::DKIM::Verifier;
  version->parse(Mail::DKIM::Verifier->VERSION) >= version->parse(0.31);
};
use constant HAS_MAILDMARC => eval { require Mail::DMARC::PurePerl; };

plan skip_all => "Needs Mail::SPF" unless HAS_MAILSPF;
plan skip_all => "Needs Mail::DMARC::PurePerl" unless HAS_MAILDMARC;
plan skip_all => "Needs Mail::DKIM::Verifier >= 0.31" unless HAS_DKIM_VERIFIER ;
plan tests => 9;

sub tstprefs {
  my $rules = shift;
  open(OUT, '>', 't/rules/dmarc.cf') or die("Cannot write to rules directory: $!");
  print OUT $rules;
  close OUT;
}

sub tstcleanup {
  unlink('t/rules/dmarc.cf');
}

my $sarun = qx{which spamassassin 2>&1};

tstprefs("
  loadplugin Mail::SpamAssassin::Plugin::SPF
  loadplugin Mail::SpamAssassin::Plugin::DKIM
  loadplugin Mail::SpamAssassin::Plugin::DMARC ../../DMARC.pm

header SPF_PASS     eval:check_for_spf_pass()
tflags SPF_PASS     nice userconf net
full   DKIM_SIGNED  eval:check_dkim_signed()
tflags DKIM_SIGNED  net

header DMARC_PASS eval:check_dmarc_pass()
tflags DMARC_PASS net

header DMARC_NONE eval:check_dmarc_none()
tflags DMARC_NONE net

header DMARC_QUAR eval:check_dmarc_quarantine()
tflags DMARC_QUAR net

header DMARC_REJECT eval:check_dmarc_reject()
tflags DMARC_REJECT net

header DMARC_MISSING eval:check_dmarc_missing()
tflags DMARC_MISSING net

");

chomp($sarun);
my $test = qx($sarun -t --siteconfigpath=t/rules < t/data/nice/dmarc/noneok.eml);
like($test, "/DMARC_PASS/");

$test = qx($sarun -t --siteconfigpath=t/rules < t/data/nice/dmarc/quarok.eml);
unlike($test, "/DMARC_QUAR/");

$test = qx($sarun -t --siteconfigpath=t/rules < t/data/nice/dmarc/rejectok.eml);
unlike($test, "/DMARC_REJECT/");

$test = qx($sarun -t --siteconfigpath=t/rules < t/data/nice/dmarc/strictrejectok.eml);
unlike($test, "/DMARC_REJECT/");

$test = qx($sarun -t --siteconfigpath=t/rules < t/data/spam/dmarc/noneko.eml);
like($test, "/DMARC_NONE/");

$test = qx($sarun -t --siteconfigpath=t/rules < t/data/spam/dmarc/quarko.eml);
like($test, "/DMARC_QUAR/");

$test = qx($sarun -t --siteconfigpath=t/rules < t/data/spam/dmarc/rejectko.eml);
like($test, "/DMARC_REJECT/");

$test = qx($sarun -t --siteconfigpath=t/rules < t/data/spam/dmarc/strictrejectko.eml);
like($test, "/DMARC_REJECT/");

$test = qx($sarun -t --siteconfigpath=t/rules < t/data/spam/dmarc/nodmarc.eml);
like($test, "/DMARC_MISSING/");

tstcleanup();
