#
# Author: Giovanni Bechis <gbechis@apache.org>
# Copyright 2020 Giovanni Bechis
#
# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>
#

=head1 NAME

Mail::SpamAssassin::Plugin::Dmarc - check Dmarc policy

=head1 SYNOPSIS

  loadplugin Mail::SpamAssassin::Plugin::Dmarc

  ifplugin Mail::SpamAssassin::Plugin::Dmarc
    meta __DKIM_DEP ( DKIM_VALID || DKIM_INVALID || __DKIM_DEPENDABLE )
    meta __SPF_DEP ( SPF_NONE || SPF_FAIL || SPF_SOFTFAIL || SPF_PASS )
    header __DMARC_REJECT eval:check_dmarc_reject()
    meta DMARC_REJECT ( ( __DKIM_DEP || __SPF_DEP ) && __DMARC_REJECT )
    header DMARC_REJECT eval:check_dmarc_reject()
    describe DMARC_REJECT Dmarc reject policy
  endif

=head1 DESCRIPTION

This plugin checks if emails matches Dmarc policy, the plugin needs both DKIM
and SPF plugins.

=cut

package Mail::SpamAssassin::Plugin::Dmarc;

use strict;
use warnings;
use re 'taint';

my $VERSION = 0.1;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;

our @ISA = qw(Mail::SpamAssassin::Plugin);

use constant HAS_DMARC => eval { require Mail::DMARC::PurePerl; };

BEGIN
{
    eval{
      import Mail::DMARC::PurePerl
    };
}

sub dbg { Mail::SpamAssassin::Plugin::dbg ("Dmarc: @_"); }

# XXX copied from "FromNameSpoof" plugin, put into util ?
sub uri_to_domain {
  my ($self, $domain) = @_;

  return unless defined $domain;

  if ($Mail::SpamAssassin::VERSION <= 3.004000) {
    Mail::SpamAssassin::Util::uri_to_domain($domain);
  } else {
    $self->{main}->{registryboundaries}->uri_to_domain($domain);
  }
}

sub new {
    my ($class, $mailsa) = @_;

    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsa);
    bless ($self, $class);

    $self->set_config($mailsa->{conf});
    $self->register_eval_rule("check_dmarc_reject");
    $self->register_eval_rule("check_dmarc_quarantine");
    $self->register_eval_rule("check_dmarc_none");
    $self->register_eval_rule("check_dmarc_missing");

    return $self;
}

sub set_config {
    my ($self, $conf) = @_;
    my @cmds;

=over 4

=item dmarc_save_reports ( 0 | 1 ) (default: 0)

Store DMARC reports using Mail::Dmarc::Store, mail-dmarc.ini must be configured to save and send DMARC reports.

=back

=cut

    push(@cmds, {
        setting => 'dmarc_save_reports',
        default => '0',
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
        }
    );
    $conf->{parser}->register_commands(\@cmds);

}

sub check_dmarc_reject {
  my ($self,$pms,$name) = @_;

  my @tags = ('RELAYSEXTERNAL');

  $pms->action_depends_on_tags(\@tags,
      sub { my($pms, @args) = @_;
        $self->_check_dmarc(@_);
        if((defined $pms->{dmarc_result}) and ($pms->{dmarc_result} eq 'fail') and ($pms->{dmarc_policy} eq 'reject')) {
          $pms->got_hit($pms->get_current_eval_rule_name(), "");
          return 1;
        }
      }
  );
  return 0;
}

sub check_dmarc_quarantine {
  my ($self,$pms,$name) = @_;

  my @tags = ('RELAYSEXTERNAL');

  $pms->action_depends_on_tags(\@tags,
      sub { my($pms, @args) = @_;
        $self->_check_dmarc(@_);
        if((defined $pms->{dmarc_result}) and ($pms->{dmarc_result} eq 'fail') and ($pms->{dmarc_policy} eq 'quarantine')) {
          $pms->got_hit($pms->get_current_eval_rule_name(), "");
          return 1;
        }
      }
  );
  return 0;
}

sub check_dmarc_none {
  my ($self,$pms,$name) = @_;

  my @tags = ('RELAYSEXTERNAL');

  $pms->action_depends_on_tags(\@tags,
      sub { my($pms, @args) = @_;
        $self->_check_dmarc(@_);
        if((defined $pms->{dmarc_result}) and ($pms->{dmarc_result} eq 'fail') and ($pms->{dmarc_policy} eq 'none')) {
          $pms->got_hit($pms->get_current_eval_rule_name(), "");
          return 1;
        }
      }
  );
  return 0;
}

sub check_dmarc_missing {
  my ($self,$pms,$name) = @_;

  my @tags = ('RELAYSEXTERNAL');

  $pms->action_depends_on_tags(\@tags,
      sub { my($pms, @args) = @_;
        $self->_check_dmarc(@_);
        if((defined $pms->{dmarc_result}) and ($pms->{dmarc_policy} eq 'no policy available')) {
          $pms->got_hit($pms->get_current_eval_rule_name(), "");
          return 1;
        }
      }
  );
  return 0;
}

sub _check_dmarc {
  my ($self,$pms,$name) = @_;
  my $spf_status = 'none';
  my $spf_helo_status = 'none';
  my ($dmarc, $lasthop, $result, $rua, $domain);

  if (!HAS_DMARC) {
    warn "check_dmarc not supported, required module Mail::DMARC::PurePerl missing\n";
    return 0;
  }

  if((defined $self->{dmarc_checked}) and ($self->{dmarc_checked} eq 1)) {
    return;
  }
  $dmarc = Mail::DMARC::PurePerl->new();
  $lasthop = $pms->{relays_external}->[0];

  # XXX SpamAssassin 3.4 compat glue
  $pms->{spf_sender} = $pms->{sender} unless defined $pms->{spf_sender};
  $pms->{spf_sender} = $pms->get('EnvelopeFrom:addr') unless defined $pms->{spf_sender};

  return if ( not ref($pms->{dkim_verifier}));
  return if ( $pms->get('From:addr') !~ /\@/ );

  $spf_status = 'pass' if ((defined $pms->{spf_pass}) and ($pms->{spf_pass} eq 1));
  $spf_status = 'fail' if ((defined $pms->{spf_fail}) and ($pms->{spf_fail} eq 1));
  $spf_status = 'fail' if ((defined $pms->{spf_none}) and ($pms->{spf_none} eq 1));
  $spf_status = 'fail' if ((defined $pms->{spf_permerror}) and ($pms->{spf_permerror} eq 1));
  $spf_status = 'neutral' if ((defined $pms->{spf_neutral}) and ($pms->{spf_neutral} eq 1));
  $spf_status = 'softfail' if ((defined $pms->{spf_softfail}) and ($pms->{spf_softfail} eq 1));
  $spf_helo_status = 'pass' if ((defined $pms->{spf_helo_pass}) and ($pms->{spf_helo_pass} eq 1));
  $spf_helo_status = 'fail' if ((defined $pms->{spf_helo_fail}) and ($pms->{spf_helo_fail} eq 1));
  $spf_helo_status = 'fail' if ((defined $pms->{spf_helo_permerror}) and ($pms->{spf_helo_permerror} eq 1));
  $spf_helo_status = 'fail' if ((defined $pms->{spf_helo_none}) and ($pms->{spf_helo_none} eq 1));
  $spf_helo_status = 'neutral' if ((defined $pms->{spf_helo_neutral}) and ($pms->{spf_helo_neutral} eq 1));
  $spf_helo_status = 'softfail' if ((defined $pms->{spf_helo_softfail}) and ($pms->{spf_helo_softfail} eq 1));

  $domain = $self->uri_to_domain($pms->{spf_sender});
  if(not defined $domain) {
    # read domain from mail from if spf is not available
    $domain = $self->uri_to_domain($pms->get('From:addr'));
  }
  $dmarc->source_ip($lasthop->{ip});
  $dmarc->header_from_raw($pms->get('From:addr'));
  $dmarc->dkim($pms->{dkim_verifier});
  eval {
    $dmarc->spf([
      {
        scope  => 'mfrom',
        domain => "$domain",
        result => "$spf_status",
      },
      {
        scope  => 'helo',
        domain => "$lasthop->{lc_helo}",
        result => "$spf_helo_status",
      },
    ]);
    $result = $dmarc->validate();
  };
  if ($@) {
    dbg("Dmarc error while evaluating domain $domain: $@");
    return;
  }

  if(($pms->{conf}->{dmarc_save_reports} == 1) and (defined $result->result)) {
    $rua = eval { $result->published()->rua(); };
    if (defined $rua and $rua =~ /mailto\:/) {
      eval {
        dbg("Dmarc report will be sent to $rua");
        $dmarc->save_aggregate();
      };
      if ( my $error = $@ ) {
        dbg("Dmarc report could not be saved: $error");
      }
    }
  }

  $pms->{dmarc_result} = $result->result;
  if((defined $pms->{dmarc_result}) and ($pms->{dmarc_result} ne 'none')) {
    dbg("result: " . $pms->{dmarc_result} . ", disposition: " . $result->disposition . ", dkim: " . $result->dkim . ", spf: " . $result->spf . " ( spf: $spf_status, spf_helo: $spf_helo_status)");
    $pms->{dmarc_policy} = $result->published->p;
  } else {
    dbg("result: no policy available");
    $pms->{dmarc_policy} = "no policy available";
  }
  $pms->{dmarc_checked} = 1;
  undef $result;
  undef $dmarc;
}

1;
