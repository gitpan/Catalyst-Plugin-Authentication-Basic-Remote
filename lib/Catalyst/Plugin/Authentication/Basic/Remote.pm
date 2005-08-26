package Catalyst::Plugin::Authentication::Basic::Remote;

use strict;
use NEXT;

use LWP::UserAgent;
use MIME::Base64;

our $VERSION = '0.01';

=head1 NAME

Catalyst::Plugin::Authentication::Basic::Remote - Authentication at Remote host's Basic one.

=head1 SYNOPSIS

  use Catalyst;
  MyApp->setup(qw/Authentication::Basic::Remote Session::FastMmap/);

  MyApp->config(
      authentication => {
          auth_url => 'http://example.com/',
	  
	  # option
	  view_tt  => 'MyApp::V::TT',
	  template => '401.tt',
      },
  );

=head1 DESCRIPTION

Catalyst authentication plugin that use remote host's Basic authentication.

It is only first time that plugin request to remote host for authentication.
After that, user infomation keeps in sessions.

=head1 METHODS

=over 4

=item prepare

=cut

sub prepare {
    my $c = shift;

    $c = $c->NEXT::prepare(@_);

    if ( $c->session->{user} and $c->session->{pass} ) {
        $c->req->{user}     = $c->session->{user};
        $c->req->{password} = $c->session->{password};
        return $c;
    }

    if ( $c->config->{authentication}->{auth_url} ) {
        if ( my ($tokens) = ( $c->req->header('Authorization') =~ /^Basic (.+)$/ ) ) {
            my ( $username, $password ) = split /:/, decode_base64($tokens);

            my $ua = LWP::UserAgent->new;
            my $req = HTTP::Request->new( HEAD => $c->config->{authentication}->{auth_url} );
            $req->header( 'Authorization' => $c->req->header('Authorization') );

            my $res = $ua->request($req);

            if ( $res->code ne '401' ) {
                $c->req->{user}         = $username;
                $c->session->{user}     = $username;
                $c->req->{password}     = $password;
                $c->session->{password} = $password;
            }
        }

        unless ( $c->req->{user} ) {
            $c->res->status(401);
            $c->res->header( 'WWW-Authenticate' =>
                  qq!Basic realm="@{[ $c->config->{authentication}->{auth_name} || 'Require Authorization' ]}"!
            );
        }
    }

    return $c;
}

=item dispatch

=cut

sub dispatch {
    my $c = shift;

    if ( $c->config->{authentication}->{template} ) {
        my $view = $c->config->{authentication}->{view_tt} || $c->config->{name};

        if ($view) {
            $c->stash->{template} = $c->config->{authentication}->{template};
            $c->forward($view);
            return;
        }
    }

    return $c->NEXT::dispatch(@_);
}

=item logout

=cut

sub logout {
    my ( $c, $username, $password ) = @_;

    return unless $c->config->{authentication}->{auth_url};

    delete $c->session->{user}     if $c->session->{user};
    delete $c->session->{password} if $c->session->{password};

    delete $c->req->{user}     if $c->req->{user};
    delete $c->req->{password} if $c->req->{password};

    1;
}

=back

=head1 SEE ALSO

L<Catalyst>

=head1 AUTHOR

Daisuke Murase, E<lt>typester@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Daisuke Murase

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.


=cut

1;
