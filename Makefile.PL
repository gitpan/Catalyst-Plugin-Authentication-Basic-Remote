use ExtUtils::MakeMaker;
WriteMakefile(
    NAME              => 'Catalyst::Plugin::Authentication::Basic::Remote',
    VERSION_FROM      => 'lib/Catalyst/Plugin/Authentication/Basic/Remote.pm', # finds $VERSION
    PREREQ_PM         => {
	'LWP::UserAgent' => 0,
	'MIME::Base64' => 0,
    },
    ABSTRACT_FROM  => 'lib/Catalyst/Plugin/Authentication/Basic/Remote.pm',
    AUTHOR         => 'Daisuke Murase <typester@cpan.org>',
);
