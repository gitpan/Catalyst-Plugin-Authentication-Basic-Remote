use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'Catalyst::Plugin::Authentication::Basic::Remote',
    VERSION_FROM      => 'lib/Catalyst/Plugin/Authentication/Basic/Remote.pm',
    ABSTRACT_FROM  => 'lib/Catalyst/Plugin/Authentication/Basic/Remote.pm',
    PREREQ_PM         => {
        Catalyst => '5.30',
	'LWP::UserAgent' => 0,
	'MIME::Base64' => 0,
    },
    AUTHOR         => 'Daisuke Murase <typester@cpan.org>',
);
