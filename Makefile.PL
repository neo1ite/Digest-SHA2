use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME' => 'Digest::SHA2',
    'VERSION_FROM' => 'SHA2.pm',
    'PREREQ_PM' => {'MIME::Base64' => '0'},
    'AUTHOR' => 'Julius C. Duque',
    'LIBS' => [''],
    'DEFINE' => '',
    'INC' => '-I.',
    'OPTIMIZE' => '-O2 -fomit-frame-pointer -Wall -pipe -ffast-math -funroll-loops -Wshadow',
    'dist' => {'COMPRESS' => 'gzip -9f', 'SUFFIX' => 'gz'}
);

