package Digest::SHA2;

use strict;
use warnings;
use MIME::Base64;
require Exporter;

our @EXPORT_OK = qw(new hashsize reset add addfile digest hexdigest base64digest);
our $VERSION = '1.0.0';
our @ISA = qw(Exporter);

require XSLoader;
XSLoader::load('Digest::SHA2', $VERSION);

# Preloaded methods go here.

sub addfile
{
    my ($self, $handle) = @_;
    my ($package, $file, $line) = caller;

    if (!ref($handle)) {
        $handle = "$package::$handle" unless ($handle =~ /(\:\:|\')/);
    }

    while (read($handle, my $data, 1048576)) {
        $self->add($data);
    }
}

sub digest
{
    my $self = shift;
    return pack("H*", $self->hexdigest());
}

sub base64digest
{
    my $self = shift;
    return encode_base64($self->digest(), "");
}

1;

__END__

=head1 NAME

Digest::SHA2 - A variable-length one-way hash function

=head1 ABSTRACT

Digest::SHA2 - A Perl interface for SHA-256, SHA-384 and SHA-512,
collectively known as SHA-2

=head1 DESCRIPTION

SHA-2 is the collective name of one-way hash functions developed by the
NIST. SHA-256, SHA-384, and SHA-512 pertain to hashes whose outputs are
256 bits, 384 bits and 512 bits, respectively.

This Perl implementation is meant to be a replacement for the older
SHA256 by Rafael R. Sevilla. His module has a bug in the SHA-256
implementation.

This new implementation uses the C source of Aaron Gifford.

=head1 SYNOPSIS

    use Digest::SHA2;

    $sha2obj = new Digest::SHA2 [$hashlength];
    $sha2obj->add(LIST);
    $sha2obj->addfile(*HANDLE);
    $sha2obj->reset();

    $digest = $sha2obj->digest();
    $digest = $sha2obj->hexdigest();
    $digest = $sha2obj->base64digest();
    
    $digest = $sha2obj->hashsize();

=head1 DESCRIPTION

SHA-2 supports the following functions:

=over

=item B<new($hashlength)>

Creates a SHA-2 object, where B<$hashlength> represents the hash output
length; valid values for B<$hashlength> are 256, 384, and 512 only.
If B<$hashlength> is omitted, the output defaults to 256 bits.

For example, to specify SHA-512, use

        $sha2obj = new Digest::SHA2 512;

To specify the default SHA-256, just use

        $sha2obj = new Digest::SHA2;

=item B<hashsize()>

Returns the digest size (in bits) of the hash output used

=item B<add(LIST)>

Hashes a string or a list of strings

=item B<addfile(*HANDLE)>

Hashes a file

=item B<reset()>

Re-initializes the hash state. Before calculating another digest, the
hash state must be refreshed.

=item B<digest()>

Generates the hash output as a binary string

=item B<hexdigest()>

Generates a hexadecimal representation of the hash output

=item B<base64digest()>

Generates a base64 representation of the hash output. B<MIME::Base64>
must be installed first for this function to work.

=back

=head1 EXAMPLE 1

    #!/usr/local/bin/perl

    use diagnostics;
    use strict;
    use warnings;
    use Digest::SHA2;

    my $string1 = "This is a string.";
    my $string2 = "This is another string.";
    my $string3 = "This is a string.This is another string.";

    my $sha2obj = new Digest::SHA2 512;
    print "hash size=", $sha2obj->hashsize, "\n";

    $sha2obj->add($string1);
    my $digest = $sha2obj->hexdigest();
    print "Hash string1 only\n";
    print "$digest\n\n";

    $sha2obj->reset();
    $sha2obj->add($string1, $string2);
    my $digest2 = $sha2obj->hexdigest();
    print "Hash string1 and then hash string2\n";
    print "$digest2\n\n";
    
    $sha2obj->reset();
    $sha2obj->add($string1);
    $sha2obj->add($string2);
    my $digest3 = $sha2obj->hexdigest();
    print "Hash string1 and then hash string2\n";
    print "$digest3\n\n";
    
    $sha2obj->reset();
    $sha2obj->add($string3);
    print "Hash the two concatenated strings\n";
    my $digest4 = $sha2obj->hexdigest();
    print "$digest4\n";

=head1 EXAMPLE 2

    #!/usr/local/bin/perl

    use diagnostics;
    use strict;
    use warnings;
    use MIME::Base64;
    use Digest::SHA2;

    my $file = "strings.pl";
    open INFILE, $file or die "$file not found";

    my $sha2obj = new Digest::SHA2;  # defaults to 256-bit output
    $sha2obj->addfile(*INFILE);
    my $hex_output = $sha2obj->hexdigest();
    my $base64_output = $sha2obj->base64digest();
    close INFILE;
    print "$file\n";
    print "$hex_output\n";
    print "$base64_output\n";

=head1 MORE EXAMPLES

See the "examples" and "t" directories for more examples.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2003 Julius C. Duque. Please read contact.html that comes
with this distribution for details on how to contact the author.

This library is free software; you can redistribute it and/or modify
it under the same terms as the GNU General Public License.

=head1 ACKNOWLEDGEMENT

I used the C source of Aaron Gifford as backend for this Perl
implementation.

=cut

