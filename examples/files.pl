#!/usr/local/bin/perl

use diagnostics;
use strict;
use warnings;
use Digest::SHA2;
use MIME::Base64;

my $file = "strings.pl";
open INFILE, $file or die "$file not found";

my $sha2obj = new Digest::SHA2;   # default output is 256 bits
$sha2obj->addfile(*INFILE);
my $hex_output = $sha2obj->hexdigest();
my $base64_output = $sha2obj->base64digest();
close INFILE;
print "$file\n";
print "$hex_output\n";
print "$base64_output\n";

