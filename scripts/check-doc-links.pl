#!/usr/bin/env perl
use strict;
use warnings;

use Cwd qw(abs_path getcwd);
use File::Basename qw(dirname);
use File::Find qw(find);
use File::Spec;

my $root = abs_path(getcwd());
my @files;

find(
    sub {
        if (-d $_ && ($_ eq '.git' || $_ eq 'dist' || $_ eq 'target')) {
            $File::Find::prune = 1;
            return;
        }
        return if -d $_;
        return unless /\.md\z/;
        push @files, $File::Find::name;
    },
    $root
);

my $failed = 0;

for my $file (sort @files) {
    open my $fh, '<', $file or die "cannot read $file: $!";
    local $/;
    my $content = <$fh>;
    close $fh;

    while ($content =~ /(?<!!)\[[^\]]+\]\(([^)\s]+)(?:\s+["'][^"']*["'])?\)/g) {
        my $target = $1;
        next if $target =~ m{\A(?:https?|mailto):}i;
        next if $target =~ m{\A#};

        $target =~ s/\A<//;
        $target =~ s/>\z//;
        $target =~ s/[?#].*\z//;
        next if $target eq '';

        my $resolved = $target =~ m{\A/}
            ? File::Spec->catfile($root, substr($target, 1))
            : File::Spec->catfile(dirname($file), $target);
        $resolved = File::Spec->canonpath($resolved);

        if (!-e $resolved) {
            my $display_file = File::Spec->abs2rel($file, $root);
            print STDERR "$display_file: broken local link: $target\n";
            $failed = 1;
        }
    }
}

exit $failed;
