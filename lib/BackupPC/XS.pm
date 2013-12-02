package BackupPC::XS;

use 5.008;
use strict;
use warnings;

require Exporter;

use vars qw( @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS );

@ISA = qw(Exporter);

#
# These must match the file types used by tar
#
use constant BPC_FTYPE_FILE     => 0;
use constant BPC_FTYPE_HARDLINK => 1;
use constant BPC_FTYPE_SYMLINK  => 2;
use constant BPC_FTYPE_CHARDEV  => 3;
use constant BPC_FTYPE_BLOCKDEV => 4;
use constant BPC_FTYPE_DIR      => 5;
use constant BPC_FTYPE_FIFO     => 6;
use constant BPC_FTYPE_SOCKET   => 8;
use constant BPC_FTYPE_UNKNOWN  => 9;
use constant BPC_FTYPE_DELETED  => 10;

my @FILE_TYPES = qw(
                  BPC_FTYPE_FILE
                  BPC_FTYPE_HARDLINK
                  BPC_FTYPE_SYMLINK
                  BPC_FTYPE_CHARDEV
                  BPC_FTYPE_BLOCKDEV
                  BPC_FTYPE_DIR
                  BPC_FTYPE_FIFO
                  BPC_FTYPE_SOCKET
                  BPC_FTYPE_UNKNOWN
                  BPC_FTYPE_DELETED
             );

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use BackupPC::XS ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.

@EXPORT    = qw( );

@EXPORT_OK = (
                  @FILE_TYPES,
             );

%EXPORT_TAGS = (
    'all'    => [ @EXPORT_OK ],
);

our $VERSION = '0.30';

require XSLoader;
XSLoader::load('BackupPC::XS', $VERSION);

# Preloaded methods go here.

#
# If $compress is >0, copy and compress $srcFile putting the output
# in $destFileZ.  Otherwise, copy the file to $destFileNoZ, or do
# nothing if $destFileNoZ is undef.  Finally, if rename is set, then
# the source file is removed.
#
sub compressCopy
{
    my($srcFile, $destFileZ, $destFileNoZ, $compress, $rmSrc) = @_;
    my($srcFh);
    my(@s) = stat($srcFile);
    my $atime = $s[8];
    my $mtime = $s[9];

    if ( $compress > 0 ) {
        my $fh = BackupPC::XS::FileZIO::open($destFileZ, 1, $compress);
        my $data;
        if ( defined($fh) && open($srcFh, "<", $srcFile) ) {
            binmode($srcFh);
            while ( sysread($srcFh, $data, 65536 *4) > 0 ) {
                $fh->write(\$data);
            }
            close($srcFh);
            $fh->close();
            unlink($srcFile) if ( $rmSrc );
            utime($atime, $mtime, $destFileZ);
            return 1;
        } else {
            $fh->close() if ( defined($fh) );
            return 0;
        }
    }
    return 0 if ( !defined($destFileNoZ) );
    if ( $rmSrc ) {
        return rename($srcFile, $destFileNoZ);
    } else {
        return 0 if ( !copy($srcFile, $destFileNoZ) );
        utime($atime, $mtime, $destFileNoZ);
    }
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

BackupPC::XS - Perl extension for BackupPC libraries

=head1 SYNOPSIS

  use BackupPC::XS;
  use BackupPC::XS qw( :all );

=head1 DESCRIPTION

BackupPC::XS provides various submodules that implement various BackupPC library functions.
The following sections describe each submodule.

This documentation is very terse.  BackupPC::XS is not intended to be a general-purpose
module - it is closely tied to BackupPC.  Look in the BackupPC code to see examples of
using this module.

=head2 BackupPC::XS::FileZIO

Compressed file I/O using zlib:

    $fd = BackupPC::XS::FileZIO::open($fileName, $writeFlag, $compressLevel);
    $fd = BackupPC::XS::FileZIO::fdopen($stream, $writeFlag, $compressLevel);
    $nWrite   = $fd->write($dataRef);
    $nRead    = $fd->read($dataRef, $maxRead);
    $textLine = $fd->readLine();
    $fd->rewind();
    $fd->close();
    $fd->writeTeeStderr($boolean);

=head2 BackupPC::XS::PoolRefCnt

Pool file reference counting:

    $countDB = BackupPC::XS::PoolRefCnt::new(initialEntryCnt);
    $refCount = $countDB->get($digest);
    $countDB->set($digest, $refCount);
    $countDB->delete($digest);
    $countDB->incr($digest, $refIncr);
    ($digest, $refCnt, $idx) = $countDB->iterate($idx);
    $countDB->read($fileName);
    $countDB->write($fileName);
    $countDB->print();

Pool file delta accumulation:

    BackupPC::XS::PoolRefCnt::DeltaFileInit($hostDir);
    BackupPC::XS::PoolRefCnt::DeltaFileFlush();
    BackupPC::XS::PoolRefCnt::DeltaUpdate($digest, $refIncr);
    BackupPC::XS::PoolRefCnt::DeltaPrint();

=head2 BackupPC::XS::PoolWrite

Writing and matching files in the pool:

    $poolWrite = BackupPC::XS::PoolWrite::new($compressLevel [, $digest]);
    $poolWrite->write($dataRef);
    ($match, $digest, $poolSize, $error) = $poolWrite->close();
    $poolWrite->addToPool($fileName, $isV3PoolFile);

=head2 BackupPC::XS::Attrib

Manipulating a set of files and attributes (typically one directory's worth):

    $a = BackupPC::XS::Attrib::new($compressLevel);
    $attrHash = $a->get($fileName);
    $a->set($fileName, $attrHash);
    $numDirEntries = $a->count();
    $a->read($dirPath, $attribFileName);
    $a->write($dirPath, $attribFileName);

    $textType = BackupPC::XS::Attrib::fileType2Text(BPC_FTYPE_....);

=head2 BackupPC::XS::AttribCache

Maintain a cache of directories, with full share/path semantics.

    $ac = BackupPC::XS::AttribCache::new($host, $backupNum, $shareNameUM, $compress);

    $attrHash = $ac->get($fileName, $allocateIfMissing, $dontReadInode);
    $ac->set($fileName, $attrHash, $dontOverwriteInode);
    $ac->delete($fileName);

    $attrHash = $ac->getInode($inode, $allocateIfMissing);
    $ac->setInode($inode, $attrHash);
    $ac->deleteInode($inode);

    $ac->getAll($path, $dontReadInode);

    $ac->flush($all, $path);
    $ac->getFullMangledPath($path);

=head2 BackupPC::XS::DirOps

    $zeroMeansOk = BackupPC::XS::DirOps::path_create($path);
    $errorCnt = BackupPC::XS::DirOps::path_remove($path, $compress);

    $errorCnt = BackupPC::XS::DirOps::refCountAll($path, $compress);

    $lockFd = BackupPC::XS::DirOps::lockRangeFile($lockFile, $offset, $len, $block);
    BackupPC::XS::DirOps::unlockRangeFile($lockFd);

=head2 BackupPC::XS::Lib

    BackupPC::XS::Lib::ConfInit($topDir, $hardLinkMax, $poolV3Enabled, $logLevel)

    $messageArrayRef = BackupPC::XS::Lib::logMsgGet();
    $errorCnt = BackupPC::XS::Lib::logErrorCntGet;
    BackupPC::XS::Lib::logLevelSet($level);

=head1 EXPORTS

If you specify :all (see SYNOPSIS), then the BPC_FTYPE_ values are exported.

=head1 SEE ALSO

BackupPC, backuppc.sourceforge.net.

rsync-bpc.

=head1 AUTHOR

Craig Barratt, E<lt>cbarratt@users.sourceforge.net<gt>

=head1 COPYRIGHT AND LICENSE

BackupPC code is copyright (C) 2013 Craig Barratt
<cbarratt@users.sourceforge.net>.

bpc_hashTable.c is based on code from rsync.  Rsync is Copyright
(C) 1996-2001 by Andrew Tridgell, 1996 by Paul Mackerras, 2001-2002
by Martin Pool, and 2003-2009 by Wayne Davison, and others.

The md5 library is from the rsync codebase, and is Copyright (C) 2001-2003
Christophe Devine.  See the code for the license.

The zlib library is from the rsync codebase, and is Copyright (C) 1995-2005
Jean-loup Gailly and Mark Adler.  See the code for the license.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, visit the http://fsf.org website.

=cut
