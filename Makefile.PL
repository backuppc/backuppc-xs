use 5.008;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
my $object = q[
            BackupPC_XS$(OBJ_EXT)
            bpc_attrib$(OBJ_EXT)
            bpc_attribCache$(OBJ_EXT)
            bpc_dirOps$(OBJ_EXT)
            bpc_fileZIO$(OBJ_EXT)
            bpc_hashtable$(OBJ_EXT)
            bpc_lib$(OBJ_EXT)
            bpc_poolWrite$(OBJ_EXT)
            bpc_refCount$(OBJ_EXT)
    ];
$object =~ s/[\n\r\s]+/ /g;

WriteMakefile(
    NAME              => 'BackupPC::XS',
    VERSION_FROM      => 'lib/BackupPC/XS.pm', # finds $VERSION
    ABSTRACT_FROM     => 'lib/BackupPC/XS.pm', # finds ABSTRACT
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    LIBS              => [''], # e.g., '-lm'
    DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I.', # e.g., '-I. -I/usr/include/other'
    OBJECT            => $object,
    MYEXTLIB          => 'zlib/libzlib$(LIB_EXT) md5/libmd5$(LIB_EXT)',
    DIR               => ['md5', 'zlib'],
    depend            => { 'BackupPC_XS.o' => 'config.h' },
    clean             => { FILES => "config.log config.status config.h" },
);

sub MY::postamble {
        return <<'EOF';

zlib/libzlib$(LIB_EXT): zlib/Makefile config.h
	cd zlib && $(MAKE) $(PASSTHRU)

md5/libmd5$(LIB_EXT): md5/Makefile config.h
	cd md5 && $(MAKE) $(PASSTHRU)

config.h: config.h.in
	./configure.sh

#
# hack to make sure config.h is built before subdirs are entered
#
config :: config.h

EOF
}
