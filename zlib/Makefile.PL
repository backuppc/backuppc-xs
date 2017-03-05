use ExtUtils::MakeMaker;

WriteMakefile(
    NAME   => 'BackupPC::XS::zlib',
    SKIP   => [qw(all static_lib static dynamic_lib dynamic)],
    clean  => {'FILES' => 'libzlib$(LIB_EXT)'},
);

sub MY::top_targets {
       '
all :: static

pure_all :: static

static ::       libzlib$(LIB_EXT)

dynamic ::

libzlib$(LIB_EXT): $(O_FILES)
	$(AR) cr libzlib$(LIB_EXT) $(O_FILES)
	$(RANLIB) libzlib$(LIB_EXT)

';
}
