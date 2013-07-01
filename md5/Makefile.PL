use ExtUtils::MakeMaker;
$Verbose = 1;
WriteMakefile(
    NAME   => 'BackupPC::XS::md5',
    SKIP   => [qw(all static_lib static dynamic_lib dynamic)],
    clean  => {'FILES' => 'libmd5$(LIB_EXT)'},
);

sub MY::top_targets {
       '
all :: static

pure_all :: static

static ::       libmd5$(LIB_EXT)

libmd5$(LIB_EXT): $(O_FILES)
	$(AR) cr libmd5$(LIB_EXT) $(O_FILES)
	$(RANLIB) libmd5$(LIB_EXT)

';
}
