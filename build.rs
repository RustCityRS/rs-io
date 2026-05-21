fn main() {
    let mut build = cc::Build::new();
    build
        .files([
            // bzip2
            "csrc/blocksort.c",
            "csrc/huffman.c",
            "csrc/crctable.c",
            "csrc/randtable.c",
            "csrc/compress.c",
            "csrc/decompress.c",
            "csrc/bzlib.c",
            "csrc/zcrc32.c",
            // zlib 1.2.3 (deflate + inflate)
            "csrc/zlib/deflate.c",
            "csrc/zlib/trees.c",
            "csrc/zlib/inflate.c",
            "csrc/zlib/inftrees.c",
            "csrc/zlib/inffast.c",
            "csrc/zlib/zutil.c",
            "csrc/zlib/adler32.c",
            "csrc/zlib/compress.c",
        ])
        .include("csrc")
        .include("csrc/zlib")
        .define("BZ_NO_STDIO", None)
        .opt_level(3)
        .warnings(false);

    #[cfg(feature = "bz-error-handler")]
    build.file("csrc/bz_error.c");

    build.compile("rsio_native");
}
