fn main() {
    let mut build = cc::Build::new();
    build
        .files([
            "csrc/blocksort.c",
            "csrc/huffman.c",
            "csrc/crctable.c",
            "csrc/randtable.c",
            "csrc/compress.c",
            "csrc/decompress.c",
            "csrc/bzlib.c",
            "csrc/zcrc32.c",
        ])
        .include("csrc")
        .define("BZ_NO_STDIO", None)
        .opt_level(3)
        .warnings(false);

    #[cfg(feature = "bz-error-handler")]
    build.file("csrc/bz_error.c");

    build.compile("rsio_native");
}
