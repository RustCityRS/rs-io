fn main() {
    cc::Build::new()
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
        .warnings(false)
        .compile("rsio_native");
}
