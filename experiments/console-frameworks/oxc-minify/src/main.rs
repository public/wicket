// Minifies each ES module given on the command line in place, as a build.rs would: parse, compress,
// mangle local names (exports and imports keep theirs), print minified.
use oxc_allocator::Allocator;
use oxc_codegen::{Codegen, CodegenOptions};
use oxc_minifier::{CompressOptions, MangleOptions, Minifier, MinifierOptions};
use oxc_parser::Parser;
use oxc_span::SourceType;

fn main() {
    for path in std::env::args().skip(1) {
        let src = std::fs::read_to_string(&path).unwrap();
        let alloc = Allocator::default();
        let ret = Parser::new(&alloc, &src, SourceType::mjs()).parse();
        assert!(ret.diagnostics.is_empty(), "{path}: {:?}", ret.diagnostics);
        let mut program = ret.program;
        let opts = MinifierOptions { mangle: Some(MangleOptions::default()), mangle_properties: None, compress: Some(CompressOptions::default()) };
        let min = Minifier::new(opts).minify(&alloc, &mut program);
        let code = Codegen::new().with_options(CodegenOptions::minify()).with_scoping(min.scoping).build(&program).code;
        std::fs::write(&path, code).unwrap();
        eprintln!("{path}: {} -> {} bytes", src.len(), std::fs::metadata(&path).unwrap().len());
    }
}
