#[cfg(feature = "std")]
fn main() {
	substrate_wasm_builder::WasmBuilder::init_with_defaults()
		.enable_metadata_hash("ERT", 12)
		.build()
}

#[cfg(not(feature = "std"))]
fn main() {}
