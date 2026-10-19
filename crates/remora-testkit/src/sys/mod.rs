//! The only place in this crate allowed to use `unsafe` (see count_alloc.rs).

#[allow(unsafe_code)]
pub(crate) mod count_alloc;
