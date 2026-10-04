//! Handing freed memory back to the system (PaoPao).

/// Returns freed heap pages to the system where the allocator keeps them
/// otherwise (Apple platforms: `malloc_zone_pressure_relief`). Cheap; call
/// after building large temporary structures. No-op elsewhere.
pub fn release_free_memory() {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        unsafe extern "C" {
            fn malloc_zone_pressure_relief(zone: *mut std::ffi::c_void, goal: usize) -> usize;
        }
        // SAFETY: a null zone means every zone; goal 0 means as much as
        // possible. The call only releases pages the allocator holds free.
        unsafe {
            malloc_zone_pressure_relief(std::ptr::null_mut(), 0);
        }
    }
}
