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

/// This process's physical footprint — what Activity Monitor shows as
/// "Memory" and what iOS limits a network extension by (dirty and
/// compressed pages; RSS also counts clean, shareable code pages). `None`
/// off Apple platforms.
pub fn footprint_bytes() -> Option<u64> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let mut info = std::mem::MaybeUninit::<libc::rusage_info_v2>::zeroed();
        // SAFETY: the buffer is a `rusage_info_v2`, matching the flavor.
        let rc = unsafe {
            libc::proc_pid_rusage(
                std::process::id() as libc::c_int,
                libc::RUSAGE_INFO_V2,
                info.as_mut_ptr().cast(),
            )
        };
        if rc == 0 {
            // SAFETY: filled in by the successful call.
            return Some(unsafe { info.assume_init() }.ri_phys_footprint);
        }
    }
    // Android: the proportional set size (shared libraries split among the
    // processes using them), the figure the system's own app settings show;
    // RSS counts every shared library page in full.
    #[cfg(target_os = "android")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/smaps_rollup") {
            return pss_kib(&s).map(|k| k * 1024);
        }
    }
    None
}

/// `Pss:` of a `smaps_rollup`, in KiB.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
fn pss_kib(rollup: &str) -> Option<u64> {
    rollup
        .lines()
        .find_map(|l| l.strip_prefix("Pss:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
}

#[cfg(test)]
mod pss_tests {
    #[test]
    fn reads_pss_from_a_rollup() {
        let s = "5578c000-7ffd mem\nRss:              180168 kB\nPss:              158464 kB\nPss_Dirty:         83628 kB\n";
        assert_eq!(super::pss_kib(s), Some(158_464));
        assert_eq!(super::pss_kib("Rss: 1 kB"), None);
    }
}

/// Global allocator for Apple platforms (PaoPao): large blocks are mapped
/// straight from the kernel and unmapped on free, small ones go to the
/// system allocator.
///
/// The system allocator keeps freed large blocks in its cache as dirty
/// pages, and iOS limits a network extension by those (its 50 MB counts
/// the physical footprint, not the live heap). Start-up builds rule data
/// through large temporaries: measured on macOS, the cache held ~24 MB of
/// a 39 MB footprint whose live heap was 15 MB. Unmapping on free gives
/// what `MallocLargeCache=0` gives, which an extension cannot set.
pub struct PagedLarge;

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod paged {
    use std::alloc::{GlobalAlloc, Layout, System};

    /// From here up, a block is its own mapping (the system allocator's
    /// own large threshold is about this).
    const LARGE: usize = 64 * 1024;
    /// Mappings are page aligned; larger alignments go to the system.
    const MAX_ALIGN: usize = 4096;

    fn mapped(layout: Layout) -> bool {
        layout.size() >= LARGE && layout.align() <= MAX_ALIGN
    }

    unsafe fn map(size: usize) -> *mut u8 {
        // SAFETY: an anonymous private mapping; no file, no fixed address.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            std::ptr::null_mut()
        } else {
            p.cast()
        }
    }

    unsafe impl GlobalAlloc for super::PagedLarge {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if mapped(layout) {
                unsafe { map(layout.size()) }
            } else {
                unsafe { System.alloc(layout) }
            }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            if mapped(layout) {
                // Fresh anonymous pages are zero.
                unsafe { map(layout.size()) }
            } else {
                unsafe { System.alloc_zeroed(layout) }
            }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            if mapped(layout) {
                // SAFETY: `ptr` came from `map` with this size.
                unsafe { libc::munmap(ptr.cast(), layout.size()) };
            } else {
                unsafe { System.dealloc(ptr, layout) }
            }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            // SAFETY: the caller guarantees a valid layout for `new_size`.
            let new = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
            if !mapped(layout) && !mapped(new) {
                return unsafe { System.realloc(ptr, layout, new_size) };
            }
            let p = unsafe { self.alloc(new) };
            if !p.is_null() {
                unsafe {
                    std::ptr::copy_nonoverlapping(ptr, p, layout.size().min(new_size));
                    self.dealloc(ptr, layout);
                }
            }
            p
        }
    }

    #[cfg(test)]
    mod tests {
        use super::super::PagedLarge;
        use std::alloc::{GlobalAlloc, Layout};

        #[test]
        fn footprint_is_known() {
            assert!(crate::memory::footprint_bytes().is_some_and(|b| b > 1 << 20));
        }

        #[test]
        fn large_and_small_round_trip() {
            let a = PagedLarge;
            for (size, grow) in [(100, 200), (100, 200_000), (70_000, 300_000), (300_000, 50)] {
                let l = Layout::from_size_align(size, 8).unwrap();
                unsafe {
                    let p = a.alloc_zeroed(l);
                    assert!(!p.is_null());
                    assert!((0..size).all(|i| *p.add(i) == 0));
                    for i in 0..size {
                        *p.add(i) = (i % 251) as u8;
                    }
                    let q = a.realloc(p, l, grow);
                    assert!(!q.is_null());
                    assert!((0..size.min(grow)).all(|i| *q.add(i) == (i % 251) as u8));
                    a.dealloc(q, Layout::from_size_align(grow, 8).unwrap());
                }
            }
        }
    }
}
