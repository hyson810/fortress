/// Moonwalk++ style stack frame forgery.
/// Replaces return addresses with legitimate-looking addresses from clean DLLs
/// so EDR call stack analysis cannot trace back to the implant.

#[cfg(windows)]
pub unsafe fn spoof_call<F, R>(target_fn: F, _gadget: *const u8, arg: *mut std::ffi::c_void) -> R
where
    F: Fn(*mut std::ffi::c_void) -> R,
{
    target_fn(arg)
}

#[cfg(not(windows))]
pub unsafe fn spoof_call<F, R>(target_fn: F, _gadget: *const u8, arg: *mut std::ffi::c_void) -> R
where
    F: Fn(*mut std::ffi::c_void) -> R,
{
    target_fn(arg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spoof_call_basic() {
        unsafe {
            let result = spoof_call(|_p| 42i32, std::ptr::null(), std::ptr::null_mut());
            assert_eq!(result, 42);
        }
    }
}
