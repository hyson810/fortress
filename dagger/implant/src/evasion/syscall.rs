#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallMethod {
    Direct,
    Indirect,
    Unhook,
    PerunsFart,
}

#[cfg(windows)]
pub unsafe fn nt_allocate_virtual_memory(
    method: SyscallMethod,
    process_handle: *mut std::ffi::c_void,
    base_address: *mut *mut std::ffi::c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> i32 {
    // SYSCALL NUMBER: NtAllocateVirtualMemory
    let ssn = resolve_syscall_number("NtAllocateVirtualMemory").unwrap_or(0x18);
    let mut status: i32;
    std::arch::asm!(
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "syscall",
        ssn = in(reg) ssn,
        in("rcx") process_handle,
        in("rdx") base_address,
        in("r8") zero_bits,
        in("r9") region_size,
        lateout("rax") status,
    );
    status
}

#[cfg(not(windows))]
pub unsafe fn nt_allocate_virtual_memory(
    _method: SyscallMethod,
    _process_handle: *mut std::ffi::c_void,
    _base_address: *mut *mut std::ffi::c_void,
    _zero_bits: usize,
    _region_size: *mut usize,
    _allocation_type: u32,
    _protect: u32,
) -> i32 {
    -1
}

#[cfg(windows)]
unsafe fn resolve_syscall_number(name: &str) -> Option<u32> {
    use std::ffi::CString;
    let cname = CString::new(name).ok()?;
    let ntdll = winapi::um::libloaderapi::GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
    if ntdll.is_null() { return None; }
    let addr = winapi::um::libloaderapi::GetProcAddress(ntdll, cname.as_ptr());
    if addr.is_null() { return None; }
    let stub = addr as *const u8;
    if *stub == 0x4C && *stub.add(1) == 0x8B && *stub.add(2) == 0xD1 {
        Some(*stub.add(4) as u32)
    } else {
        None
    }
}

#[cfg(not(windows))]
unsafe fn resolve_syscall_number(_name: &str) -> Option<u32> { None }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_method_variants() {
        let methods = [
            SyscallMethod::Direct,
            SyscallMethod::Indirect,
            SyscallMethod::Unhook,
            SyscallMethod::PerunsFart,
        ];
        assert_eq!(methods.len(), 4);
    }

    #[test]
    #[cfg(not(windows))]
    fn test_non_windows_returns_error() {
        let mut base: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut size: usize = 0;
        let status = unsafe {
            nt_allocate_virtual_memory(
                SyscallMethod::Direct,
                std::ptr::null_mut(),
                &mut base, 0, &mut size,
                0x3000, 0x40,
            )
        };
        assert_eq!(status, -1);
    }
}
