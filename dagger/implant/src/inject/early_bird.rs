use super::{InjectMethod, InjectResult};

/// Early Bird APC Injection:
/// 1. CreateProcess(CREATE_SUSPENDED) on a legitimate process
/// 2. Allocate RWX memory via NtAllocateVirtualMemory
/// 3. Write shellcode via NtWriteVirtualMemory
/// 4. Queue APC via NtQueueApcThread
/// 5. ResumeThread — APC fires before any process code runs
#[cfg(windows)]
pub fn inject(target_exe: &str, shellcode: &[u8]) -> Result<InjectResult, Box<dyn std::error::Error>> {
    Ok(InjectResult {
        success: false,
        pid: None,
        method: InjectMethod::EarlyBirdApc,
        detail: "Early Bird APC: CreateProcess(CREATE_SUSPENDED) -> NtAllocateVirtualMemory -> NtWriteVirtualMemory -> NtQueueApcThread -> ResumeThread".into(),
    })
}

#[cfg(not(windows))]
pub fn inject(_target_exe: &str, _shellcode: &[u8]) -> Result<InjectResult, Box<dyn std::error::Error>> {
    Ok(InjectResult {
        success: false, pid: None, method: InjectMethod::EarlyBirdApc,
        detail: "Early Bird APC is Windows-only".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_early_bird_returns_result() {
        let result = inject("svchost.exe", &[0x90u8; 64]).unwrap();
        assert_eq!(result.method, InjectMethod::EarlyBirdApc);
    }
}
