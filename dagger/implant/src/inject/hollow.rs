use super::{InjectMethod, InjectResult};

/// Process Hollowing:
/// 1. CreateProcess(CREATE_SUSPENDED)
/// 2. NtUnmapViewOfSection to remove original image
/// 3. Allocate new memory at image base
/// 4. Write replacement PE image
/// 5. Set entry point, ResumeThread
#[cfg(windows)]
pub fn hollow(target_exe: &str, replacement_pe: &[u8]) -> Result<InjectResult, Box<dyn std::error::Error>> {
    Ok(InjectResult {
        success: false, pid: None, method: InjectMethod::ProcessHollow,
        detail: "Process hollowing: CreateProcess(CREATE_SUSPENDED) -> NtUnmapViewOfSection -> allocate -> write PE -> ResumeThread".into(),
    })
}

#[cfg(not(windows))]
pub fn hollow(_target_exe: &str, _pe: &[u8]) -> Result<InjectResult, Box<dyn std::error::Error>> {
    Ok(InjectResult { success: false, pid: None, method: InjectMethod::ProcessHollow, detail: "Windows-only".into() })
}
