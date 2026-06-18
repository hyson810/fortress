use super::{InjectMethod, InjectResult};

/// Module Stomping:
/// 1. Load a legitimate signed DLL (e.g. kernel32.dll)
/// 2. Overwrite its .text section with shellcode
/// 3. Call entry — shellcode runs under signed DLL guise
#[cfg(windows)]
pub fn stomp(pid: u32, legitimate_dll: &str, shellcode: &[u8]) -> Result<InjectResult, Box<dyn std::error::Error>> {
    Ok(InjectResult {
        success: false, pid: Some(pid), method: InjectMethod::ModuleStomp,
        detail: format!("Module stomping: load {legitimate_dll} -> overwrite .text -> call shellcode"),
    })
}

#[cfg(not(windows))]
pub fn stomp(_pid: u32, _dll: &str, _sc: &[u8]) -> Result<InjectResult, Box<dyn std::error::Error>> {
    Ok(InjectResult { success: false, pid: None, method: InjectMethod::ModuleStomp, detail: "Windows-only".into() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stomp_returns_result() {
        let result = stomp(1234, "kernel32.dll", &[0x90u8; 64]).unwrap();
        assert_eq!(result.method, InjectMethod::ModuleStomp);
    }
}
