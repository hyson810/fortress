use super::{LateralMethod, LateralResult};

pub fn psexec(target_ip: &str, _user: &str, _pass: &str, command: &str) -> LateralResult {
    LateralResult { success: false, target: target_ip.into(), method: LateralMethod::PSExec, output: format!("PSExec to {target_ip}: {command}") }
}
pub fn wmi_exec(target_ip: &str, _user: &str, _pass: &str, command: &str) -> LateralResult {
    LateralResult { success: false, target: target_ip.into(), method: LateralMethod::WmiExec, output: format!("Win32_Process.Create on {target_ip}: {command}") }
}
pub fn smb_exec(target_ip: &str, _user: &str, _pass: &str, command: &str) -> LateralResult {
    LateralResult { success: false, target: target_ip.into(), method: LateralMethod::SmbExec, output: format!("SMB -> {target_ip}: {command}") }
}
