pub mod windows;
pub mod linux;

#[derive(Debug)]
pub enum LateralMethod { PSExec, WmiExec, SmbExec, WinRm, SshKey, CfgMgmt }

#[derive(Debug)]
pub struct LateralResult {
    pub success: bool,
    pub target: String,
    pub method: LateralMethod,
    pub output: String,
}
