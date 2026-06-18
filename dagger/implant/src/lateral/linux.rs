use super::{LateralMethod, LateralResult};

pub fn ssh_key_deploy(target_ip: &str, username: &str, ssh_key_path: &str) -> LateralResult {
    LateralResult { success: false, target: target_ip.into(), method: LateralMethod::SshKey, output: format!("cat {ssh_key_path} >> {username}@{target_ip}:~/.ssh/authorized_keys") }
}
