use super::{PersistMethod, PersistResult};

pub fn cron_reboot(cmd: &str) -> PersistResult {
    PersistResult { success: false, method: PersistMethod::CronReboot, detail: format!("@reboot {cmd}") }
}
pub fn systemd_user(exec_path: &str, service_name: &str) -> PersistResult {
    let unit = format!("[Unit]\nDescription={0}\n\n[Service]\nExecStart={1}\nRestart=always\n\n[Install]\nWantedBy=default.target\n", service_name, exec_path);
    PersistResult { success: false, method: PersistMethod::SystemdUser, detail: format!("~/.config/systemd/user/{service_name}.service") }
}
pub fn xdg_autostart(exec_path: &str, name: &str) -> PersistResult {
    PersistResult { success: false, method: PersistMethod::XdgAutostart, detail: format!("~/.config/autostart/{name}.desktop -> {exec_path}") }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_cron_result() {
        let r = cron_reboot("/tmp/implant");
        assert!(!r.success);
    }
}
