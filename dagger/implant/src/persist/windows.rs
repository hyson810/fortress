use super::{PersistMethod, PersistResult};

pub fn registry_run(exe_path: &str) -> PersistResult {
    PersistResult { success: false, method: PersistMethod::RegistryRun, detail: format!("HKCU\\...\\Run: {exe_path}") }
}
pub fn scheduled_task(exe_path: &str, task_name: &str) -> PersistResult {
    PersistResult { success: false, method: PersistMethod::ScheduledTask, detail: format!("schtasks /create /tn {task_name} /tr {exe_path}") }
}
pub fn windows_service(exe_path: &str, svc_name: &str) -> PersistResult {
    PersistResult { success: false, method: PersistMethod::WindowsService, detail: format!("sc create {svc_name} binPath= {exe_path}") }
}
pub fn wmi_subscription(exe_path: &str) -> PersistResult {
    PersistResult { success: false, method: PersistMethod::WmiEventSubscription, detail: format!("WMI __EventFilter -> {exe_path}") }
}
