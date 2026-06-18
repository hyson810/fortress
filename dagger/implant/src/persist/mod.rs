pub mod windows;
pub mod linux;

#[derive(Debug)]
pub enum PersistMethod {
    RegistryRun,
    ScheduledTask,
    WindowsService,
    WmiEventSubscription,
    CronReboot,
    SystemdUser,
    XdgAutostart,
}

#[derive(Debug)]
pub struct PersistResult {
    pub success: bool,
    pub method: PersistMethod,
    pub detail: String,
}
