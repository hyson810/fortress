pub mod early_bird;
pub mod stomp;
pub mod hollow;
pub mod reflective;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectMethod {
    EarlyBirdApc,
    ModuleStomp,
    ProcessHollow,
    ReflectiveDll,
}

#[derive(Debug)]
pub struct InjectResult {
    pub success: bool,
    pub pid: Option<u32>,
    pub method: InjectMethod,
    pub detail: String,
}
