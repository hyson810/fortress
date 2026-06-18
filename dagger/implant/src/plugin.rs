use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("plugin not found: {0}")]
    NotFound(String),
    #[error("load failed: {0}")]
    LoadFailed(String),
    #[error("plugin already loaded: {0}")]
    AlreadyLoaded(String),
}

pub struct Plugin {
    pub name: String,
    pub version: String,
    pub entry_point: String,
}

pub struct PluginManager {
    loaded: HashMap<String, Plugin>,
}

impl PluginManager {
    pub fn new() -> Self { Self { loaded: HashMap::new() } }

    pub fn load(&mut self, name: &str, _data: &[u8]) -> Result<(), PluginError> {
        if self.loaded.contains_key(name) {
            return Err(PluginError::AlreadyLoaded(name.into()));
        }
        self.loaded.insert(name.into(), Plugin { name: name.into(), version: "0.1.0".into(), entry_point: format!("{name}_main") });
        Ok(())
    }

    pub fn call(&self, name: &str, _func: &str, _args: &[u8]) -> Result<Vec<u8>, PluginError> {
        self.loaded.get(name).map(|_| b"plugin result".to_vec()).ok_or_else(|| PluginError::NotFound(name.into()))
    }

    pub fn unload(&mut self, name: &str) -> Result<(), PluginError> {
        self.loaded.remove(name).map(|_| ()).ok_or_else(|| PluginError::NotFound(name.into()))
    }

    pub fn list(&self) -> Vec<String> { self.loaded.keys().cloned().collect() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_load_unload() {
        let mut pm = PluginManager::new();
        pm.load("keylogger", b"fake").unwrap();
        assert!(pm.list().contains(&"keylogger".to_string()));
        pm.unload("keylogger").unwrap();
        assert!(pm.list().is_empty());
    }
}
