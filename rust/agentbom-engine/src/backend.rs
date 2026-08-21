use crate::Engine;

pub trait GraphBackend {
    type Error;

    fn load(&self, payload: &str) -> Result<Engine, Self::Error>;
    fn save(&self, engine: &Engine) -> Result<String, Self::Error>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct JsonBackend;

impl GraphBackend for JsonBackend {
    type Error = String;

    fn load(&self, payload: &str) -> Result<Engine, Self::Error> {
        Engine::import_json(payload)
    }

    fn save(&self, engine: &Engine) -> Result<String, Self::Error> {
        engine.export_json()
    }
}
