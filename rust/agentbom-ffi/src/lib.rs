use agentbom_core::{Edge, Node};
use agentbom_engine::Engine;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn agentbom_engine_new() -> *mut Engine { Box::into_raw(Box::new(Engine::new())) }

#[no_mangle]
pub unsafe extern "C" fn agentbom_engine_free(engine: *mut Engine) {
    if !engine.is_null() { drop(Box::from_raw(engine)); }
}

#[no_mangle]
pub unsafe extern "C" fn agentbom_engine_add_node(engine: *mut Engine, id: *const c_char, kind: *const c_char, name: *const c_char) -> i32 {
    let Some(engine) = engine.as_mut() else { return 1 };
    let (Some(id), Some(kind), Some(name)) = (read(id), read(kind), read(name)) else { return 2 };
    engine.add_node(Node { id, kind, name, properties: serde_json::json!({}) });
    0
}

#[no_mangle]
pub unsafe extern "C" fn agentbom_engine_add_node_json(engine: *mut Engine, id: *const c_char, kind: *const c_char, name: *const c_char, properties_json: *const c_char) -> i32 {
    let Some(engine) = engine.as_mut() else { return 1 };
    let (Some(id), Some(kind), Some(name), Some(properties_json)) = (read(id), read(kind), read(name), read(properties_json)) else { return 2 };
    let Ok(properties) = serde_json::from_str(&properties_json) else { return 4 };
    engine.add_node(Node { id, kind, name, properties });
    0
}

#[no_mangle]
pub unsafe extern "C" fn agentbom_engine_add_edge(engine: *mut Engine, source: *const c_char, kind: *const c_char, target: *const c_char) -> i32 {
    let Some(engine) = engine.as_mut() else { return 1 };
    let (Some(source), Some(kind), Some(target)) = (read(source), read(kind), read(target)) else { return 2 };
    match engine.add_edge(Edge { source, kind, target, properties: serde_json::json!({}) }) { Ok(()) => 0, Err(_) => 3 }
}

#[no_mangle]
pub unsafe extern "C" fn agentbom_engine_add_edge_json(engine: *mut Engine, source: *const c_char, kind: *const c_char, target: *const c_char, properties_json: *const c_char) -> i32 {
    let Some(engine) = engine.as_mut() else { return 1 };
    let (Some(source), Some(kind), Some(target), Some(properties_json)) = (read(source), read(kind), read(target), read(properties_json)) else { return 2 };
    let Ok(properties) = serde_json::from_str(&properties_json) else { return 4 };
    match engine.add_edge(Edge { source, kind, target, properties }) { Ok(()) => 0, Err(_) => 3 }
}

#[no_mangle]
pub unsafe extern "C" fn agentbom_engine_snapshot_hash(engine: *const Engine) -> *mut c_char {
    let Some(engine) = engine.as_ref() else { return std::ptr::null_mut() };
    into_c_string(engine.snapshot_hash())
}

#[no_mangle]
pub unsafe extern "C" fn agentbom_engine_policy_findings(engine: *const Engine, max_depth: usize) -> *mut c_char {
    let Some(engine) = engine.as_ref() else { return std::ptr::null_mut() };
    serde_json::to_string(&engine.policy_findings(max_depth)).ok().and_then(into_c_string_opt).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn agentbom_engine_attack_paths(engine: *const Engine, max_depth: usize) -> *mut c_char {
    let Some(engine) = engine.as_ref() else { return std::ptr::null_mut() };
    serde_json::to_string(&engine.attack_paths(max_depth)).ok().and_then(into_c_string_opt).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn agentbom_engine_blast_radius(engine: *const Engine, max_depth: usize) -> *mut c_char {
    let Some(engine) = engine.as_ref() else { return std::ptr::null_mut() };
    serde_json::to_string(&engine.blast_radius(max_depth)).ok().and_then(into_c_string_opt).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn agentbom_engine_export_json(engine: *const Engine) -> *mut c_char {
    let Some(engine) = engine.as_ref() else { return std::ptr::null_mut() };
    engine.export_json().ok().and_then(into_c_string_opt).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn agentbom_string_free(value: *mut c_char) {
    if !value.is_null() { drop(CString::from_raw(value)); }
}

unsafe fn read(value: *const c_char) -> Option<String> {
    if value.is_null() { return None; }
    CStr::from_ptr(value).to_str().ok().map(ToOwned::to_owned)
}

fn into_c_string_opt(value: String) -> Option<*mut c_char> { CString::new(value).ok().map(CString::into_raw) }
fn into_c_string(value: String) -> *mut c_char { into_c_string_opt(value).unwrap_or(std::ptr::null_mut()) }
