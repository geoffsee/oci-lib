// SPDX-License-Identifier: Apache-2.0

//! Stub engine for platforms that are neither Linux nor a macOS VM build.

use std::path::PathBuf;

use crate::engine::{
    Auth, Engine, EngineImage, EngineState, EngineStats, ExecOutput, FsInfo, InputSource,
    OutputSink,
};
use crate::error::{Error, ErrorCode, Result};

#[allow(dead_code)] // unused when `other` is compiled only for tests
pub(crate) fn startup() -> Result<()> {
    Err(unsupported())
}

pub(crate) fn unsupported() -> Error {
    Error::new(
        ErrorCode::Unsupported,
        "oci-cri engine is available on Linux only",
        "",
    )
}

/// Engine that reports every operation as unsupported.
#[allow(dead_code)]
pub struct UnsupportedEngine;

impl Engine for UnsupportedEngine {
    fn pull_image(&self, _image: &str, _auth: Option<&Auth>, _insecure: bool) -> Result<String> {
        Err(unsupported())
    }
    fn list_images(&self, _filter: &str) -> Result<Vec<EngineImage>> {
        Err(unsupported())
    }
    fn remove_image(&self, _image: &str) -> Result<()> {
        Err(unsupported())
    }
    fn image_fs_info(&self) -> Result<Vec<FsInfo>> {
        Err(unsupported())
    }
    fn prepare_rootfs(&self, _id: &str, _image: &str) -> Result<PathBuf> {
        Err(unsupported())
    }
    fn release_rootfs(&self, _id: &str) -> Result<()> {
        Err(unsupported())
    }
    fn create_container(&self, _id: &str, _spec_json: &str) -> Result<()> {
        Err(unsupported())
    }
    fn start_container(&self, _id: &str, _on_output: OutputSink) -> Result<()> {
        Err(unsupported())
    }
    fn wait_container(&self, _id: &str) -> Result<i32> {
        Err(unsupported())
    }
    fn signal_container(&self, _id: &str, _signal: i32) -> Result<()> {
        Err(unsupported())
    }
    fn remove_container(&self, _id: &str) -> Result<()> {
        Err(unsupported())
    }
    fn container_state(&self, _id: &str) -> Result<EngineState> {
        Err(unsupported())
    }
    fn exec_sync(&self, _id: &str, _cmd: &[String], _timeout_secs: i64) -> Result<ExecOutput> {
        Err(unsupported())
    }
    fn exec_stream(
        &self,
        _id: &str,
        _cmd: &[String],
        _tty: bool,
        _next_input: InputSource,
        _on_output: OutputSink,
    ) -> Result<i32> {
        Err(unsupported())
    }
    fn write_stdin(&self, _id: &str, _data: &[u8]) -> Result<()> {
        Err(unsupported())
    }
    fn resize_tty(&self, _id: &str, _width: u16, _height: u16) -> Result<()> {
        Err(unsupported())
    }
    fn container_stats(&self, _id: &str) -> Result<EngineStats> {
        Err(unsupported())
    }
    fn update_resources(&self, _id: &str, _resources_json: &str) -> Result<()> {
        Err(unsupported())
    }
    fn checkpoint(&self, _id: &str, _image: &str, _parent: &str) -> Result<()> {
        Err(unsupported())
    }
    fn diagnose(&self) -> Result<String> {
        Err(unsupported())
    }
}
