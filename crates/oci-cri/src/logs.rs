// SPDX-License-Identifier: Apache-2.0

//! CRI log files.
//!
//! Format per line: `<RFC3339 timestamp> <stdout|stderr> <F|P> <message>`.
//! `F` is a complete line, `P` a partial chunk flushed before its newline
//! arrived (rotated or container exit). kubelet's `kubectl logs` parses this.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::error::{Error, ErrorCode, Result};

/// Stream identifiers used across the engine ABI.
pub const STDOUT: u8 = 1;
/// Stream identifiers used across the engine ABI.
pub const STDERR: u8 = 2;

struct WriterState {
    file: Option<File>,
    pending_stdout: Vec<u8>,
    pending_stderr: Vec<u8>,
}

/// Appends one container's output to its CRI log file. Safe to share: the
/// engine output callback and `ReopenContainerLog` may race.
pub struct CriLogWriter {
    path: PathBuf,
    state: Mutex<WriterState>,
}

impl CriLogWriter {
    /// Open (creating parent directories) a log writer for `path`.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io_err)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(io_err)?;
        Ok(Self {
            path: path.to_path_buf(),
            state: Mutex::new(WriterState {
                file: Some(file),
                pending_stdout: Vec::new(),
                pending_stderr: Vec::new(),
            }),
        })
    }

    /// The file this writer appends to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Consume one raw output chunk from the engine.
    pub fn write(&self, stream: u8, data: &[u8]) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let pending = if stream == STDERR {
            &mut state.pending_stderr
        } else {
            &mut state.pending_stdout
        };
        pending.extend_from_slice(data);
        let name = if stream == STDERR { "stderr" } else { "stdout" };
        let mut lines: Vec<String> = Vec::new();
        while let Some(at) = pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = pending.drain(..=at).collect();
            lines.push(String::from_utf8_lossy(&line[..line.len() - 1]).into_owned());
        }
        for text in &lines {
            let _ = write_line(state.file.as_mut(), name, "F", text);
        }
        // Interactive attach must deliver prompts and `echo -n` output
        // before a newline or process exit. CRI partial records preserve
        // that boundary without inventing a newline in the byte stream.
        let partial = if stream == STDERR {
            std::mem::take(&mut state.pending_stderr)
        } else {
            std::mem::take(&mut state.pending_stdout)
        };
        if !partial.is_empty() {
            let _ = write_line(
                state.file.as_mut(),
                name,
                "P",
                &String::from_utf8_lossy(&partial),
            );
        }
    }

    /// Flush any unterminated output as partial (`P`) lines.
    pub fn flush_partial(&self) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let stdout_pending = std::mem::take(&mut state.pending_stdout);
        let stderr_pending = std::mem::take(&mut state.pending_stderr);
        for (pending, name) in [(stdout_pending, "stdout"), (stderr_pending, "stderr")] {
            if !pending.is_empty() {
                let text = String::from_utf8_lossy(&pending).into_owned();
                let _ = write_line(state.file.as_mut(), name, "P", &text);
            }
        }
        if let Some(file) = state.file.as_mut() {
            let _ = file.flush();
        }
    }

    /// Close and reopen the file (log rotation): `ReopenContainerLog`.
    pub fn reopen(&self) -> Result<()> {
        self.flush_partial();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.file = None;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(io_err)?;
        state.file = Some(file);
        Ok(())
    }
}

fn write_line(file: Option<&mut File>, stream: &str, tag: &str, text: &str) -> Result<()> {
    let Some(file) = file else { return Ok(()) };
    // CRI timestamps are RFC3339 with nanosecond precision.
    writeln!(file, "{} {} {} {}", rfc3339_now(), stream, tag, text).map_err(io_err)?;
    file.flush().map_err(io_err)
}

/// Format the current time as `2006-01-02T15:04:05.000000000Z`.
pub fn rfc3339_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let nanos = now.subsec_nanos();
    let days = secs.div_euclid(86_400);
    let day_secs = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{nanos:09}Z",
        day_secs / 3600,
        (day_secs % 3600) / 60,
        day_secs % 60,
    )
}

/// Days-from-epoch → (year, month, day), Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn io_err(err: std::io::Error) -> Error {
    Error::new(ErrorCode::Internal, format!("log file: {err}"), "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_looks_like_rfc3339() {
        let text = rfc3339_now();
        assert_eq!(text.len(), 30, "{text}");
        assert!(text.ends_with('Z'));
        assert_eq!(&text[4..5], "-");
    }

    #[test]
    fn writes_full_and_partial_lines() {
        let dir = std::env::temp_dir().join(format!("rok-log-{}", crate::store::new_id()));
        let path = dir.join("c.log");
        let writer = CriLogWriter::open(&path).unwrap();
        writer.write(STDOUT, b"hello\nwor");
        writer.write(STDERR, b"oops\n");
        writer.flush_partial();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "{text}");
        assert!(lines[0].ends_with("stdout F hello"), "{}", lines[0]);
        assert!(lines[1].ends_with("stdout P wor"), "{}", lines[1]);
        assert!(lines[2].ends_with("stderr F oops"), "{}", lines[2]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn interactive_partial_output_is_visible_before_eof() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("interactive.log");
        let writer = CriLogWriter::open(&path).unwrap();
        writer.write(STDOUT, b"prompt> ");
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.ends_with(" stdout P prompt> \n"));
    }

    #[test]
    fn reopen_keeps_appending() {
        let dir = std::env::temp_dir().join(format!("rok-log-{}", crate::store::new_id()));
        let path = dir.join("c.log");
        let writer = CriLogWriter::open(&path).unwrap();
        writer.write(STDOUT, b"one\n");
        writer.reopen().unwrap();
        writer.write(STDOUT, b"two\n");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
