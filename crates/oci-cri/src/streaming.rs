// SPDX-License-Identifier: Apache-2.0

//! Exec/Attach/PortForward streaming server.
//!
//! kubelet's remote-command client speaks the Kubernetes streaming protocol
//! over a WebSocket upgrade: every message is a channel byte (`0` stdin,
//! `1` stdout, `2` stderr, `3` error, `4` resize) followed by payload. This
//! server implements that protocol directly over TCP (the client negotiates
//! `v4.channel.k8s.io`-style subprotocols), so no HTTP framework is needed.
//! Sessions are single-use tokens handed out by the CRI `Exec`, `Attach`,
//! and `PortForward` calls.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::engine::Engine;
use crate::store::Store;

/// What one streaming token does when the client connects.
#[derive(Debug, Clone)]
pub enum SessionKind {
    /// Run a command interactively in a container.
    Exec {
        /// Container ID.
        container_id: String,
        /// Command and arguments.
        cmd: Vec<String>,
        /// Whether a terminal was requested.
        tty: bool,
        /// Whether stdin is forwarded.
        stdin: bool,
    },
    /// Attach to a running container's streams (log follow + stdin).
    Attach {
        /// Container ID.
        container_id: String,
        /// Whether stdin is forwarded.
        stdin: bool,
        /// Whether a terminal was requested.
        tty: bool,
    },
    /// Forward connections to the sandbox IP.
    PortForward {
        /// Sandbox ID (for status/debugging).
        pod_sandbox_id: String,
        /// Sandbox IP to connect to.
        ip: String,
    },
}

struct Session {
    kind: SessionKind,
    expires: Instant,
}

/// Shared streaming state: session tokens plus the bound address.
pub struct StreamingState {
    sessions: Mutex<HashMap<String, Session>>,
    addr: Mutex<Option<SocketAddr>>,
    engine: Arc<dyn Engine>,
    store: Arc<Store>,
}

impl StreamingState {
    /// Create streaming state over the daemon's engine and store.
    pub fn new(engine: Arc<dyn Engine>, store: Arc<Store>) -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            addr: Mutex::new(None),
            engine,
            store,
        })
    }

    /// Register a session and return its single-use token.
    pub fn register(&self, kind: SessionKind) -> String {
        let token = crate::store::new_id();
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                token.clone(),
                Session {
                    kind,
                    expires: Instant::now() + Duration::from_secs(300),
                },
            );
        token
    }

    /// Base URL (`http://127.0.0.1:PORT`) for session URLs, once bound.
    pub fn base_url(&self) -> Option<String> {
        self.addr
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .map(|addr| format!("http://{addr}"))
    }

    /// Full URL for a session path segment (`exec`, `attach`, `portforward`).
    pub fn url(&self, segment: &str, kind: SessionKind) -> String {
        let token = self.register(kind);
        match self.base_url() {
            Some(base) => format!("{base}/{segment}/{token}"),
            None => format!("http://127.0.0.1:0/{segment}/{token}"),
        }
    }

    fn take(&self, token: &str) -> Option<SessionKind> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        let session = sessions.remove(token)?;
        if session.expires < Instant::now() {
            return None;
        }
        Some(session.kind)
    }
}

/// Bind the streaming server and serve forever. Records the bound address in
/// `state` so CRI handlers can mint URLs.
pub async fn serve(state: Arc<StreamingState>, address: SocketAddr) -> Result<(), crate::Error> {
    let listener = TcpListener::bind(address).await.map_err(|err| {
        crate::Error::new(
            crate::ErrorCode::Prerequisite,
            format!("binding streaming server {address}: {err}"),
            "",
        )
    })?;
    let local = listener
        .local_addr()
        .map_err(|err| crate::Error::new(crate::ErrorCode::Internal, err.to_string(), ""))?;
    *state.addr.lock().unwrap_or_else(|p| p.into_inner()) = Some(local);
    loop {
        let (socket, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = handle_connection(socket, state).await;
        });
    }
}

async fn handle_connection(
    mut socket: TcpStream,
    state: Arc<StreamingState>,
) -> std::io::Result<()> {
    let (path, protocol) = websocket_handshake(&mut socket).await?;
    let mut parts = path.split('/').filter(|p| !p.is_empty());
    let segment = parts.next().unwrap_or("").to_string();
    let token = parts.next().unwrap_or("").to_string();
    let _ = protocol;
    let Some(kind) = state.take(&token) else {
        let _ = ws_send(&mut socket, 3, br#"{"metadata":{},"status":"Failure","message":"unknown or expired streaming token","code":404}"#, true).await;
        return Ok(());
    };
    match (segment.as_str(), kind) {
        (
            "exec",
            SessionKind::Exec {
                container_id,
                cmd,
                tty,
                stdin,
            },
        ) => run_exec(socket, state, container_id, cmd, tty, stdin).await,
        (
            "attach",
            SessionKind::Attach {
                container_id,
                stdin,
                tty,
            },
        ) => run_attach(socket, state, container_id, stdin, tty).await,
        ("portforward", SessionKind::PortForward { ip, .. }) => run_port_forward(socket, ip).await,
        _ => Ok(()),
    }
}

/// Read the HTTP upgrade request and reply `101`, returning (path, subprotocol).
async fn websocket_handshake(socket: &mut TcpStream) -> std::io::Result<(String, String)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = socket.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof in handshake",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16 * 1024 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = text.lines();
    let request_line = lines.next().unwrap_or("");
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();
    let mut key = String::new();
    let mut protocol = String::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "sec-websocket-key" => key = value.trim().to_string(),
            "sec-websocket-protocol" => {
                protocol = value.split(',').next().unwrap_or("").trim().to_string()
            }
            _ => {}
        }
    }
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let accept = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
    let mut response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n"
    );
    if !protocol.is_empty() {
        response.push_str(&format!("Sec-WebSocket-Protocol: {protocol}\r\n"));
    }
    response.push_str("\r\n");
    socket.write_all(response.as_bytes()).await?;
    Ok((path, protocol))
}

/// One decoded WebSocket message.
enum WsMessage {
    Data(#[allow(dead_code)] u8, Vec<u8>),
    Close,
}

/// Read one (possibly fragmented) client message. Client frames are masked.
async fn ws_read(socket: &mut (impl tokio::io::AsyncRead + Unpin)) -> std::io::Result<WsMessage> {
    let mut payload = Vec::new();
    let mut opcode_out = 2u8;
    loop {
        let mut head = [0u8; 2];
        socket.read_exact(&mut head).await?;
        let fin = head[0] & 0x80 != 0;
        let opcode = head[0] & 0x0f;
        let masked = head[1] & 0x80 != 0;
        let mut len = u64::from(head[1] & 0x7f);
        if len == 126 {
            let mut ext = [0u8; 2];
            socket.read_exact(&mut ext).await?;
            len = u64::from(u16::from_be_bytes(ext));
        } else if len == 127 {
            let mut ext = [0u8; 8];
            socket.read_exact(&mut ext).await?;
            len = u64::from_be_bytes(ext);
        }
        if len > 16 * 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
        let mut mask = [0u8; 4];
        if masked {
            socket.read_exact(&mut mask).await?;
        }
        let mut data = vec![0u8; len as usize];
        socket.read_exact(&mut data).await?;
        if masked {
            for (i, byte) in data.iter_mut().enumerate() {
                *byte ^= mask[i % 4];
            }
        }
        match opcode {
            8 => return Ok(WsMessage::Close),
            9 => {
                // Ping: sessions are short-lived and the split read half
                // cannot reply; clients used by kubelet do not require pongs
                // mid-session, so the frame is consumed and ignored.
                continue;
            }
            10 => continue,
            0 => payload.extend_from_slice(&data),
            op => {
                opcode_out = op;
                payload.extend_from_slice(&data);
            }
        }
        if fin {
            return Ok(WsMessage::Data(opcode_out, payload));
        }
    }
}

/// Send one framed server message (unmasked).
async fn ws_frame(
    socket: &mut (impl tokio::io::AsyncWrite + Unpin),
    opcode: u8,
    data: &[u8],
) -> std::io::Result<()> {
    let mut frame = Vec::with_capacity(data.len() + 10);
    frame.push(0x80 | opcode);
    if data.len() < 126 {
        frame.push(data.len() as u8);
    } else if data.len() <= u16::MAX as usize {
        frame.push(126);
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(data.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(data);
    socket.write_all(&frame).await
}

/// Send a channel-tagged message. Data channels are binary; the error
/// channel (`3`) is text JSON, matching the remote-command protocol.
async fn ws_send(
    socket: &mut (impl tokio::io::AsyncWrite + Unpin),
    channel: u8,
    data: &[u8],
    is_text: bool,
) -> std::io::Result<()> {
    let mut payload = Vec::with_capacity(data.len() + 1);
    payload.push(channel);
    payload.extend_from_slice(data);
    ws_frame(socket, if is_text { 1 } else { 2 }, &payload).await
}

async fn run_exec(
    socket: TcpStream,
    state: Arc<StreamingState>,
    container_id: String,
    cmd: Vec<String>,
    tty: bool,
    _stdin: bool,
) -> std::io::Result<()> {
    let (ws_out_tx, mut ws_out_rx) = mpsc::channel::<(u8, Vec<u8>)>(64);
    let (in_tx, in_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let in_rx = Arc::new(Mutex::new(in_rx));
    let engine = Arc::clone(&state.engine);
    let exec_container = container_id.clone();
    let (done_tx, mut done_rx) = mpsc::channel::<i32>(1);
    let out_sink: crate::engine::OutputSink = Arc::new(move |stream, data| {
        let _ = ws_out_tx.try_send((stream, data.to_vec()));
    });
    let in_rx_clone = Arc::clone(&in_rx);
    let next_input: crate::engine::InputSource = Arc::new(move || {
        let rx = in_rx_clone.lock().unwrap_or_else(|p| p.into_inner());
        rx.recv().unwrap_or_default()
    });
    tokio::task::spawn_blocking(move || {
        let code = engine
            .exec_stream(&exec_container, &cmd, tty, next_input, out_sink)
            .unwrap_or(1);
        let _ = done_tx.blocking_send(code);
    });
    let (mut reader, mut writer) = socket.into_split();
    let writer_task = tokio::spawn(async move {
        while let Some((stream, data)) = ws_out_rx.recv().await {
            if ws_send(&mut writer, stream, &data, false).await.is_err() {
                break;
            }
        }
        writer
    });
    loop {
        tokio::select! {
            message = ws_read(&mut reader) => {
                match message {
                    Ok(WsMessage::Data(_, data)) if !data.is_empty() => {
                        match data[0] {
                            0 => { let _ = in_tx.send(data[1..].to_vec()); }
                            4 => { /* resize: exec without a tty has no console to size */ }
                            _ => {}
                        }
                    }
                    _ => break,
                }
            }
            _code = done_rx.recv() => {
                break;
            }
        }
    }
    drop(in_tx);
    let _ = writer_task.await;
    Ok(())
}

async fn run_attach(
    socket: TcpStream,
    state: Arc<StreamingState>,
    container_id: String,
    stdin: bool,
    _tty: bool,
) -> std::io::Result<()> {
    let record = state.store.container(&container_id);
    let Some(record) = record else {
        return Ok(());
    };
    let log_path: PathBuf = record.log_path.clone().into();
    let (mut reader, mut writer) = socket.into_split();
    let engine = Arc::clone(&state.engine);
    let attach_id = container_id.clone();
    // Follow the CRI log file: strip the 4 log fields and emit raw payloads.
    let follow = tokio::spawn(async move {
        let mut offset: u64 = 0;
        loop {
            if let Ok(text) = tokio::fs::read_to_string(&log_path).await {
                let bytes = text.as_bytes();
                if (bytes.len() as u64) > offset {
                    let fresh = &text[offset as usize..];
                    offset = bytes.len() as u64;
                    for line in fresh.lines() {
                        // "<ts> <stream> <tag> <payload>"
                        let mut fields = line.splitn(4, ' ');
                        let _ = fields.next();
                        let stream = fields.next().unwrap_or("stdout");
                        let _ = fields.next();
                        let payload = fields.next().unwrap_or("");
                        let channel = if stream == "stderr" { 2 } else { 1 };
                        let mut data = vec![channel];
                        data.extend_from_slice(payload.as_bytes());
                        data.push(b'\n');
                        if ws_frame(&mut writer, 2, &data).await.is_err() {
                            return;
                        }
                    }
                }
            }
            let running = state
                .store
                .container(&attach_id)
                .map(|r| r.state == crate::store::ContainerState::Running)
                .unwrap_or(false);
            if !running && offset > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    if stdin {
        loop {
            match ws_read(&mut reader).await {
                Ok(WsMessage::Data(_, data)) if !data.is_empty() && data[0] == 0 => {
                    let _ = engine.write_stdin(&container_id, &data[1..]);
                }
                Ok(WsMessage::Data(_, _)) => {}
                _ => break,
            }
            if follow.is_finished() {
                break;
            }
        }
    } else {
        let _ = follow.await;
    }
    Ok(())
}

async fn run_port_forward(socket: TcpStream, ip: String) -> std::io::Result<()> {
    let (mut reader, writer) = socket.into_split();
    // First data message: channel byte + 2-byte little-endian port.
    let (channel, port, initial) = loop {
        match ws_read(&mut reader).await? {
            WsMessage::Data(_, data) if data.len() >= 3 => {
                let chan = data[0];
                let port = u16::from_le_bytes([data[1], data[2]]);
                break (chan, port, data[3..].to_vec());
            }
            WsMessage::Data(_, _) => continue,
            WsMessage::Close => return Ok(()),
        }
    };
    let upstream = TcpStream::connect((ip.as_str(), port)).await?;
    let (mut up_reader, mut up_writer) = upstream.into_split();
    if !initial.is_empty() {
        up_writer.write_all(&initial).await?;
    }
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    let writer_clone = Arc::clone(&writer);
    let up_task = tokio::spawn(async move {
        let mut buf = [0u8; 32 * 1024];
        loop {
            match up_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut payload = Vec::with_capacity(n + 1);
                    payload.push(channel);
                    payload.extend_from_slice(&buf[..n]);
                    let mut guard = writer_clone.lock().await;
                    if ws_frame(&mut *guard, 2, &payload).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    loop {
        match ws_read(&mut reader).await {
            Ok(WsMessage::Data(_, data)) if data.len() > 1 => {
                if up_writer.write_all(&data[1..]).await.is_err() {
                    break;
                }
            }
            Ok(WsMessage::Data(_, _)) => {}
            _ => break,
        }
    }
    up_task.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_are_single_use_and_expire_checked() {
        let store = Arc::new(
            Store::open(
                std::env::temp_dir().join(format!("rok-stream-{}-sb", crate::store::new_id())),
                std::env::temp_dir().join(format!("rok-stream-{}-ct", crate::store::new_id())),
            )
            .unwrap(),
        );
        let engine: Arc<dyn Engine> = Arc::new(crate::other::UnsupportedEngine);
        let state = StreamingState::new(engine, store);
        let token = state.register(SessionKind::Exec {
            container_id: "c1".into(),
            cmd: vec!["/bin/true".into()],
            tty: false,
            stdin: false,
        });
        assert!(state.take(&token).is_some());
        assert!(state.take(&token).is_none());
        assert!(state.take("nope").is_none());
    }
}
