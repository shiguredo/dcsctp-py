//! dcsctp の Python バインディング。
//!
//! `maturin develop --generate-stubs` / `maturin generate-stubs` で
//! `python/dcsctp/_core.pyi` を自動生成する。そのためエントリポイントは
//! 関数形式ではなく declarative module（inline `mod`）で宣言する。

use std::sync::Once;
use std::time::Duration;

use dcsctp::api::handover::{HandoverReadiness, HandoverSocketState, SocketHandoverState};
use dcsctp::api::{
    DcSctpSocket as DcSctpSocketTrait, ErrorKind, HandoverError, Message, Metrics, Options, PpId,
    SctpImplementation, SendError, SendOptions, SocketEvent, SocketState, SocketTime, StreamId,
};
use pyo3::exceptions::PyRuntimeError;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Rust の log クレート出力を Python logging へ橋渡しする初期化を一度だけ行う。
///
/// `#[pymodule_init]` を使うと introspection が Incomplete 扱いになるため、
/// 公開 API 呼び出し側で遅延初期化する。
fn ensure_logging() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        pyo3_log::init();
    });
}

#[pyclass(name = "SocketState", eq, eq_int, skip_from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PySocketState {
    Closed,
    Connecting,
    Connected,
    ShuttingDown,
}

impl From<SocketState> for PySocketState {
    fn from(state: SocketState) -> Self {
        match state {
            SocketState::Closed => PySocketState::Closed,
            SocketState::Connecting => PySocketState::Connecting,
            SocketState::Connected => PySocketState::Connected,
            SocketState::ShuttingDown => PySocketState::ShuttingDown,
        }
    }
}

#[pyclass(name = "ErrorKind", eq, eq_int, skip_from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PyErrorKind {
    NoError,
    TooManyRetries,
    NotConnected,
    ParseFailed,
    WrongSequence,
    PeerReported,
    ProtocolViolation,
    ResourceExhaustion,
    UnsupportedOperation,
}

impl From<ErrorKind> for PyErrorKind {
    fn from(kind: ErrorKind) -> Self {
        match kind {
            ErrorKind::NoError => PyErrorKind::NoError,
            ErrorKind::TooManyRetries => PyErrorKind::TooManyRetries,
            ErrorKind::NotConnected => PyErrorKind::NotConnected,
            ErrorKind::ParseFailed => PyErrorKind::ParseFailed,
            ErrorKind::WrongSequence => PyErrorKind::WrongSequence,
            ErrorKind::PeerReported => PyErrorKind::PeerReported,
            ErrorKind::ProtocolViolation => PyErrorKind::ProtocolViolation,
            ErrorKind::ResourceExhaustion => PyErrorKind::ResourceExhaustion,
            ErrorKind::UnsupportedOperation => PyErrorKind::UnsupportedOperation,
        }
    }
}

#[pyclass(name = "Message", from_py_object)]
#[derive(Clone)]
pub(crate) struct PyMessage {
    #[pyo3(get)]
    stream_id: u16,
    #[pyo3(get)]
    ppid: u32,
    #[pyo3(get)]
    payload: Vec<u8>,
}

#[pymethods]
impl PyMessage {
    #[new]
    fn new(stream_id: u16, ppid: u32, payload: Vec<u8>) -> Self {
        PyMessage {
            stream_id,
            ppid,
            payload,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Message(stream_id={}, ppid={}, payload_len={})",
            self.stream_id,
            self.ppid,
            self.payload.len()
        )
    }
}

impl From<PyMessage> for Message {
    fn from(msg: PyMessage) -> Self {
        Message::new(StreamId(msg.stream_id), PpId(msg.ppid), msg.payload)
    }
}

impl From<Message> for PyMessage {
    fn from(msg: Message) -> Self {
        PyMessage {
            stream_id: msg.stream_id.0,
            ppid: msg.ppid.0,
            payload: msg.payload,
        }
    }
}

#[pyclass(name = "SendOptions", from_py_object)]
#[derive(Clone)]
pub(crate) struct PySendOptions {
    #[pyo3(get, set)]
    unordered: bool,
    #[pyo3(get, set)]
    lifetime_ms: Option<u64>,
    #[pyo3(get, set)]
    max_retransmissions: Option<u16>,
    #[pyo3(get, set)]
    lifecycle_id: Option<u64>,
}

#[pymethods]
impl PySendOptions {
    #[new]
    #[pyo3(signature = (unordered=false, lifetime_ms=None, max_retransmissions=None, lifecycle_id=None))]
    fn new(
        unordered: bool,
        lifetime_ms: Option<u64>,
        max_retransmissions: Option<u16>,
        lifecycle_id: Option<u64>,
    ) -> Self {
        PySendOptions {
            unordered,
            lifetime_ms,
            max_retransmissions,
            lifecycle_id,
        }
    }
}

impl From<&PySendOptions> for SendOptions {
    fn from(opts: &PySendOptions) -> Self {
        SendOptions {
            unordered: opts.unordered,
            lifetime: opts.lifetime_ms.map(Duration::from_millis),
            max_retransmissions: opts.max_retransmissions,
            lifecycle_id: opts.lifecycle_id.and_then(dcsctp::api::LifecycleId::new),
        }
    }
}

#[pyclass(name = "SocketEvent")]
pub(crate) struct PySocketEvent {
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    data: Option<Vec<u8>>,
    #[pyo3(get)]
    error_kind: Option<PyErrorKind>,
    #[pyo3(get)]
    message: Option<String>,
    #[pyo3(get)]
    stream_id: Option<u16>,
    #[pyo3(get)]
    stream_ids: Option<Vec<u16>>,
    #[pyo3(get)]
    lifecycle_id: Option<u64>,
}

impl From<SocketEvent> for PySocketEvent {
    fn from(event: SocketEvent) -> Self {
        match event {
            SocketEvent::SendPacket(data) => PySocketEvent {
                kind: "send_packet".to_string(),
                data: Some(data),
                error_kind: None,
                message: None,
                stream_id: None,
                stream_ids: None,
                lifecycle_id: None,
            },
            SocketEvent::OnConnected() => PySocketEvent {
                kind: "connected".to_string(),
                data: None,
                error_kind: None,
                message: None,
                stream_id: None,
                stream_ids: None,
                lifecycle_id: None,
            },
            SocketEvent::OnClosed() => PySocketEvent {
                kind: "closed".to_string(),
                data: None,
                error_kind: None,
                message: None,
                stream_id: None,
                stream_ids: None,
                lifecycle_id: None,
            },
            SocketEvent::OnConnectionRestarted() => PySocketEvent {
                kind: "connection_restarted".to_string(),
                data: None,
                error_kind: None,
                message: None,
                stream_id: None,
                stream_ids: None,
                lifecycle_id: None,
            },
            SocketEvent::OnAborted(error_kind, msg) => PySocketEvent {
                kind: "aborted".to_string(),
                data: None,
                error_kind: Some(error_kind.into()),
                message: Some(msg),
                stream_id: None,
                stream_ids: None,
                lifecycle_id: None,
            },
            SocketEvent::OnError(error_kind, msg) => PySocketEvent {
                kind: "error".to_string(),
                data: None,
                error_kind: Some(error_kind.into()),
                message: Some(msg),
                stream_id: None,
                stream_ids: None,
                lifecycle_id: None,
            },
            SocketEvent::OnBufferedAmountLow(stream_id) => PySocketEvent {
                kind: "buffered_amount_low".to_string(),
                data: None,
                error_kind: None,
                message: None,
                stream_id: Some(stream_id.0),
                stream_ids: None,
                lifecycle_id: None,
            },
            SocketEvent::OnTotalBufferedAmountLow() => PySocketEvent {
                kind: "total_buffered_amount_low".to_string(),
                data: None,
                error_kind: None,
                message: None,
                stream_id: None,
                stream_ids: None,
                lifecycle_id: None,
            },
            SocketEvent::OnStreamsResetFailed(stream_ids) => PySocketEvent {
                kind: "streams_reset_failed".to_string(),
                data: None,
                error_kind: None,
                message: None,
                stream_id: None,
                stream_ids: Some(stream_ids.iter().map(|s| s.0).collect()),
                lifecycle_id: None,
            },
            SocketEvent::OnStreamsResetPerformed(stream_ids) => PySocketEvent {
                kind: "streams_reset_performed".to_string(),
                data: None,
                error_kind: None,
                message: None,
                stream_id: None,
                stream_ids: Some(stream_ids.iter().map(|s| s.0).collect()),
                lifecycle_id: None,
            },
            SocketEvent::OnIncomingStreamReset(stream_ids) => PySocketEvent {
                kind: "incoming_stream_reset".to_string(),
                data: None,
                error_kind: None,
                message: None,
                stream_id: None,
                stream_ids: Some(stream_ids.iter().map(|s| s.0).collect()),
                lifecycle_id: None,
            },
            SocketEvent::OnLifecycleMessageFullySent(id) => PySocketEvent {
                kind: "lifecycle_message_fully_sent".to_string(),
                data: None,
                error_kind: None,
                message: None,
                stream_id: None,
                stream_ids: None,
                lifecycle_id: Some(id.value()),
            },
            SocketEvent::OnLifecycleMessageMaybeExpired(id) => PySocketEvent {
                kind: "lifecycle_message_maybe_expired".to_string(),
                data: None,
                error_kind: None,
                message: None,
                stream_id: None,
                stream_ids: None,
                lifecycle_id: Some(id.value()),
            },
            SocketEvent::OnLifecycleMessageExpired(id) => PySocketEvent {
                kind: "lifecycle_message_expired".to_string(),
                data: None,
                error_kind: None,
                message: None,
                stream_id: None,
                stream_ids: None,
                lifecycle_id: Some(id.value()),
            },
            SocketEvent::OnLifecycleMessageDelivered(id) => PySocketEvent {
                kind: "lifecycle_message_delivered".to_string(),
                data: None,
                error_kind: None,
                message: None,
                stream_id: None,
                stream_ids: None,
                lifecycle_id: Some(id.value()),
            },
            SocketEvent::OnLifecycleEnd(id) => PySocketEvent {
                kind: "lifecycle_end".to_string(),
                data: None,
                error_kind: None,
                message: None,
                stream_id: None,
                stream_ids: None,
                lifecycle_id: Some(id.value()),
            },
        }
    }
}

#[pyclass(name = "SctpImplementation", eq, eq_int, skip_from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PySctpImplementation {
    Unknown,
    DcsctpRs,
    DcsctpCc,
    UsrSctp,
    Other,
}

impl From<SctpImplementation> for PySctpImplementation {
    fn from(implementation: SctpImplementation) -> Self {
        match implementation {
            SctpImplementation::Unknown => PySctpImplementation::Unknown,
            SctpImplementation::DcsctpRs => PySctpImplementation::DcsctpRs,
            SctpImplementation::DcsctpCc => PySctpImplementation::DcsctpCc,
            SctpImplementation::UsrSctp => PySctpImplementation::UsrSctp,
            SctpImplementation::Other => PySctpImplementation::Other,
        }
    }
}

#[pyclass(name = "Metrics")]
pub(crate) struct PyMetrics {
    #[pyo3(get)]
    tx_packets_count: usize,
    #[pyo3(get)]
    tx_messages_count: usize,
    #[pyo3(get)]
    rtx_packets_count: usize,
    #[pyo3(get)]
    rtx_bytes_count: u64,
    #[pyo3(get)]
    cwnd_bytes: usize,
    #[pyo3(get)]
    srtt_ms: u64,
    #[pyo3(get)]
    unack_data_count: usize,
    #[pyo3(get)]
    rx_packets_count: usize,
    #[pyo3(get)]
    rx_messages_count: usize,
    #[pyo3(get)]
    peer_rwnd_bytes: u32,
    // ピアの SCTP 実装。接続確立前や判定できない場合は Unknown
    #[pyo3(get)]
    peer_implementation: PySctpImplementation,
    #[pyo3(get)]
    uses_message_interleaving: bool,
    #[pyo3(get)]
    uses_zero_checksum: bool,
    #[pyo3(get)]
    negotiated_maximum_incoming_streams: u16,
    #[pyo3(get)]
    negotiated_maximum_outgoing_streams: u16,
}

impl From<Metrics> for PyMetrics {
    fn from(m: Metrics) -> Self {
        PyMetrics {
            tx_packets_count: m.tx_packets_count,
            tx_messages_count: m.tx_messages_count,
            rtx_packets_count: m.rtx_packets_count,
            rtx_bytes_count: m.rtx_bytes_count,
            cwnd_bytes: m.cwnd_bytes,
            srtt_ms: m.srtt.as_millis() as u64,
            unack_data_count: m.unack_data_count,
            rx_packets_count: m.rx_packets_count,
            rx_messages_count: m.rx_messages_count,
            peer_rwnd_bytes: m.peer_rwnd_bytes,
            peer_implementation: m.peer_implementation.into(),
            uses_message_interleaving: m.uses_message_interleaving,
            uses_zero_checksum: m.uses_zero_checksum,
            negotiated_maximum_incoming_streams: m.negotiated_maximum_incoming_streams,
            negotiated_maximum_outgoing_streams: m.negotiated_maximum_outgoing_streams,
        }
    }
}

#[pyclass(name = "Options", from_py_object)]
#[derive(Clone)]
pub(crate) struct PyOptions {
    #[pyo3(get, set)]
    local_port: u16,
    #[pyo3(get, set)]
    remote_port: u16,
    #[pyo3(get, set)]
    announced_maximum_incoming_streams: u16,
    #[pyo3(get, set)]
    announced_maximum_outgoing_streams: u16,
    #[pyo3(get, set)]
    mtu: usize,
    #[pyo3(get, set)]
    max_message_size: usize,
    #[pyo3(get, set)]
    default_stream_priority: u16,
    #[pyo3(get, set)]
    max_receiver_window_buffer_size: usize,
    #[pyo3(get, set)]
    max_send_buffer_size: usize,
    #[pyo3(get, set)]
    per_stream_send_queue_limit: usize,
    #[pyo3(get, set)]
    total_buffered_amount_low_threshold: usize,
    #[pyo3(get, set)]
    default_stream_buffered_amount_low_threshold: usize,
    #[pyo3(get, set)]
    rtt_max_ms: u64,
    #[pyo3(get, set)]
    rto_initial_ms: u64,
    #[pyo3(get, set)]
    rto_max_ms: u64,
    #[pyo3(get, set)]
    rto_min_ms: u64,
    #[pyo3(get, set)]
    t1_init_timeout_ms: u64,
    #[pyo3(get, set)]
    t1_cookie_timeout_ms: u64,
    #[pyo3(get, set)]
    t2_shutdown_timeout_ms: u64,
    #[pyo3(get, set)]
    max_timer_backoff_duration_ms: Option<u64>,
    #[pyo3(get, set)]
    heartbeat_interval_ms: u64,
    #[pyo3(get, set)]
    delayed_ack_max_timeout_ms: u64,
    #[pyo3(get, set)]
    min_rtt_variance_ms: u64,
    #[pyo3(get, set)]
    cwnd_mtus_initial: usize,
    #[pyo3(get, set)]
    cwnd_mtus_min: usize,
    #[pyo3(get, set)]
    avoid_fragmentation_cwnd_mtus: usize,
    #[pyo3(get, set)]
    immediate_sack_under_cwnd_mtus: usize,
    #[pyo3(get, set)]
    max_burst: i32,
    #[pyo3(get, set)]
    max_retransmissions: Option<u32>,
    #[pyo3(get, set)]
    max_init_retransmits: Option<u32>,
    #[pyo3(get, set)]
    enable_partial_reliability: bool,
    #[pyo3(get, set)]
    enable_message_interleaving: bool,
    #[pyo3(get, set)]
    heartbeat_interval_include_rtt: bool,
    #[pyo3(get, set)]
    disable_checksum_verification: bool,
    // RFC 9653 の zero checksum で使う代替誤り検出方式 (0 = なし、1 = DTLS)
    #[pyo3(get, set)]
    zero_checksum_alternate_error_detection_method: u32,
}

#[pymethods]
impl PyOptions {
    #[new]
    #[pyo3(signature = (**kwargs))]
    fn new(kwargs: Option<&Bound<'_, pyo3::types::PyDict>>) -> PyResult<Self> {
        let defaults = Options::default();
        let mut opts = PyOptions::from_rust(&defaults);

        if let Some(kw) = kwargs {
            for (key, value) in kw.iter() {
                let key: String = key.extract()?;
                match key.as_str() {
                    "local_port" => opts.local_port = value.extract()?,
                    "remote_port" => opts.remote_port = value.extract()?,
                    "announced_maximum_incoming_streams" => {
                        opts.announced_maximum_incoming_streams = value.extract()?
                    }
                    "announced_maximum_outgoing_streams" => {
                        opts.announced_maximum_outgoing_streams = value.extract()?
                    }
                    "mtu" => opts.mtu = value.extract()?,
                    "max_message_size" => opts.max_message_size = value.extract()?,
                    "default_stream_priority" => opts.default_stream_priority = value.extract()?,
                    "max_receiver_window_buffer_size" => {
                        opts.max_receiver_window_buffer_size = value.extract()?
                    }
                    "max_send_buffer_size" => opts.max_send_buffer_size = value.extract()?,
                    "per_stream_send_queue_limit" => {
                        opts.per_stream_send_queue_limit = value.extract()?
                    }
                    "total_buffered_amount_low_threshold" => {
                        opts.total_buffered_amount_low_threshold = value.extract()?
                    }
                    "default_stream_buffered_amount_low_threshold" => {
                        opts.default_stream_buffered_amount_low_threshold = value.extract()?
                    }
                    "rtt_max_ms" => opts.rtt_max_ms = value.extract()?,
                    "rto_initial_ms" => opts.rto_initial_ms = value.extract()?,
                    "rto_max_ms" => opts.rto_max_ms = value.extract()?,
                    "rto_min_ms" => opts.rto_min_ms = value.extract()?,
                    "t1_init_timeout_ms" => opts.t1_init_timeout_ms = value.extract()?,
                    "t1_cookie_timeout_ms" => opts.t1_cookie_timeout_ms = value.extract()?,
                    "t2_shutdown_timeout_ms" => opts.t2_shutdown_timeout_ms = value.extract()?,
                    "max_timer_backoff_duration_ms" => {
                        opts.max_timer_backoff_duration_ms = value.extract()?
                    }
                    "heartbeat_interval_ms" => opts.heartbeat_interval_ms = value.extract()?,
                    "delayed_ack_max_timeout_ms" => {
                        opts.delayed_ack_max_timeout_ms = value.extract()?
                    }
                    "min_rtt_variance_ms" => opts.min_rtt_variance_ms = value.extract()?,
                    "cwnd_mtus_initial" => opts.cwnd_mtus_initial = value.extract()?,
                    "cwnd_mtus_min" => opts.cwnd_mtus_min = value.extract()?,
                    "avoid_fragmentation_cwnd_mtus" => {
                        opts.avoid_fragmentation_cwnd_mtus = value.extract()?
                    }
                    "immediate_sack_under_cwnd_mtus" => {
                        opts.immediate_sack_under_cwnd_mtus = value.extract()?
                    }
                    "max_burst" => opts.max_burst = value.extract()?,
                    "max_retransmissions" => opts.max_retransmissions = value.extract()?,
                    "max_init_retransmits" => opts.max_init_retransmits = value.extract()?,
                    "enable_partial_reliability" => {
                        opts.enable_partial_reliability = value.extract()?
                    }
                    "enable_message_interleaving" => {
                        opts.enable_message_interleaving = value.extract()?
                    }
                    "heartbeat_interval_include_rtt" => {
                        opts.heartbeat_interval_include_rtt = value.extract()?
                    }
                    "disable_checksum_verification" => {
                        opts.disable_checksum_verification = value.extract()?
                    }
                    "zero_checksum_alternate_error_detection_method" => {
                        opts.zero_checksum_alternate_error_detection_method = value.extract()?
                    }
                    _ => return Err(PyValueError::new_err(format!("unknown option: {key}"))),
                }
            }
        }

        Ok(opts)
    }
}

impl PyOptions {
    fn from_rust(opts: &Options) -> Self {
        PyOptions {
            local_port: opts.local_port,
            remote_port: opts.remote_port,
            announced_maximum_incoming_streams: opts.announced_maximum_incoming_streams,
            announced_maximum_outgoing_streams: opts.announced_maximum_outgoing_streams,
            mtu: opts.mtu,
            max_message_size: opts.max_message_size,
            default_stream_priority: opts.default_stream_priority,
            max_receiver_window_buffer_size: opts.max_receiver_window_buffer_size,
            max_send_buffer_size: opts.max_send_buffer_size,
            per_stream_send_queue_limit: opts.per_stream_send_queue_limit,
            total_buffered_amount_low_threshold: opts.total_buffered_amount_low_threshold,
            default_stream_buffered_amount_low_threshold: opts
                .default_stream_buffered_amount_low_threshold,
            rtt_max_ms: opts.rtt_max.as_millis() as u64,
            rto_initial_ms: opts.rto_initial.as_millis() as u64,
            rto_max_ms: opts.rto_max.as_millis() as u64,
            rto_min_ms: opts.rto_min.as_millis() as u64,
            t1_init_timeout_ms: opts.t1_init_timeout.as_millis() as u64,
            t1_cookie_timeout_ms: opts.t1_cookie_timeout.as_millis() as u64,
            t2_shutdown_timeout_ms: opts.t2_shutdown_timeout.as_millis() as u64,
            max_timer_backoff_duration_ms: opts
                .max_timer_backoff_duration
                .map(|d| d.as_millis() as u64),
            heartbeat_interval_ms: opts.heartbeat_interval.as_millis() as u64,
            delayed_ack_max_timeout_ms: opts.delayed_ack_max_timeout.as_millis() as u64,
            min_rtt_variance_ms: opts.min_rtt_variance.as_millis() as u64,
            cwnd_mtus_initial: opts.cwnd_mtus_initial,
            cwnd_mtus_min: opts.cwnd_mtus_min,
            avoid_fragmentation_cwnd_mtus: opts.avoid_fragmentation_cwnd_mtus,
            immediate_sack_under_cwnd_mtus: opts.immediate_sack_under_cwnd_mtus,
            max_burst: opts.max_burst,
            max_retransmissions: opts.max_retransmissions,
            max_init_retransmits: opts.max_init_retransmits,
            enable_partial_reliability: opts.enable_partial_reliability,
            enable_message_interleaving: opts.enable_message_interleaving,
            heartbeat_interval_include_rtt: opts.heartbeat_interval_include_rtt,
            disable_checksum_verification: opts.disable_checksum_verification,
            zero_checksum_alternate_error_detection_method: opts
                .zero_checksum_alternate_error_detection_method
                .0,
        }
    }

    fn to_rust(&self) -> Options {
        Options {
            local_port: self.local_port,
            remote_port: self.remote_port,
            announced_maximum_incoming_streams: self.announced_maximum_incoming_streams,
            announced_maximum_outgoing_streams: self.announced_maximum_outgoing_streams,
            mtu: self.mtu,
            max_message_size: self.max_message_size,
            default_stream_priority: self.default_stream_priority,
            max_receiver_window_buffer_size: self.max_receiver_window_buffer_size,
            max_send_buffer_size: self.max_send_buffer_size,
            per_stream_send_queue_limit: self.per_stream_send_queue_limit,
            total_buffered_amount_low_threshold: self.total_buffered_amount_low_threshold,
            default_stream_buffered_amount_low_threshold: self
                .default_stream_buffered_amount_low_threshold,
            rtt_max: Duration::from_millis(self.rtt_max_ms),
            rto_initial: Duration::from_millis(self.rto_initial_ms),
            rto_max: Duration::from_millis(self.rto_max_ms),
            rto_min: Duration::from_millis(self.rto_min_ms),
            t1_init_timeout: Duration::from_millis(self.t1_init_timeout_ms),
            t1_cookie_timeout: Duration::from_millis(self.t1_cookie_timeout_ms),
            t2_shutdown_timeout: Duration::from_millis(self.t2_shutdown_timeout_ms),
            max_timer_backoff_duration: self
                .max_timer_backoff_duration_ms
                .map(Duration::from_millis),
            heartbeat_interval: Duration::from_millis(self.heartbeat_interval_ms),
            delayed_ack_max_timeout: Duration::from_millis(self.delayed_ack_max_timeout_ms),
            min_rtt_variance: Duration::from_millis(self.min_rtt_variance_ms),
            cwnd_mtus_initial: self.cwnd_mtus_initial,
            cwnd_mtus_min: self.cwnd_mtus_min,
            avoid_fragmentation_cwnd_mtus: self.avoid_fragmentation_cwnd_mtus,
            immediate_sack_under_cwnd_mtus: self.immediate_sack_under_cwnd_mtus,
            max_burst: self.max_burst,
            max_retransmissions: self.max_retransmissions,
            max_init_retransmits: self.max_init_retransmits,
            enable_partial_reliability: self.enable_partial_reliability,
            enable_message_interleaving: self.enable_message_interleaving,
            heartbeat_interval_include_rtt: self.heartbeat_interval_include_rtt,
            disable_checksum_verification: self.disable_checksum_verification,
            zero_checksum_alternate_error_detection_method:
                dcsctp::api::ZeroChecksumAlternateErrorDetectionMethod(
                    self.zero_checksum_alternate_error_detection_method,
                ),
        }
    }
}

// dcsctp::api::DcSctpSocket は Send/Sync を実装していないため unsendable とする
#[pyclass(unsendable)]
pub(crate) struct Socket {
    inner: Box<dyn DcSctpSocketTrait>,
}

/// ハンドオーバーの可否と、その理由をビットマスクで保持する。
#[pyclass(name = "HandoverReadiness", eq, skip_from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PyHandoverReadiness {
    #[pyo3(get)]
    bits: u32,
}

#[pymethods]
impl PyHandoverReadiness {
    /// 即時にハンドオーバーできるかどうかを返す。
    fn is_ready(&self) -> bool {
        HandoverReadiness(self.bits).is_ready()
    }

    /// ハンドオーバーできない理由を文字列の一覧で返す。
    fn reasons(&self) -> Vec<String> {
        HandoverReadiness(self.bits)
            .to_string()
            .split(',')
            .filter(|reason| !reason.is_empty())
            .map(String::from)
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "HandoverReadiness(bits=0x{:x}, reasons={:?})",
            self.bits,
            self.reasons()
        )
    }
}

/// ハンドオーバー用のソケット状態スナップショット (dcsctp では不透明な値)。
#[pyclass(name = "HandoverState", frozen)]
pub(crate) struct PyHandoverState {
    inner: SocketHandoverState,
}

#[pymethods]
impl PyHandoverState {
    /// 接続済みの状態を復元するスナップショットかどうかを返す。
    #[getter]
    fn is_connected(&self) -> bool {
        matches!(self.inner.socket_state, HandoverSocketState::Connected)
    }

    #[getter]
    fn my_verification_tag(&self) -> u32 {
        self.inner.my_verification_tag
    }

    #[getter]
    fn peer_verification_tag(&self) -> u32 {
        self.inner.peer_verification_tag
    }

    #[getter]
    fn my_initial_tsn(&self) -> u32 {
        self.inner.my_initial_tsn
    }

    #[getter]
    fn peer_initial_tsn(&self) -> u32 {
        self.inner.peer_initial_tsn
    }

    #[getter]
    fn next_tsn(&self) -> u32 {
        self.inner.tx.next_tsn
    }

    #[getter]
    fn cwnd(&self) -> u32 {
        self.inner.tx.cwnd
    }

    #[getter]
    fn rwnd(&self) -> u32 {
        // dcsctp 0.1.15 では a_rwnd という名前 (0.1.16 以降で rwnd に改名される)
        self.inner.tx.a_rwnd
    }

    #[getter]
    fn ssthresh(&self) -> u32 {
        self.inner.tx.ssthresh
    }

    #[getter]
    fn uses_partial_reliability(&self) -> bool {
        self.inner.capabilities.partial_reliability
    }

    #[getter]
    fn uses_message_interleaving(&self) -> bool {
        self.inner.capabilities.message_interleaving
    }

    #[getter]
    fn supports_reconfig(&self) -> bool {
        self.inner.capabilities.reconfig
    }

    #[getter]
    fn uses_zero_checksum(&self) -> bool {
        self.inner.capabilities.zero_checksum
    }

    #[getter]
    fn negotiated_maximum_incoming_streams(&self) -> u16 {
        self.inner.capabilities.negotiated_maximum_incoming_streams
    }

    #[getter]
    fn negotiated_maximum_outgoing_streams(&self) -> u16 {
        self.inner.capabilities.negotiated_maximum_outgoing_streams
    }

    fn __repr__(&self) -> String {
        format!(
            "HandoverState(is_connected={}, my_verification_tag=0x{:08x}, peer_verification_tag=0x{:08x})",
            self.is_connected(),
            self.inner.my_verification_tag,
            self.inner.peer_verification_tag,
        )
    }
}

#[pymethods]
impl Socket {
    #[new]
    #[pyo3(signature = (name, options=None))]
    fn new(name: &str, options: Option<PyOptions>) -> Self {
        ensure_logging();
        let opts = options.map(|o| o.to_rust()).unwrap_or_default();
        Socket {
            inner: dcsctp::new_socket(name, &opts),
        }
    }

    fn poll_event(&mut self) -> Option<PySocketEvent> {
        self.inner.poll_event().map(|e| e.into())
    }

    fn get_next_message(&mut self) -> Option<PyMessage> {
        self.inner.get_next_message().map(|m| m.into())
    }

    fn handle_input(&mut self, packet: &[u8]) {
        self.inner.handle_input(packet);
    }

    fn advance_time(&mut self, millis: u64) {
        self.inner
            .advance_time(SocketTime::zero() + Duration::from_millis(millis));
    }

    fn poll_timeout(&self) -> Option<u64> {
        let timeout = self.inner.poll_timeout();
        if timeout == SocketTime::infinite_future() {
            None
        } else {
            Some((timeout - SocketTime::zero()).as_millis() as u64)
        }
    }

    fn connect(&mut self) {
        self.inner.connect();
    }

    fn shutdown(&mut self) {
        self.inner.shutdown();
    }

    fn close(&mut self) {
        self.inner.close();
    }

    fn state(&self) -> PySocketState {
        self.inner.state().into()
    }

    fn messages_ready_count(&self) -> usize {
        self.inner.messages_ready_count()
    }

    fn set_max_message_size(&mut self, max_message_size: usize) {
        self.inner.set_max_message_size(max_message_size);
    }

    fn set_stream_priority(&mut self, stream_id: u16, priority: u16) {
        self.inner
            .set_stream_priority(StreamId(stream_id), priority);
    }

    fn get_stream_priority(&self, stream_id: u16) -> u16 {
        self.inner.get_stream_priority(StreamId(stream_id))
    }

    #[pyo3(signature = (message, send_options=None))]
    fn send(&mut self, message: PyMessage, send_options: Option<PySendOptions>) -> PyResult<()> {
        let opts = send_options
            .as_ref()
            .map(SendOptions::from)
            .unwrap_or_default();
        self.inner.send(message.into(), &opts).map_err(|e| match e {
            SendError::EmptyPayload => PyValueError::new_err(e.to_string()),
            SendError::MessageTooLarge { .. } => PyValueError::new_err(e.to_string()),
            SendError::ResourceExhaustion => PyRuntimeError::new_err(e.to_string()),
            SendError::ShuttingDown => PyRuntimeError::new_err(e.to_string()),
        })
    }

    fn reset_streams(&mut self, outgoing_streams: Vec<u16>) -> PyResult<()> {
        let streams: Vec<StreamId> = outgoing_streams.into_iter().map(StreamId).collect();
        self.inner
            .reset_streams(&streams)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    fn buffered_amount(&self, stream_id: u16) -> usize {
        self.inner.buffered_amount(StreamId(stream_id))
    }

    fn buffered_amount_low_threshold(&self, stream_id: u16) -> usize {
        self.inner
            .buffered_amount_low_threshold(StreamId(stream_id))
    }

    fn set_buffered_amount_low_threshold(&mut self, stream_id: u16, bytes: usize) {
        self.inner
            .set_buffered_amount_low_threshold(StreamId(stream_id), bytes);
    }

    fn get_metrics(&self) -> Option<PyMetrics> {
        self.inner.get_metrics().map(|m| m.into())
    }

    fn options(&self) -> PyOptions {
        PyOptions::from_rust(&self.inner.options())
    }

    fn get_handover_readiness(&self) -> PyHandoverReadiness {
        PyHandoverReadiness {
            bits: self.inner.get_handover_readiness().0,
        }
    }

    fn get_handover_state_and_close(&mut self) -> PyResult<PyHandoverState> {
        self.inner
            .get_handover_state_and_close()
            .map(|state| PyHandoverState { inner: state })
            .map_err(|error| {
                let message = error.to_string();
                PyRuntimeError::new_err(match error {
                    HandoverError::NotReady(readiness) => format!("{message} ({readiness})"),
                })
            })
    }

    fn restore_from_state(&mut self, state: &PyHandoverState) -> PyResult<()> {
        self.inner
            .restore_from_state(&state.inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }
}

/// dcsctp クレートのバージョン文字列を返す。
#[pyfunction]
pub(crate) fn version() -> &'static str {
    ensure_logging();
    dcsctp::version()
}

/// Python から `import dcsctp._core` される拡張モジュール。
///
/// declarative module 形式にしないと pyo3-introspection による .pyi 生成ができない。
#[pymodule(gil_used = false, name = "_core")]
mod _core {
    #[pymodule_export]
    use crate::{
        version, PyErrorKind, PyHandoverReadiness, PyHandoverState, PyMessage, PyMetrics,
        PyOptions, PySctpImplementation, PySendOptions, PySocketEvent, PySocketState, Socket,
    };
}
