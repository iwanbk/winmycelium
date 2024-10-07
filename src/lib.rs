use std::convert::TryFrom;
use std::io;

use tracing::{error, info};

use metrics::Metrics;
use mycelium::endpoint::Endpoint;
use mycelium::{crypto, metrics, Config, Node};
use once_cell::sync::Lazy;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, timeout, Duration};

const CHANNEL_MSG_OK: &str = "ok";
const CHANNEL_TIMEOUT: u64 = 2;

fn setup_logging() {
    tracing_subscriber::fmt().init();
}

static INIT_LOG: Lazy<()> = Lazy::new(|| {
    setup_logging();
});

fn setup_logging_once() {
    // Accessing the Lazy value will ensure setup_logging is called exactly once
    let _ = &*INIT_LOG;
}

// Declare the channel globally so we can use it on the start & stop mycelium functions
type CommandChannelType = (Mutex<mpsc::Sender<Cmd>>, Mutex<mpsc::Receiver<Cmd>>);
static COMMAND_CHANNEL: Lazy<CommandChannelType> = Lazy::new(|| {
    let (tx_cmd, rx_cmd) = mpsc::channel::<Cmd>(1);
    (Mutex::new(tx_cmd), Mutex::new(rx_cmd))
});

type ResponseChannelType = (
    Mutex<mpsc::Sender<Response>>,
    Mutex<mpsc::Receiver<Response>>,
);
static RESPONSE_CHANNEL: Lazy<ResponseChannelType> = Lazy::new(|| {
    let (tx_resp, rx_resp) = mpsc::channel::<Response>(1);
    (Mutex::new(tx_resp), Mutex::new(rx_resp))
});

/// Default name of tun interface
#[cfg(not(target_os = "macos"))]
const TUN_NAME: &str = "mycelium";
/// Default name of tun interface
#[cfg(target_os = "macos")]
const TUN_NAME: &str = "utun0";

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn ff_generate_secret_key(out_ptr: *mut *mut u8, out_len: *mut usize) {
    let secret_key = generate_secret_key();
    let len = secret_key.len();
    let ptr = secret_key.as_ptr();

    // Transfer ownership to the caller
    std::mem::forget(secret_key);

    unsafe {
        *out_ptr = ptr as *mut u8;
        *out_len = len;
    }
}

#[no_mangle]
pub extern "C" fn free_secret_key(ptr: *mut u8, len: usize) {
    unsafe {
        if ptr.is_null() {
            return;
        }
        Vec::from_raw_parts(ptr, len, len);
    }
}
#[no_mangle]
pub extern "C" fn ff_address_from_secret_key(data: *const u8, len: usize) -> *mut c_char {
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    let vec = slice.to_vec();
    let address = address_from_secret_key(vec);
    let c_string = CString::new(address).unwrap();
    c_string.into_raw()
}

#[no_mangle]
pub extern "C" fn free_c_string(s: *mut c_char) {
    unsafe {
        if s.is_null() {
            return;
        }
        CString::from_raw(s)
    };
}

#[no_mangle]
pub extern "C" fn ff_start_mycelium(
    peers_ptr: *const *const c_char,
    peers_len: usize,
    priv_key_ptr: *const u8,
    priv_key_len: usize,
) {
    let peers: Vec<String> = unsafe {
        (0..peers_len)
            .map(|i| {
                let c_str = CStr::from_ptr(*peers_ptr.add(i));
                c_str.to_string_lossy().into_owned()
            })
            .collect()
    };

    let priv_key: Vec<u8> =
        unsafe { std::slice::from_raw_parts(priv_key_ptr, priv_key_len).to_vec() };

    start_mycelium(peers, priv_key);
}

#[no_mangle]
pub extern "C" fn ff_stop_mycelium() -> bool {
    let result = stop_mycelium();
    error!("winmyc result: {}", result);
    result == CHANNEL_MSG_OK
}

#[no_mangle]
#[tokio::main]
#[allow(unused_variables)] // because tun_fd is only used in android and ios
pub async fn start_mycelium(peers: Vec<String>, priv_key: Vec<u8>) {
    setup_logging_once();

    info!("starting mycelium");
    let endpoints: Vec<Endpoint> = peers
        .into_iter()
        .filter_map(|peer| peer.parse().ok())
        .collect();

    let secret_key = build_secret_key(priv_key).await.unwrap();

    let config = Config {
        node_key: secret_key,
        peers: endpoints,
        no_tun: false,
        tcp_listen_port: DEFAULT_TCP_LISTEN_PORT,
        quic_listen_port: None,
        peer_discovery_port: None, // disable multicast discovery
        tun_name: TUN_NAME.to_string(),

        metrics: NoMetrics,
        private_network_config: None,
        firewall_mark: None,
        update_workers: 1,
    };
    let _node = match Node::new(config).await {
        Ok(node) => {
            info!("node successfully created");
            node
        }
        Err(err) => {
            error!("failed to create mycelium node: {err}");
            return;
        }
    };

    let mut rx = COMMAND_CHANNEL.1.lock().await;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c()  => {
                info!("Received SIGINT, stopping mycelium node");
                break;
            }
           cmd = rx.recv() => {
                match cmd.unwrap().cmd {
                    CmdType::Stop => {
                        info!("Received stop command, stopping mycelium node");
                        send_response(vec![CHANNEL_MSG_OK.to_string()]).await;
                        break;
                    }
                    CmdType::Status => {
                        let mut vec: Vec<String> = Vec::new();
                        for info in _node.peer_info() {
                            vec.push(info.endpoint.proto().to_string() + ","+ info.endpoint.address().to_string().as_str()+","+ &info.connection_state.to_string());
                        }
                        send_response(vec).await;
                    }
                }
            }
        }
    }
    info!("mycelium stopped");
}

struct Cmd {
    cmd: CmdType,
}

enum CmdType {
    Stop,
    Status,
}

struct Response {
    response: Vec<String>,
}

// stop_mycelium returns string with the status of the command
#[no_mangle]
#[tokio::main]
pub async fn stop_mycelium() -> String {
    if let Err(e) = send_command(CmdType::Stop).await {
        return e.to_string();
    }

    match recv_response().await {
        Ok(_) => CHANNEL_MSG_OK.to_string(),
        Err(e) => e.to_string(),
    }
}

use thiserror::Error;
#[derive(Error, Debug)]
pub enum NodeError {
    #[error("err_node_dead")]
    NodeDead,

    #[error("err_node_timeout")]
    NodeTimeout,
}

async fn send_command(cmd_type: CmdType) -> Result<(), NodeError> {
    let tx = COMMAND_CHANNEL.0.lock().await;
    tokio::select! {
        _ = sleep(Duration::from_secs(CHANNEL_TIMEOUT)) => {
            Err(NodeError::NodeTimeout)
        }
        result = tx.send(Cmd { cmd: cmd_type }) => {
            match result {
                Ok(_) => Ok(()),
                Err(_) => Err(NodeError::NodeDead)
            }
        }
    }
}

async fn send_response(resp: Vec<String>) {
    let tx = RESPONSE_CHANNEL.0.lock().await;

    tokio::select! {
        _ = sleep(Duration::from_secs(CHANNEL_TIMEOUT)) => {
            error!("send_response timeout");
        }
        result = tx.send(Response { response: resp }) => {
            match result {
                Ok(_) => {},
                Err(_) =>{error!("send_response failed");},
            }
        }
    }
}

async fn recv_response() -> Result<Vec<String>, NodeError> {
    let mut rx = RESPONSE_CHANNEL.1.lock().await;
    let duration = Duration::from_secs(CHANNEL_TIMEOUT);
    match timeout(duration, rx.recv()).await {
        Ok(result) => match result {
            Some(resp) => Ok(resp.response),
            None => Err(NodeError::NodeDead),
        },
        Err(_) => Err(NodeError::NodeTimeout),
    }
}

#[derive(Clone)]
pub struct NoMetrics;
impl Metrics for NoMetrics {}

/// The default port on the underlay to listen on for incoming TCP connections.
const DEFAULT_TCP_LISTEN_PORT: u16 = 9651;

fn convert_slice_to_array32(slice: &[u8]) -> Result<[u8; 32], std::array::TryFromSliceError> {
    <[u8; 32]>::try_from(slice)
}

async fn build_secret_key<T>(bin: Vec<u8>) -> Result<T, io::Error>
where
    T: From<[u8; 32]>,
{
    Ok(T::from(convert_slice_to_array32(bin.as_slice()).unwrap()))
}

/// generate secret key
/// it is used by android & ios app
#[no_mangle]
pub extern "C" fn generate_secret_key() -> Vec<u8> {
    crypto::SecretKey::new().as_bytes().into()
}

/// generate node_address from secret key
#[no_mangle]
pub fn address_from_secret_key(data: Vec<u8>) -> String {
    let data = <[u8; 32]>::try_from(data.as_slice()).unwrap();
    let secret_key = crypto::SecretKey::from(data);
    crypto::PublicKey::from(&secret_key).address().to_string()
}
