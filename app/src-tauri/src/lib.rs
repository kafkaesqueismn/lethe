//! Tauri shell around `lethe-client`. All crypto and networking stays in Rust; the web
//! view only gets the commands below and a `lethe-event` stream.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Mutex as StdMutex;

use lethe_client::{Agent, AgentConfig, ChatItem, ContactInfo, RelayAddr, StoreLocation};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex;

type CmdResult<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// Non-secret preferences. Kept in plain JSON so they can be read before unlocking.
#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Settings {
    relay: Option<String>,
    socks_proxy: Option<String>,
    profile_name: Option<String>,
    /// Lock after this many idle minutes; 0 = never. `None` = default (5).
    auto_lock_minutes: Option<u32>,
    /// Run a relay inside the app (started at launch, so it's up even while locked).
    #[serde(default)]
    host_relay: bool,
}

#[derive(Default)]
struct AppState {
    agent: Mutex<Option<Agent>>,
    settings: StdMutex<Settings>,
    local_relay: Mutex<Option<lethe_relay::RelayHandle>>,
}

/// Fixed so the relay's address (and every contact that uses it) survives restarts.
const LOCAL_RELAY_PORT: u16 = 5223;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Invite {
    contact_id: Option<u64>,
    link: String,
    qr_svg: String,
}

/// `LETHE_DATA_DIR` lets several profiles run side by side (e.g. testing with two windows).
fn data_dir(app: &AppHandle) -> CmdResult<PathBuf> {
    let dir = match std::env::var_os("LETHE_DATA_DIR") {
        Some(d) => PathBuf::from(d),
        None => app.path().app_data_dir().map_err(err)?,
    };
    std::fs::create_dir_all(&dir).map_err(err)?;
    Ok(dir)
}

/// `LETHE_DEFAULT_RELAY` pre-fills the relay when none is configured (set by `run.sh`).
fn load_settings(app: &AppHandle) -> Settings {
    let mut s: Settings = data_dir(app)
        .ok()
        .and_then(|d| std::fs::read(d.join("settings.json")).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    if s.relay.is_none() {
        s.relay = std::env::var("LETHE_DEFAULT_RELAY").ok().filter(|r| r.parse::<RelayAddr>().is_ok());
    }
    s
}

fn save_settings(app: &AppHandle, state: &AppState, settings: Settings) -> CmdResult<()> {
    let json = serde_json::to_vec_pretty(&settings).map_err(err)?;
    std::fs::write(data_dir(app)?.join("settings.json"), json).map_err(err)?;
    *state.settings.lock().unwrap() = settings;
    Ok(())
}

/// This machine's address on the local network, so other devices on the same Wi-Fi can
/// reach a relay hosted here. `connect` on a UDP socket only picks a route; nothing is sent.
fn lan_ip() -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?; // TEST-NET-1, never actually contacted
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

/// Start the in-app relay if it isn't running. Returns its address.
async fn ensure_local_relay(app: &AppHandle, state: &AppState) -> CmdResult<String> {
    let mut slot = state.local_relay.lock().await;
    if let Some(h) = slot.as_ref() {
        return Ok(h.addr.to_string());
    }
    let host = lan_ip().map_or_else(|| "127.0.0.1".to_string(), |ip| ip.to_string());
    let handle = lethe_relay::start(lethe_relay::Config {
        listen: SocketAddr::from(([0, 0, 0, 0], LOCAL_RELAY_PORT)),
        public_host: host,
        data_dir: Some(data_dir(app)?.join("relay")),
        ..Default::default()
    })
    .await
    .map_err(|e| {
        if e.to_string().contains("in use") {
            format!("Port {LOCAL_RELAY_PORT} is already in use. Is another lethe relay running (for example ./run.sh)? Stop it, or paste that relay's address instead.")
        } else {
            format!("Couldn't start the relay: {e}")
        }
    })?;
    let addr = handle.addr.to_string();
    *slot = Some(handle);
    Ok(addr)
}

fn qr_svg(link: &str) -> CmdResult<String> {
    let code = qrcode::QrCode::new(link.as_bytes()).map_err(err)?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(256, 256)
        .quiet_zone(true)
        .build())
}

async fn agent(state: &State<'_, AppState>) -> CmdResult<Agent> {
    state.agent.lock().await.clone().ok_or_else(|| "locked".to_string())
}

fn relay(state: &State<'_, AppState>) -> CmdResult<RelayAddr> {
    let s = state.settings.lock().unwrap();
    s.relay
        .as_deref()
        .ok_or("set a relay address in settings first")?
        .parse()
        .map_err(err)
}

fn profile_name(state: &State<'_, AppState>) -> Option<String> {
    state.settings.lock().unwrap().profile_name.clone()
}

#[tauri::command]
fn profile_exists(app: AppHandle) -> CmdResult<bool> {
    Ok(data_dir(&app)?.join("lethe.db").exists())
}

#[tauri::command]
async fn unlock(app: AppHandle, state: State<'_, AppState>, passphrase: String) -> CmdResult<()> {
    let mut slot = state.agent.lock().await;
    // Never trust an already-open session: if the UI was reloaded while unlocked, a
    // shortcut here would accept any passphrase. Close it and re-verify from disk.
    if let Some(old) = slot.take() {
        old.shutdown().await;
    }
    let settings = load_settings(&app);
    let socks_proxy = match settings.socks_proxy.as_deref().filter(|s| !s.is_empty()) {
        Some(p) => Some(p.parse::<SocketAddr>().map_err(|_| "invalid proxy address")?),
        None => None,
    };
    *state.settings.lock().unwrap() = settings;
    let path = data_dir(&app)?.join("lethe.db");
    let agent = Agent::start(AgentConfig {
        store: StoreLocation::File { path, passphrase },
        socks_proxy,
        fast_kdf_for_tests: false,
    })
    .await
    .map_err(err)?;

    let mut rx = agent.subscribe();
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        use tokio::sync::broadcast::error::RecvError;
        loop {
            match rx.recv().await {
                Ok(e) => {
                    let _ = handle.emit("lethe-event", &e);
                }
                Err(RecvError::Lagged(_)) => {
                    let _ = handle.emit("lethe-resync", ());
                }
                Err(RecvError::Closed) => break,
            }
        }
    });
    *slot = Some(agent);
    Ok(())
}

#[tauri::command]
async fn lock(state: State<'_, AppState>) -> CmdResult<()> {
    if let Some(a) = state.agent.lock().await.take() {
        a.shutdown().await;
    }
    Ok(())
}

#[tauri::command]
fn get_settings(app: AppHandle, state: State<'_, AppState>) -> Settings {
    let s = load_settings(&app);
    *state.settings.lock().unwrap() = s.clone();
    s
}

#[tauri::command]
fn set_settings(app: AppHandle, state: State<'_, AppState>, settings: Settings) -> CmdResult<()> {
    let clean = |o: Option<String>| o.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let host_relay = state.settings.lock().unwrap().host_relay;
    let settings = Settings {
        relay: clean(settings.relay),
        socks_proxy: clean(settings.socks_proxy),
        profile_name: clean(settings.profile_name),
        auto_lock_minutes: settings.auto_lock_minutes.map(|m| m.min(24 * 60)),
        host_relay,
    };
    if let Some(r) = &settings.relay {
        r.parse::<RelayAddr>().map_err(err)?;
    }
    if let Some(p) = &settings.socks_proxy {
        p.parse::<SocketAddr>().map_err(|_| "proxy must look like 127.0.0.1:9050")?;
    }
    save_settings(&app, &state, settings)
}

/// Start hosting a relay in the app and use it for new conversations.
#[tauri::command]
async fn host_local_relay(app: AppHandle, state: State<'_, AppState>) -> CmdResult<Settings> {
    let addr = ensure_local_relay(&app, &state).await?;
    let mut s = load_settings(&app);
    s.relay = Some(addr);
    s.host_relay = true;
    save_settings(&app, &state, s.clone())?;
    Ok(s)
}

#[tauri::command]
async fn stop_local_relay(app: AppHandle, state: State<'_, AppState>) -> CmdResult<Settings> {
    if let Some(h) = state.local_relay.lock().await.take() {
        h.shutdown();
    }
    let mut s = load_settings(&app);
    s.host_relay = false;
    save_settings(&app, &state, s.clone())?;
    Ok(s)
}

/// Address of the relay this app is hosting, if any.
#[tauri::command]
async fn local_relay_address(state: State<'_, AppState>) -> CmdResult<Option<String>> {
    Ok(state.local_relay.lock().await.as_ref().map(|h| h.addr.to_string()))
}

#[tauri::command]
async fn contacts(state: State<'_, AppState>) -> CmdResult<Vec<ContactInfo>> {
    Ok(agent(&state).await?.contacts().await)
}

#[tauri::command]
async fn messages(state: State<'_, AppState>, contact_id: u64) -> CmdResult<Vec<ChatItem>> {
    agent(&state).await?.messages(contact_id).await.map_err(err)
}

#[tauri::command]
async fn create_invite(state: State<'_, AppState>, alias: Option<String>) -> CmdResult<Invite> {
    let relay = relay(&state)?;
    let (id, link) = agent(&state).await?.create_invite(&relay, alias, profile_name(&state)).await.map_err(err)?;
    Ok(Invite { contact_id: Some(id), qr_svg: qr_svg(&link)?, link })
}

#[tauri::command]
async fn invite_link(state: State<'_, AppState>, contact_id: u64) -> CmdResult<Invite> {
    let link = agent(&state).await?.invite_link(contact_id).await.map_err(err)?;
    Ok(Invite { contact_id: Some(contact_id), qr_svg: qr_svg(&link)?, link })
}

#[tauri::command]
async fn accept_invite(state: State<'_, AppState>, link: String, alias: Option<String>) -> CmdResult<u64> {
    let relay = relay(&state)?;
    agent(&state).await?.accept_invite(&link, &relay, alias, profile_name(&state)).await.map_err(err)
}

#[tauri::command]
async fn send_text(state: State<'_, AppState>, contact_id: u64, text: String) -> CmdResult<ChatItem> {
    agent(&state).await?.send_text(contact_id, &text).await.map_err(err)
}

#[tauri::command]
async fn rename_contact(state: State<'_, AppState>, contact_id: u64, alias: Option<String>) -> CmdResult<()> {
    agent(&state).await?.rename_contact(contact_id, alias.filter(|a| !a.trim().is_empty())).await.map_err(err)
}

#[tauri::command]
async fn delete_contact(state: State<'_, AppState>, contact_id: u64) -> CmdResult<()> {
    agent(&state).await?.delete_contact(contact_id).await.map_err(err)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            profile_exists,
            unlock,
            lock,
            get_settings,
            set_settings,
            contacts,
            messages,
            create_invite,
            invite_link,
            accept_invite,
            send_text,
            rename_contact,
            delete_contact,
            host_local_relay,
            stop_local_relay,
            local_relay_address,
        ])
        .setup(|app| {
            // Bring the hosted relay up at launch, before unlock, so contacts can
            // deliver to it while the profile is locked.
            let handle = app.handle().clone();
            if load_settings(&handle).host_relay {
                tauri::async_runtime::spawn(async move {
                    let state = handle.state::<AppState>();
                    match ensure_local_relay(&handle, state.inner()).await {
                        Ok(addr) => {
                            // The LAN address may have changed since last time.
                            let mut s = load_settings(&handle);
                            if s.relay.as_deref() != Some(addr.as_str()) {
                                s.relay = Some(addr);
                                let _ = save_settings(&handle, state.inner(), s);
                            }
                        }
                        Err(e) => eprintln!("lethe: hosted relay didn't start: {e}"),
                    }
                });
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running lethe");
}
