//! C FFI API for embedding IP Bypass Plus Frag as a library in Android apps.
//!
//! This library exposes the core functionality via C-compatible functions so
//! it can be loaded by apps like v2rayNG. All functions are `extern "C"` and
//! use C-compatible types.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use ip_bypass_plus_frag_core::config::Config;
use ip_bypass_plus_frag_core::flow::new_flow_table;
use ip_bypass_plus_frag_core::handler::Handler;
use ip_bypass_plus_frag_core::interceptor::{FilterSpec, PacketInterceptor};
use ip_bypass_plus_frag_core::ip_scanner::{load_ip_list, scan_ip_list, IpScanEvent};
use ip_bypass_plus_frag_core::methods::build_method;
use ip_bypass_plus_frag_core::net::default_interface_ipv4;
use ip_bypass_plus_frag_core::proxy::{run_ip_bypass_plus_proxy, CONNECT_PORT};
use ip_bypass_plus_frag_platform::DefaultInterceptor;

/// Opaque handle to a running proxy instance.
pub struct ProxyHandle {
    _runtime: tokio::runtime::Handle,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

/// Scan result entry returned to the caller.
#[repr(C)]
pub struct ScanResult {
    pub ip: [u8; 16],
    pub ip_len: u32,
    pub tcp_latency_ms: u64,
    pub tls_ok: bool,
    pub tls_latency_ms: u64,
    pub ttfb_ms: u64,
    pub download_bps: f64,
    pub upload_bps: f64,
    pub score: u8,
}

/// Log callback type. The library calls this for every log line.
pub type LogCallback = extern "C" fn(level: i32, message: *const c_char);

static mut LOG_CALLBACK: Option<LogCallback> = None;

fn emit_log(level: i32, msg: &str) {
    unsafe {
        if let Some(cb) = LOG_CALLBACK {
            if let Ok(c_msg) = CString::new(msg) {
                cb(level, c_msg.as_ptr());
            }
        }
    }
}

/// Set the log callback. Call before any other function.
///
/// # Safety
/// `callback` must be a valid function pointer.
#[no_mangle]
pub unsafe extern "C" fn ipbp_set_log_callback(callback: LogCallback) {
    LOG_CALLBACK = Some(callback);
}

/// Get library version string. Caller must free with `ipbp_free_string`.
///
/// # Safety
/// Returns a valid C string pointer or null on error.
#[no_mangle]
pub unsafe extern "C" fn ipbp_version() -> *mut c_char {
    match CString::new(env!("CARGO_PKG_VERSION")) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a string returned by this library.
///
/// # Safety
/// `ptr` must have been returned by a function from this library.
#[no_mangle]
pub unsafe extern "C" fn ipbp_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

/// Load and validate a config file.
///
/// # Safety
/// `config_path` must be a valid null-terminated C string.
/// Returns 0 on success, negative on error.
#[no_mangle]
pub unsafe extern "C" fn ipbp_load_config(config_path: *const c_char) -> i32 {
    let path = match CStr::from_ptr(config_path).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    match Config::from_file(path) {
        Ok(_) => 0,
        Err(e) => {
            emit_log(1, &format!("config error: {e:#}"));
            -2
        }
    }
}

/// Scan IP list and return results.
///
/// # Safety
/// - `ip_list_path` must be a valid null-terminated C string.
/// - `sni` must be a valid null-terminated C string.
/// - `results_out` must point to a valid `ScanResult` array of `max_results` entries.
/// - Returns the number of results written, or negative on error.
#[no_mangle]
pub unsafe extern "C" fn ipbp_scan_ips(
    ip_list_path: *const c_char,
    sni: *const c_char,
    timeout_secs: u64,
    max_results: u32,
    results_out: *mut ScanResult,
    max_ip_scan: u32,
) -> i32 {
    let path_str = match CStr::from_ptr(ip_list_path).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let sni_str = match CStr::from_ptr(sni).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return -3,
    };

    let path = PathBuf::from(path_str);
    let cfg_text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return -4,
    };
    let mut cfg: Config = match toml::from_str(&cfg_text) {
        Ok(c) => c,
        Err(_) => return -5,
    };
    if max_ip_scan > 0 {
        cfg.MAX_IP_SCAN = max_ip_scan as usize;
    }
    let cfg = Arc::new(cfg);

    let ips = match load_ip_list(&path, cfg.IPV6_MAX_HOSTS) {
        Ok(ips) => ips,
        Err(_) => return -6,
    };
    if ips.is_empty() {
        return -7;
    }

    let scan_sni: Arc<str> = Arc::from(sni_str);
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let entries = rt.block_on(scan_ip_list(ips, scan_sni, timeout, cfg, None));

    let count = (entries.len() as u32).min(max_results);
    for (i, entry) in entries.iter().take(count as usize).enumerate() {
        let out = &mut *results_out.add(i as usize);
        let ip_str = entry.ip.to_string();
        let ip_bytes = ip_str.as_bytes();
        let copy_len = ip_bytes.len().min(15);
        out.ip[..copy_len].copy_from_slice(&ip_bytes[..copy_len]);
        out.ip[copy_len..].fill(0);
        out.ip_len = copy_len as u32;
        out.tcp_latency_ms = entry.tcp_latency_ms.unwrap_or(0);
        out.tls_ok = entry.tls_ok;
        out.tls_latency_ms = entry.tls_latency_ms.unwrap_or(0);
        out.ttfb_ms = entry.ttfb_ms.unwrap_or(0);
        out.download_bps = entry.download_bps.unwrap_or(0.0);
        out.upload_bps = entry.upload_bps.unwrap_or(0.0);
        out.score = entry.score;
    }

    count as i32
}

/// Pretty-print the effective IPBF configuration supplied by the caller.
fn log_ipbf_settings(cfg: &Config, initial_target: &str) {
    emit_log(
        0,
        &format!(
            "settings: mode={} | method={} | listener={}:{} | initial_target={}",
            cfg.MODE, cfg.BYPASS_METHOD, cfg.LISTEN_HOST, cfg.LISTEN_PORT, initial_target
        ),
    );
    let frag_length = cfg
        .TLS_FRAG_LENGTH
        .map(|r| r.to_string())
        .unwrap_or_else(|| "?".into());
    emit_log(
        0,
        &format!(
            "frag: packets={} | length={} | interval_ms={} | tcp_seg_size={} | nodelay={}",
            cfg.TLS_FRAG_PACKETS, frag_length, cfg.TLS_FRAG_INTERVAL_MS, cfg.TCP_SEG_SIZE, cfg.TCP_SEG_NODELAY,
        ),
    );
    emit_log(
        0,
        &format!(
            "scanner: sni={} | timeout={}s | p1={} | p2={} | max_ip_scan={}",
            cfg.IP_SCAN_SNI,
            cfg.SCAN_TIMEOUT_SECS,
            cfg.IP_MAX_P1_CONCURRENT,
            cfg.IP_MAX_P2_CONCURRENT,
            cfg.MAX_IP_SCAN,
        ),
    );
    if cfg.RESCAN_INTERVAL_SECS > 0 {
        emit_log(
            0,
            &format!(
                "rescan: interval={}s | switch_min_score={} | ip_list={}",
                cfg.RESCAN_INTERVAL_SECS, cfg.SNI_SWITCH_MIN_SCORE, cfg.IP_LIST
            ),
        );
    } else {
        emit_log(0, "rescan: disabled (interval=0s)");
    }
}

fn format_rescan_timing(interval_secs: u64) -> String {
    if interval_secs > 0 {
        format!("initial target; first rescan in ~2s, then every {interval_secs}s")
    } else {
        "initial target; rescan disabled".to_string()
    }
}

fn format_ms(v: Option<u64>) -> String {
    v.map(|x| format!("{x}ms")).unwrap_or_else(|| "-".into())
}

fn format_bps(v: Option<f64>) -> String {
    match v {
        None => "-".into(),
        Some(bps) if bps >= 1_048_576.0 => format!("{:.1}MB/s", bps / 1_048_576.0),
        Some(bps) => format!("{:.0}KB/s", bps / 1024.0),
    }
}

/// Spawn a background task that periodically rescans the IP list and hot-swaps
/// the active IP when a strictly better-scoring candidate is found.
///
/// The proxy reads `active_ip` on every new connection, so swapping the value
/// routes new connections to the new IP without disrupting existing ones.
fn spawn_background_ip_rescan(
    rt: &tokio::runtime::Runtime,
    cfg: Arc<Config>,
    path: PathBuf,
    active_ip: Arc<RwLock<std::net::IpAddr>>,
    current_score: Arc<RwLock<Option<u8>>>,
) {
    let interval_secs = cfg.RESCAN_INTERVAL_SECS;
    if interval_secs == 0 {
        return;
    }
    let interval = std::time::Duration::from_secs(interval_secs.max(1));

    rt.handle().spawn(async move {
        // Run the first scan a couple of seconds after startup so the active IP
        // and any early upgrade decision become visible in the log quickly;
        // afterwards it runs once per configured interval.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let mut cycle: u64 = 0;
        loop {
            cycle += 1;

            emit_log(
                0,
                &format!("rescan #{cycle}: loading IP list from {}", path.display()),
            );
            let mut ips = match load_ip_list(&path, cfg.IPV6_MAX_HOSTS) {
                Ok(ips) => ips,
                Err(e) => {
                    emit_log(2, &format!("rescan #{cycle}: failed to load ip_list: {e:#}"));
                    continue;
                }
            };
            if ips.is_empty() {
                emit_log(2, &format!("rescan #{cycle}: ip_list is empty"));
                continue;
            }
            if cfg.MAX_IP_SCAN > 0 && ips.len() > cfg.MAX_IP_SCAN {
                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
                ips.shuffle(&mut rng);
                ips.truncate(cfg.MAX_IP_SCAN);
            }
            let scanned = ips.len();
            let started = std::time::Instant::now();
            emit_log(
                0,
                &format!(
                    "rescan #{cycle}: scanning {scanned} IPs (timeout {}s, p1={}, p2={})",
                    cfg.SCAN_TIMEOUT_SECS, cfg.IP_MAX_P1_CONCURRENT, cfg.IP_MAX_P2_CONCURRENT
                ),
            );

            let scan_sni: Arc<str> = Arc::from(cfg.IP_SCAN_SNI.as_str());
            let scan_timeout = std::time::Duration::from_secs(cfg.SCAN_TIMEOUT_SECS);
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<IpScanEvent>();
            let mut progress = tokio::spawn(async move {
                let mut tcp_done = 0usize;
                let mut p2_count = 0usize;
                let mut tls_ok = 0usize;
                let mut healthy = 0usize;
                let mut last_pct = 0usize;
                let mut last_p2_report = 0usize;
                while let Some(evt) = rx.recv().await {
                    match evt {
                        IpScanEvent::TcpDone { tcp_tested, tcp_ok: ok } => {
                            tcp_done = tcp_tested;
                            let pct = if scanned > 0 {
                                tcp_done * 100 / scanned
                            } else {
                                100
                            };
                            if pct >= last_pct + 10 {
                                emit_log(
                                    0,
                                    &format!(
                                        "rescan #{cycle}: p1 tcp {tcp_done}/{scanned} ({pct}%) | ok {ok}"
                                    ),
                                );
                                last_pct = (pct / 10) * 10;
                            }
                        }
                        IpScanEvent::ProbeComplete(entry) => {
                            p2_count += 1;
                            if entry.tls_ok {
                                tls_ok += 1;
                            }
                            if entry.tcp_latency_ms.is_some()
                                && entry.tls_ok
                                && entry.cert_valid
                                && entry.ttfb_ms.is_some()
                                && entry.download_bps.is_some()
                                && entry.upload_bps.is_some()
                            {
                                healthy += 1;
                            }
                            if p2_count >= last_p2_report + 50 {
                                emit_log(
                                    0,
                                    &format!(
                                        "rescan #{cycle}: p2 tls {p2_count} probed | tls ok {tls_ok} | healthy {healthy}"
                                    ),
                                );
                                last_p2_report = p2_count;
                            }
                        }
                        IpScanEvent::Phase1Done { tcp_ok: ok, elapsed_ms } => {
                            if ok == 0 {
                                emit_log(
                                    2,
                                    &format!(
                                        "rescan #{cycle}: phase 1 done — NO TCP connect accepted (0/{tcp_done}), scan is wasted; skipping TLS phase"
                                    ),
                                );
                            } else {
                                emit_log(
                                    0,
                                    &format!(
                                        "rescan #{cycle}: phase 1 done — tcp ok {ok}/{tcp_done} in {elapsed_ms} ms; starting TLS/TTFB probes"
                                    ),
                                );
                            }
                        }
                        IpScanEvent::Phase2Done {
                            probed: p,
                            tls_ok: to,
                            healthy: h,
                            elapsed_ms,
                        } => {
                            emit_log(
                                0,
                                &format!(
                                    "rescan #{cycle}: phase 2 done — {p} probed, tls ok {to}, healthy {h} in {elapsed_ms} ms"
                                ),
                            );
                        }
                    }
                }
            });

            // Hard deadline for the whole scan so a stuck network phase can
            // never wedge the rescan loop; on timeout we keep the active IP.
            let scan_deadline = std::time::Duration::from_secs(120);
            let scan_fut = async {
                scan_ip_list(ips, scan_sni, scan_timeout, cfg.clone(), Some(tx)).await
            };
            let entries = match tokio::time::timeout(scan_deadline, scan_fut).await {
                Ok(entries) => entries,
                Err(_) => {
                    progress.abort();
                    emit_log(
                        2,
                        &format!(
                            "rescan #{cycle}: scan did not finish within {}s — aborting this cycle, keeping current active IP",
                            scan_deadline.as_secs()
                        ),
                    );
                    let final_active = *active_ip.read().unwrap();
                    emit_log(0, &format!("active_ip={final_active}"));
                    tokio::time::sleep(interval).await;
                    continue;
                }
            };
            // Let the (aborted) progress task drain any last phase-report line,
            // then make sure it is gone so we never block on it.
            let _ = tokio::time::timeout(std::time::Duration::from_millis(300), &mut progress).await;
            progress.abort();
            let _ = progress.await;

            let elapsed_ms = started.elapsed().as_millis();
            emit_log(
                0,
                &format!(
                    "rescan #{cycle}: complete — {} candidates probed in {elapsed_ms} ms",
                    entries.len(),
                ),
            );
            for (rank, e) in entries.iter().take(5).enumerate() {
                let marker = if *active_ip.read().unwrap() == e.ip {
                    " <- active"
                } else {
                    ""
                };
                emit_log(0, &format!("  {:>2}. {}{}", rank + 1, e.summary_line(), marker));
            }

            // Only a candidate that completed a real TLS handshake may replace
            // the active IP; a bare TCP responder would break client handshakes.
            let current = *active_ip.read().unwrap();
            let best = entries.iter().find(|e| e.tls_ok);
            let Some(best) = best else {
                emit_log(
                    2,
                    &format!(
                        "rescan #{cycle}: no TLS-OK candidate in this sample — keeping {current}"
                    ),
                );
                emit_log(0, &format!("active_ip={current}"));
                tokio::time::sleep(interval).await;
                continue;
            };

            let cur_score = *current_score.read().unwrap();
            let cur_score_str = cur_score
                .map(|s| s.to_string())
                .unwrap_or_else(|| "?".to_string());

            if current == best.ip {
                *current_score.write().unwrap() = Some(best.score);
                emit_log(
                    0,
                    &format!(
                        "rescan #{cycle}: keep {current} — best candidate equals active; score refreshed to {}",
                        best.score
                    ),
                );
            } else if best.score > cur_score.unwrap_or(0) {
                *active_ip.write().unwrap() = best.ip;
                *current_score.write().unwrap() = Some(best.score);
                emit_log(
                    0,
                    &format!(
                        "rescan #{cycle}: SWITCH {current} (score {cur_score_str}) -> {} (score {}) [+{}] | tcp {} tls {} ttfb {} down {} up {}",
                        best.ip,
                        best.score,
                        best.score - cur_score.unwrap_or(0),
                        format_ms(best.tcp_latency_ms),
                        format_ms(best.tls_latency_ms),
                        format_ms(best.ttfb_ms),
                        format_bps(best.download_bps),
                        format_bps(best.upload_bps),
                    ),
                );
                emit_log(
                    0,
                    &format!(
                        "rescan #{cycle}: note — new connections will use {}; existing connections keep {current} for their lifetime",
                        best.ip
                    ),
                );
            } else {
                emit_log(
                    0,
                    &format!(
                        "rescan #{cycle}: keep {current} (score {cur_score_str}) — best candidate {} (score {}) is not better",
                        best.ip, best.score
                    ),
                );
            }

            // Single authoritative marker of the currently active IP so the app
            // can display it without parsing free-form log lines.
            let final_active = *active_ip.read().unwrap();
            emit_log(0, &format!("active_ip={final_active}"));

            tokio::time::sleep(interval).await;
        }
    });
}

/// Start the proxy in the background.
///
/// # Safety
/// - `config_path` must be a valid null-terminated C string.
/// - `target_ip` must be a valid null-terminated C string (IPv4 address).
/// - `interface_ip` must be a valid null-terminated C string (IPv4 address).
/// - Returns an opaque handle on success, null on error.
#[no_mangle]
pub unsafe extern "C" fn ipbp_start_proxy(
    config_path: *const c_char,
    target_ip: *const c_char,
    interface_ip: *const c_char,
) -> *mut ProxyHandle {
    let cfg_path = match CStr::from_ptr(config_path).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let target = match CStr::from_ptr(target_ip).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let iface = match CStr::from_ptr(interface_ip).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let target_addr: std::net::Ipv4Addr = match target.parse() {
        Ok(a) => a,
        Err(_) => return std::ptr::null_mut(),
    };
    let iface_addr: std::net::Ipv4Addr = match iface.parse() {
        Ok(a) => a,
        Err(_) => return std::ptr::null_mut(),
    };

    let cfg = match Config::from_file(cfg_path) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            emit_log(1, &format!("config error: {e:#}"));
            return std::ptr::null_mut();
        }
    };
    log_ipbf_settings(&cfg, target);

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ipbp-proxy")
        .build()
    {
        Ok(r) => r,
        Err(_) => return std::ptr::null_mut(),
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let flows = new_flow_table();
    let active_ip = Arc::new(RwLock::new(std::net::IpAddr::V4(target_addr)));
    let current_score = Arc::new(RwLock::new(None));
    emit_log(0, &format!("startup active_ip={target_addr} ({})", format_rescan_timing(cfg.RESCAN_INTERVAL_SECS)));
    let ip_list_path = {
        let raw = PathBuf::from(&cfg.IP_LIST);
        if raw.is_absolute() {
            raw
        } else {
            PathBuf::from(cfg_path)
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(raw)
        }
    };

    // Start interceptor if needed
    if cfg.BYPASS_METHOD != "tls_frag" {
        let method = match build_method(&cfg) {
            Some(m) => Arc::from(m),
            None => {
                emit_log(1, &format!("unknown bypass method: {}", cfg.BYPASS_METHOD));
                return std::ptr::null_mut();
            }
        };
        let filter = FilterSpec {
            interface_ip: iface_addr,
            remote_ip: None,
            remote_port: CONNECT_PORT,
            queue_num: cfg.NFQUEUE_NUM,
            linux_firewall_backend: cfg.linux_firewall_backend(),
        };
        let interceptor = match DefaultInterceptor::open(filter) {
            Ok(i) => i,
            Err(e) => {
                emit_log(1, &format!("interceptor open failed: {e:#}"));
                return std::ptr::null_mut();
            }
        };
        let handler = Handler::new(flows.clone(), method);
        std::thread::Builder::new()
            .name("ipbp-intercept".into())
            .spawn(move || {
                let _ = interceptor.run_until(handler, Default::default());
            })
            .ok();
    }

    let proxy_cfg = cfg.clone();
    spawn_background_ip_rescan(
        &rt,
        cfg.clone(),
        ip_list_path,
        active_ip.clone(),
        current_score.clone(),
    );
    rt.spawn(async move {
        let _ = run_ip_bypass_plus_proxy(
            proxy_cfg,
            active_ip,
            iface_addr,
            flows,
            None,
            None,
        )
        .await;
    });

    // Keep the runtime alive until shutdown
    let runtime_handle = rt.handle().clone();
    std::thread::Builder::new()
        .name("ipbp-keepalive".into())
        .spawn(move || {
            rt.block_on(async move {
                let _ = shutdown_rx.await;
            });
        })
        .ok();

    Box::into_raw(Box::new(ProxyHandle {
        _runtime: runtime_handle,
        shutdown_tx: Some(shutdown_tx),
    }))
}

/// Stop a running proxy and free the handle.
///
/// # Safety
/// `handle` must have been returned by `ipbp_start_proxy`.
/// The handle is consumed and must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn ipbp_stop_proxy(handle: *mut ProxyHandle) {
    if handle.is_null() {
        return;
    }
    let h = Box::from_raw(handle);
    if let Some(tx) = h.shutdown_tx {
        let _ = tx.send(());
    }
}

/// Start the proxy with full config text and target IP (no file path needed).
///
/// This is the most convenient API for Android embedding: pass config contents
/// as a string and the target IP directly.
///
/// # Safety
/// - `config_text` must be a valid null-terminated C string (TOML config).
/// - `target_ip` must be a valid null-terminated C string (IPv4 address).
/// - Returns an opaque handle on success, null on error.
#[no_mangle]
pub unsafe extern "C" fn ipbp_start_proxy_from_config(
    config_text: *const c_char,
    target_ip: *const c_char,
) -> *mut ProxyHandle {
    let cfg_str = match CStr::from_ptr(config_text).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let target = match CStr::from_ptr(target_ip).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let cfg: Config = match toml::from_str(cfg_str) {
        Ok(c) => c,
        Err(e) => {
            emit_log(1, &format!("config parse error: {e:#}"));
            return std::ptr::null_mut();
        }
    };
    let cfg = Arc::new(cfg);
    log_ipbf_settings(&cfg, target);

    let target_addr: std::net::Ipv4Addr = match target.parse() {
        Ok(a) => a,
        Err(_) => return std::ptr::null_mut(),
    };

    let interface_ip = match default_interface_ipv4(target_addr) {
        Ok(ip) => ip,
        Err(e) => {
            emit_log(1, &format!("failed to determine interface IP: {e:#}"));
            return std::ptr::null_mut();
        }
    };

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ipbp-proxy")
        .build()
    {
        Ok(r) => r,
        Err(_) => return std::ptr::null_mut(),
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let flows = new_flow_table();
    let active_ip = Arc::new(RwLock::new(std::net::IpAddr::V4(target_addr)));
    let current_score = Arc::new(RwLock::new(None));
    emit_log(0, &format!("startup active_ip={target_addr} ({})", format_rescan_timing(cfg.RESCAN_INTERVAL_SECS)));
    let ip_list_path = PathBuf::from(&cfg.IP_LIST);

    // Start interceptor if needed
    if cfg.BYPASS_METHOD != "tls_frag" {
        let method = match build_method(&cfg) {
            Some(m) => Arc::from(m),
            None => {
                emit_log(1, &format!("unknown bypass method: {}", cfg.BYPASS_METHOD));
                return std::ptr::null_mut();
            }
        };
        let filter = FilterSpec {
            interface_ip,
            remote_ip: None,
            remote_port: CONNECT_PORT,
            queue_num: cfg.NFQUEUE_NUM,
            linux_firewall_backend: cfg.linux_firewall_backend(),
        };
        let interceptor = match DefaultInterceptor::open(filter) {
            Ok(i) => i,
            Err(e) => {
                emit_log(1, &format!("interceptor open failed: {e:#}"));
                return std::ptr::null_mut();
            }
        };
        let handler = Handler::new(flows.clone(), method);
        std::thread::Builder::new()
            .name("ipbp-intercept".into())
            .spawn(move || {
                let _ = interceptor.run_until(handler, Default::default());
            })
            .ok();
    }

    let proxy_cfg = cfg.clone();
    spawn_background_ip_rescan(
        &rt,
        cfg.clone(),
        ip_list_path,
        active_ip.clone(),
        current_score.clone(),
    );
    rt.spawn(async move {
        let _ = run_ip_bypass_plus_proxy(
            proxy_cfg,
            active_ip,
            interface_ip,
            flows,
            None,
            None,
        )
        .await;
    });

    let runtime_handle = rt.handle().clone();
    std::thread::Builder::new()
        .name("ipbp-keepalive".into())
        .spawn(move || {
            rt.block_on(async move {
                let _ = shutdown_rx.await;
            });
        })
        .ok();

    Box::into_raw(Box::new(ProxyHandle {
        _runtime: runtime_handle,
        shutdown_tx: Some(shutdown_tx),
    }))
}
