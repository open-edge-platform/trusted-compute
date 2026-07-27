// Copyright (C) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//
// Intel NPU telemetry reader.
//
// Reads NPU performance metrics from:
//   - Intel PMT (Platform Monitoring Technology) sysfs: /sys/class/intel_pmt/
//     for power, frequency, temperature, NoC bandwidth, tile configuration.
//   - intel_vpu driver sysfs: /sys/bus/pci/drivers/intel_vpu/<pci>/
//     for utilization (npu_busy_time_us) and memory usage (npu_memory_utilization).
//
// Emits InfluxDB line protocol to stdout once per INTERVAL so it can be consumed
// by npu-telemetry-agent.sh which POSTs lines to any HTTP line-protocol endpoint
// (Telegraf, VictoriaMetrics, InfluxDB, etc.).
//
// PMT register layout and metric calculations match npu_monitor_tool.py exactly.
//
// Compile (static, via musl):
//   rustup target add x86_64-unknown-linux-musl
//   cargo build --release --target x86_64-unknown-linux-musl
//
// Environment variables:
//   METRICS_HOSTNAME   Override the host= tag (default: /etc/hostname).
//   NPU_INTERVAL_MS    Sampling interval in milliseconds (default: 1000).

use std::env;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// PMT GUID constants
// ---------------------------------------------------------------------------
const PMT_GUID_MTL:   &str = "0x130670b2";
const PMT_GUID_ARL:   &str = "0x1306a0b3";
const PMT_GUID_ARL_H: &str = "0x1306a0b2";
const PMT_GUID_ARL_S: &str = "0x1306a0b4";
const PMT_GUID_LNL:   &str = "0x3072005";
const PMT_GUID_PTL:   &str = "0x3086000";

// ---------------------------------------------------------------------------
// Platform generation — ordered so Ptl > Lnl > Arl > Mtl for mem_supported check
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CpuGen {
    Mtl = 0,
    Arl = 1,
    Lnl = 2,
    Ptl = 3,
}

// ---------------------------------------------------------------------------
// PMT register offsets (byte offsets into the binary telem file)
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy)]
struct PmtRegs {
    vpu_energy:        usize,
    soc_temperatures:  usize,
    vpu_workpoint:     usize,
    vpu_memory_bw:     usize,
}

impl PmtRegs {
    fn for_gen(gen: CpuGen) -> Self {
        match gen {
            CpuGen::Mtl | CpuGen::Arl => Self { vpu_energy: 0x628, soc_temperatures: 0x098, vpu_workpoint: 0x068, vpu_memory_bw: 0x000 },
            CpuGen::Lnl               => Self { vpu_energy: 0x5d0, soc_temperatures: 0x070, vpu_workpoint: 0x018, vpu_memory_bw: 0xc18 },
            CpuGen::Ptl               => Self { vpu_energy: 0x670, soc_temperatures: 0x078, vpu_workpoint: 0x018, vpu_memory_bw: 0xc18 },
        }
    }
}

// ---------------------------------------------------------------------------
// PMT context
// ---------------------------------------------------------------------------
struct PmtCtx {
    telem_path: String,
    gen:        CpuGen,
    regs:       PmtRegs,
    buf:        Vec<u8>,
}

// ---------------------------------------------------------------------------
// Bit-field extraction — matches PmtTelemetry.read() in npu_monitor_tool.py:
//   data = int.from_bytes(buf[offset:offset+8], 'little')
//   mask = ((1<<(msb+1))-1) & ~((1<<lsb)-1)
//   return (data & mask) >> lsb
// ---------------------------------------------------------------------------
fn pmt_read_field(buf: &[u8], offset: usize, msb: u32, lsb: u32) -> u64 {
    if offset + 8 > buf.len() {
        return 0;
    }
    let word = u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap());
    let msb_mask: u64 = if msb >= 63 { u64::MAX } else { (1u64 << (msb + 1)).wrapping_sub(1) };
    let lsb_mask: u64 = if lsb == 0  { 0         } else { (1u64 << lsb).wrapping_sub(1) };
    (word & (msb_mask & !lsb_mask)) >> lsb
}

// ---------------------------------------------------------------------------
// Sysfs helpers
// ---------------------------------------------------------------------------
fn read_str(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn read_i64(path: &str) -> Option<i64> {
    read_str(path)?.parse().ok()
}

// ---------------------------------------------------------------------------
// PMT init: scan /sys/class/intel_pmt for a known GUID
// ---------------------------------------------------------------------------
fn pmt_init() -> Option<PmtCtx> {
    let pmt_root = "/sys/class/intel_pmt";
    for entry in fs::read_dir(pmt_root).ok()?.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("telem") {
            continue;
        }

        let base = format!("{}/{}", pmt_root, name);
        let guid = match read_str(&format!("{}/guid", base)) {
            Some(g) => g,
            None => continue,
        };
        let size: usize = match read_str(&format!("{}/size", base)).and_then(|s| s.parse().ok()) {
            Some(sz) => sz,
            None => continue,
        };
        let telem_path = format!("{}/telem", base);
        if !Path::new(&telem_path).exists() {
            continue;
        }

        let gen = match guid.as_str() {
            g if g == PMT_GUID_MTL                                                   => CpuGen::Mtl,
            g if g == PMT_GUID_ARL || g == PMT_GUID_ARL_H || g == PMT_GUID_ARL_S   => CpuGen::Arl,
            g if g == PMT_GUID_LNL                                                   => CpuGen::Lnl,
            g if g == PMT_GUID_PTL                                                   => CpuGen::Ptl,
            _                                                                        => continue,
        };

        return Some(PmtCtx {
            telem_path,
            gen,
            regs: PmtRegs::for_gen(gen),
            buf: vec![0u8; size],
        });
    }
    None
}

impl PmtCtx {
    /// Read a fresh binary snapshot from the PMT telem file.
    fn update(&mut self) -> bool {
        fs::File::open(&self.telem_path)
            .and_then(|mut f| f.read_exact(&mut self.buf))
            .is_ok()
    }

    fn freq_mhz(&self) -> f64 {
        let raw = pmt_read_field(&self.buf, self.regs.vpu_workpoint, 7, 0) as f64;
        match self.gen {
            CpuGen::Mtl | CpuGen::Arl => 2.0 * raw / 3.0 / 10.0,
            _                         => 0.05 * raw,
        }
    }

    /// Hardware-scaled frequency value emitted as the `frequency=` field in InfluxDB LP.
    /// Formula matches `get_display_freq_hz()` in npu_monitor_tool.py exactly:
    ///   freq_mhz * 1000 / 2
    /// This is intentional hardware-specific scaling — not a standard MHz→Hz conversion
    /// (which would be * 1_000_000). Changing this would diverge from the upstream
    /// Python npu_reader.py and break metrics-manager dashboards.
    fn freq_hz(&self) -> f64 {
        self.freq_mhz() * 1000.0 / 2.0
    }

    fn tile_config(&self) -> i64 {
        pmt_read_field(&self.buf, self.regs.vpu_workpoint, 23, 16) as i64
    }

    fn temperature(&self) -> i64 {
        pmt_read_field(&self.buf, self.regs.soc_temperatures, 47, 40) as i64
    }

    /// U32.18.14 fixed-point energy in joules — matches get_npu_energy().
    fn energy_j(&self) -> f64 {
        let val = pmt_read_field(&self.buf, self.regs.vpu_energy, 63, 0);
        (val >> 14) as f64 + (val & ((1u64 << 14) - 1)) as f64 / (1u64 << 14) as f64
    }

    /// NoC bandwidth raw counter → MB/s — matches get_noc_bandwidth().
    fn noc_bw(&self) -> f64 {
        pmt_read_field(&self.buf, self.regs.vpu_memory_bw, 31, 0) as f64 / 1000.0
    }
}

// ---------------------------------------------------------------------------
// Locate /sys/bus/pci/drivers/intel_vpu/<0000:xx:xx.x>
// ---------------------------------------------------------------------------
fn find_npu_dev_path() -> Option<String> {
    let base = "/sys/bus/pci/drivers/intel_vpu";
    for entry in fs::read_dir(base).ok()?.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("0000:") {
            return Some(format!("{}/{}", base, name));
        }
    }
    None
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
fn main() {
    let hosttag = env::var("METRICS_HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| read_str("/etc/hostname"))
        .unwrap_or_else(|| "kata-guest".to_string());

    let interval_ms: u64 = env::var("NPU_INTERVAL_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v: &u64| v >= 100)
        .unwrap_or(1000);
    let sleep_dur  = Duration::from_millis(interval_ms);
    let interval_s = interval_ms as f64 / 1000.0;

    let mut pmt = pmt_init().unwrap_or_else(|| {
        eprintln!("[npu-reader] PMT unavailable; sleeping indefinitely");
        loop { thread::sleep(Duration::from_secs(3600)); }
    });

    let dev_path = find_npu_dev_path().unwrap_or_else(|| {
        eprintln!("[npu-reader] intel_vpu device not found; sleeping indefinitely");
        loop { thread::sleep(Duration::from_secs(3600)); }
    });

    let busy_path = format!("{}/npu_busy_time_us",       dev_path);
    let mem_path  = format!("{}/npu_memory_utilization", dev_path);

    let busy_supported = Path::new(&busy_path).exists();
    // Memory utilization only exposed on PTL and later
    let mem_supported  = pmt.gen >= CpuGen::Ptl && Path::new(&mem_path).exists();

    if !pmt.update() {
        eprintln!("[npu-reader] Initial PMT read failed");
        std::process::exit(1);
    }

    let mut prev_energy   = pmt.energy_j();
    let mut prev_bw       = pmt.noc_bw();
    let mut prev_busy_us: Option<i64> = if busy_supported { read_i64(&busy_path) } else { None };
    let mut prev_instant  = Instant::now();

    loop {
        thread::sleep(sleep_dur);

        let curr_instant = Instant::now();
        let elapsed_s    = curr_instant.duration_since(prev_instant).as_secs_f64();
        prev_instant     = curr_instant;

        if !pmt.update() {
            continue;
        }

        // Power (W) — energy delta over actual elapsed time
        let curr_energy = pmt.energy_j();
        let power_w = if elapsed_s > 0.0 { (curr_energy - prev_energy) / elapsed_s } else { 0.0 };
        prev_energy = curr_energy;

        // Frequency (Hz)
        let freq_hz = pmt.freq_hz();

        // Temperature (°C)
        let temp_c = pmt.temperature();

        // Tile configuration
        let tile_config = pmt.tile_config();

        // NoC bandwidth delta (MB/s) — clamp to 0 on counter reset/wrap
        let curr_bw = pmt.noc_bw();
        let bw_mbs  = (curr_bw - prev_bw).max(0.0);
        prev_bw = curr_bw;

        // Utilization (%) — delta of monotonic busy_time_us counter
        let utilization: i64 = if busy_supported {
            let curr_busy = read_i64(&busy_path);
            let u = match (prev_busy_us, curr_busy) {
                (Some(prev), Some(curr)) => {
                    let delta_us    = curr - prev;
                    let interval_us = (elapsed_s * 1e6) as i64;
                    if interval_us > 0 { (100 * delta_us / interval_us).clamp(0, 100) } else { 0 }
                }
                _ => 0,
            };
            prev_busy_us = curr_busy;
            u
        } else {
            0
        };

        // Memory utilization (MB), -1.0 if unsupported/unavailable
        let mem_mb: f64 = if mem_supported {
            read_i64(&mem_path)
                .map(|v| v as f64 / 1_048_576.0)
                .unwrap_or(-1.0)
        } else {
            -1.0
        };

        // Emit InfluxDB line protocol
        println!(
            "npu,host={} power={:.3},frequency={:.0},temperature={}i,bandwidth={:.3},tile_config={}i,utilization={}i,memory_mb={:.2} {}",
            hosttag, power_w, freq_hz, temp_c, bw_mbs, tile_config, utilization, mem_mb,
            now_ns()
        );
    }
}
