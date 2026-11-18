//! A short description of the machine, stored with measurements.

use serde::Serialize;

/// The machine a measurement was taken on.
#[derive(Debug, Serialize)]
pub struct SystemInfo {
    pub os: &'static str,
    pub arch: &'static str,
    pub logical_cpus: usize,
    pub cpu: Option<String>,
}

fn cpu_name() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let info = std::fs::read_to_string("/proc/cpuinfo").ok()?;
        info.lines()
            .find(|line| line.starts_with("model name"))
            .and_then(|line| line.split_once(':'))
            .map(|(_, name)| name.trim().to_owned())
    }
    #[cfg(windows)]
    {
        std::env::var("PROCESSOR_IDENTIFIER").ok()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        None
    }
}

pub fn system_info() -> SystemInfo {
    SystemInfo {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        logical_cpus: std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get),
        cpu: cpu_name(),
    }
}

impl SystemInfo {
    /// One line for a text report, for example
    /// `windows x86_64, 8 logical CPUs, Some CPU Name`.
    pub fn line(&self) -> String {
        format!(
            "{} {}, {} logical CPUs{}",
            self.os,
            self.arch,
            self.logical_cpus,
            self.cpu
                .as_ref()
                .map(|cpu| format!(", {cpu}"))
                .unwrap_or_default()
        )
    }
}
