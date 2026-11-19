//! Real devices through hidapi.

use super::select::{Candidate, select};
use super::{Bus, Link, Opened};
use hidapi::{HidApi, HidDevice};
use std::ffi::CString;

/// Enumerates and opens OnlyKeys; hidapi is created lazily so a failed init is retried.
#[derive(Default)]
pub struct HidBus {
    /// hidapi context, once it initialised.
    api: Option<HidApi>,
}

impl Bus for HidBus {
    /// Re-enumerates and opens the interface [`select`] picks.
    fn open(&mut self) -> Result<Option<Opened>, String> {
        let api = match &mut self.api {
            Some(api) => {
                api.refresh_devices().map_err(|e| e.to_string())?;
                api
            }
            None => self.api.insert(HidApi::new().map_err(|e| e.to_string())?),
        };
        let candidates = candidates(api);
        let Some(pick) = select(&candidates) else {
            return Ok(None);
        };
        let path = CString::new(pick.path.clone()).map_err(|e| e.to_string())?;
        let device = api.open_path(&path).map_err(|e| e.to_string())?;
        Ok(Some((pick.pid, Box::new(HidLink(device)))))
    }
}

/// Every HID collection hidapi currently sees, as selection input.
pub fn candidates(api: &HidApi) -> Vec<Candidate> {
    api.device_list()
        .map(|d| Candidate {
            vid: d.vendor_id(),
            pid: d.product_id(),
            usage_page: d.usage_page(),
            usage: d.usage(),
            serial: d.serial_number().unwrap_or_default().to_string(),
            interface: d.interface_number(),
            path: d.path().to_string_lossy().into_owned(),
        })
        .collect()
}

/// An open OnlyKey interface.
struct HidLink(HidDevice);

impl Link for HidLink {
    /// Reads one input report (report ID 0 is not included), zero-padded to 64 bytes.
    fn read(&mut self, timeout_ms: u64) -> Result<Option<[u8; 64]>, String> {
        let mut buf = [0u8; 64];
        let timeout = i32::try_from(timeout_ms).unwrap_or(i32::MAX);
        match self.0.read_timeout(&mut buf, timeout) {
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(buf)),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Writes one output report behind report ID 0 (65 bytes).
    fn write(&mut self, packet: &[u8; 64]) -> Result<(), String> {
        let mut buf = [0u8; 65];
        buf[1..].copy_from_slice(packet);
        self.0.write(&buf).map(drop).map_err(|e| e.to_string())
    }
}
