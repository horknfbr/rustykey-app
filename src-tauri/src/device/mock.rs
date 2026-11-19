//! Simulated device for `RUSTYKEY_MOCK` (dev aid) and the driver-loop tests.

use super::{Bus, Link, Opened};
use onlykey_core::transport::{MockDevice, MockKind};
use std::collections::VecDeque;
use std::time::Duration;

/// Always "finds" a fresh [`MockDevice`] of one kind.
pub struct MockBus(pub MockKind);

impl MockBus {
    /// Parses a `RUSTYKEY_MOCK` value: `classic`, `duo`, `uninitialized` or `bootloader`.
    #[cfg(feature = "mock")]
    pub fn from_env_value(value: &str) -> Option<Self> {
        let kind = match value {
            "classic" => MockKind::Classic,
            "duo" => MockKind::Duo,
            "uninitialized" => MockKind::Uninitialized,
            "bootloader" => MockKind::Bootloader,
            _ => return None,
        };
        Some(Self(kind))
    }
}

impl Bus for MockBus {
    /// Plugs in a new simulated device that sends its status first, like firmware.
    fn open(&mut self) -> Result<Option<Opened>, String> {
        let device = MockDevice::new(self.0);
        let pending = VecDeque::from([device.connect_report()]);
        Ok(Some((
            device.product_id(),
            Box::new(MockLink { device, pending }),
        )))
    }
}

/// A simulated open handle: writes go to the device, its answers queue up for reads.
pub struct MockLink {
    /// The simulated firmware.
    pub device: MockDevice,
    /// Reports waiting to be read.
    pub pending: VecDeque<[u8; 64]>,
}

impl Link for MockLink {
    /// Next queued report, or sleeps out the timeout like a quiet device.
    fn read(&mut self, timeout_ms: u64) -> Result<Option<[u8; 64]>, String> {
        let report = self.pending.pop_front();
        if report.is_none() {
            std::thread::sleep(Duration::from_millis(timeout_ms));
        }
        Ok(report)
    }

    /// Hands the packet to the simulated firmware.
    fn write(&mut self, packet: &[u8; 64]) -> Result<(), String> {
        self.pending.extend(self.device.handle(packet));
        Ok(())
    }
}
