#[cfg(target_arch = "wasm32")]
mod worker;

use core_crypto::mls::{MlsSelftestReport, run_mls_selftest};

/// Runs the RFC 9420 MLS selftest (accessible both natively in tests and from WASM).
pub fn execute_mls_selftest() -> Result<MlsSelftestReport, String> {
    run_mls_selftest().map_err(|e| e.to_string())
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn start_worker() {
    worker::start();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selftest_helper_passes() {
        let report = execute_mls_selftest().unwrap();
        assert!(report.roundtrip_ok);
        assert!(report.removed_guest_blocked);
    }
}
