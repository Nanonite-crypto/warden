use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A flag that asks a running scan to stop.
///
/// Clones share the same flag, so one clone can live in a Ctrl-C handler or a
/// user-interface thread while the scan checks another. A cancelled scan
/// finishes the files it is already reading and returns a report marked
/// [`cancelled`](crate::ScanReport::cancelled).
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// Creates a token that has not been cancelled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. Can be called from any thread, any number of times.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_the_flag() {
        let token = CancelToken::new();
        let clone = token.clone();
        assert!(!clone.is_cancelled());
        token.cancel();
        assert!(clone.is_cancelled());
    }
}
