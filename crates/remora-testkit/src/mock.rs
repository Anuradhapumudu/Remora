//! Call-recording mocks: prove that something did NOT happen (e.g. the input
//! injector was never called before approval — phase3-criteria A20, INV1).

use std::sync::{Arc, Mutex, PoisonError};

/// Records the calls made to a mocked component. Clone it into the component
/// under test and keep a copy to inspect.
#[derive(Debug, Clone, Default)]
pub struct CallLog {
    calls: Arc<Mutex<Vec<String>>>,
}

impl CallLog {
    /// A fresh, empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one call (a short description, e.g. `"inject MouseButton"`).
    pub fn record(&self, call: impl Into<String>) {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(call.into());
    }

    /// Number of calls recorded.
    pub fn count(&self) -> usize {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// The recorded calls, in order.
    pub fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_one_log() {
        let log = CallLog::new();
        let inside = log.clone();
        assert_eq!(log.count(), 0);
        inside.record("inject key");
        assert_eq!(log.count(), 1);
        assert_eq!(log.calls(), vec!["inject key".to_owned()]);
    }
}
