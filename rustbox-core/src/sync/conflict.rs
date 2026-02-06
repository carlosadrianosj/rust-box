/// Which side wins a conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Winner {
    Local,
    Remote,
}

/// Resolve a conflict using last-writer-wins strategy.
/// Compares modification timestamps; the newer one wins.
/// Ties go to remote (server is source of truth for POC1).
pub fn resolve_conflict(local_modified_at: u64, remote_modified_at: u64) -> Winner {
    if local_modified_at > remote_modified_at {
        Winner::Local
    } else {
        Winner::Remote
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_wins() {
        assert_eq!(resolve_conflict(200, 100), Winner::Local);
    }

    #[test]
    fn test_remote_wins() {
        assert_eq!(resolve_conflict(100, 200), Winner::Remote);
    }

    #[test]
    fn test_tie_goes_to_remote() {
        assert_eq!(resolve_conflict(100, 100), Winner::Remote);
    }
}
