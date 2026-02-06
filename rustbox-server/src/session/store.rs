use dashmap::DashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Data stored per session.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SessionData {
    /// User identifier (UUID string).
    pub user_id: String,
    /// Pre-shared key for CRISP PSK resumption.
    pub psk_access_key: Vec<u8>,
    /// Unix timestamp when the session was created.
    pub created_at: u64,
}

/// Thread-safe in-memory session store backed by DashMap.
#[allow(dead_code)]
pub struct SessionStore {
    sessions: DashMap<String, SessionData>,
}

#[allow(dead_code)]
impl SessionStore {
    /// Create a new empty session store.
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    /// Insert or update a session.
    pub fn insert(&self, session_id: String, data: SessionData) {
        self.sessions.insert(session_id, data);
    }

    /// Get a clone of session data by session ID.
    pub fn get(&self, session_id: &str) -> Option<SessionData> {
        self.sessions.get(session_id).map(|entry| entry.clone())
    }

    /// Remove a session by ID. Returns the removed data if it existed.
    pub fn remove(&self, session_id: &str) -> Option<SessionData> {
        self.sessions.remove(session_id).map(|(_, data)| data)
    }

    /// Check if a session exists.
    pub fn contains(&self, session_id: &str) -> bool {
        self.sessions.contains_key(session_id)
    }

    /// Get the count of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Remove sessions older than `max_age_secs` seconds.
    pub fn cleanup_expired(&self, max_age_secs: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.sessions.retain(|_key, data| {
            now.saturating_sub(data.created_at) < max_age_secs
        });
    }

    /// Try each session's PSK until one matches. Returns (session_id, SessionData) on match.
    /// The caller provides a test function that returns true if the PSK is correct.
    pub fn find_by_psk<F>(&self, test: F) -> Option<(String, SessionData)>
    where
        F: Fn(&[u8]) -> bool,
    {
        for entry in self.sessions.iter() {
            if test(&entry.value().psk_access_key) {
                return Some((entry.key().clone(), entry.value().clone()));
            }
        }
        None
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}
