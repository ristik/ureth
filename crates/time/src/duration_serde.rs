//! Serde adapters for the legacy human-readable duration format.

use crate::{format_duration, parse_duration};
use serde::{Deserialize, Deserializer, Serializer};
use std::time::Duration;

/// Serialize a duration as a human-readable string.
pub fn serialize<S: Serializer>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&format_duration(*duration))
}

/// Deserialize a duration from a human-readable string.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    let input = String::deserialize(deserializer)?;
    parse_duration(&input).map_err(serde::de::Error::custom)
}

/// Serde adapters for an optional human-readable duration.
pub mod option {
    use super::*;

    /// Serialize as a human-readable string or none.
    pub fn serialize<S: Serializer>(
        duration: &Option<Duration>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match duration {
            Some(duration) => serializer.serialize_some(&format_duration(*duration).to_string()),
            None => serializer.serialize_none(),
        }
    }

    /// Deserialize from a human-readable string or none.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Duration>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|input| parse_duration(&input).map_err(serde::de::Error::custom))
            .transpose()
    }
}
