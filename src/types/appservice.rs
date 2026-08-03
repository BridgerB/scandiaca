//! Application Service types — port of strix `types/appservice.ts`.

use serde::{Deserialize, Serialize};

/// A single appservice registration (the JSON objects in
/// `APPSERVICE_REGISTRATIONS`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppserviceRegistration {
    pub id: String,
    #[serde(default)]
    pub url: String,
    pub as_token: String,
    pub hs_token: String,
    pub sender_localpart: String,
    #[serde(default)]
    pub namespaces: AppserviceNamespaces,
    #[serde(default)]
    pub rate_limited: Option<bool>,
    #[serde(default)]
    pub protocols: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AppserviceNamespaces {
    #[serde(default)]
    pub users: Option<Vec<AppserviceNamespace>>,
    #[serde(default)]
    pub rooms: Option<Vec<AppserviceNamespace>>,
    #[serde(default)]
    pub aliases: Option<Vec<AppserviceNamespace>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppserviceNamespace {
    #[serde(default)]
    pub exclusive: bool,
    pub regex: String,
}
