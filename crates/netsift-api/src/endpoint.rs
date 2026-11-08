//! Endpoint DTOs shared by the analysis views: an IP address with what the session knows about
//! it (names, address category, country), and the parsing of `category=` filters.

use std::net::IpAddr;
use std::str::FromStr;

use netsift_store::connections::EndpointInfo;
use serde::Serialize;
use ts_rs::TS;

use crate::ApiError;

/// Category of an IP address (`netsift_geo::AddressCategory`, same labels). The UI legends show
/// `private` as "LAN".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum AddressCategory {
    Private,
    Public,
    Broadcast,
    Multicast,
    LinkLocal,
    Loopback,
    Cgnat,
    Unspecified,
    Reserved,
}

impl From<netsift_geo::AddressCategory> for AddressCategory {
    fn from(c: netsift_geo::AddressCategory) -> Self {
        use netsift_geo::AddressCategory as G;
        match c {
            G::Private => Self::Private,
            G::Public => Self::Public,
            G::Broadcast => Self::Broadcast,
            G::Multicast => Self::Multicast,
            G::LinkLocal => Self::LinkLocal,
            G::Loopback => Self::Loopback,
            G::Cgnat => Self::Cgnat,
            G::Unspecified => Self::Unspecified,
            G::Reserved => Self::Reserved,
        }
    }
}

/// An IP address and what the session knows about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct Endpoint {
    /// Canonical text (RFC 5952 for IPv6).
    pub ip: String,
    /// Names learned from the traffic (DNS, NBNS...), sorted; empty when none.
    pub names: Vec<String>,
    /// Category of the address (computed when the host table lacks it).
    pub category: AddressCategory,
    /// ISO 3166-1 alpha-2 code, for geolocated public addresses.
    pub country: Option<String>,
}

impl Endpoint {
    pub(crate) fn new(ip: IpAddr, info: EndpointInfo) -> Self {
        let category = info
            .category
            .as_deref()
            .and_then(|c| netsift_geo::AddressCategory::from_str(c).ok())
            .unwrap_or_else(|| netsift_geo::AddressCategory::of(ip));
        Self {
            ip: ip.to_string(),
            names: info.names,
            category: category.into(),
            country: info.country,
        }
    }
}

/// `category=private,public,...`: stored labels, validated; `None` when absent.
pub(crate) fn parse_categories(raw: Option<&str>) -> Result<Option<Vec<String>>, ApiError> {
    let Some(raw) = raw else { return Ok(None) };
    raw.split(',')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(|c| {
            netsift_geo::AddressCategory::from_str(c)
                .map(|c| c.as_str().to_owned())
                .map_err(|_| ApiError::BadRequest("category: unknown address category".to_owned()))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_are_validated() {
        assert_eq!(parse_categories(None).unwrap(), None);
        assert_eq!(
            parse_categories(Some("private, link_local,")).unwrap(),
            Some(vec!["private".to_owned(), "link_local".to_owned()])
        );
        // An empty list matches nothing (every toggle off).
        assert_eq!(parse_categories(Some("")).unwrap(), Some(Vec::new()));
        assert!(parse_categories(Some("lan")).is_err());
    }

    #[test]
    fn category_falls_back_to_the_address() {
        let e = Endpoint::new("10.1.2.3".parse().unwrap(), EndpointInfo::default());
        assert_eq!(e.category, AddressCategory::Private);
        let e = Endpoint::new(
            "10.1.2.3".parse().unwrap(),
            EndpointInfo {
                category: Some("public".into()),
                ..EndpointInfo::default()
            },
        );
        assert_eq!(e.category, AddressCategory::Public);
        // Every geo category has a DTO.
        for c in netsift_geo::AddressCategory::ALL {
            let json = serde_json::to_value(AddressCategory::from(c)).unwrap();
            assert_eq!(json, c.as_str());
        }
    }
}
