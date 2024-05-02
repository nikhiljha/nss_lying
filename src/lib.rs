// necessary because libnss macros are badly implemented
#[macro_use]
extern crate lazy_static;

use std::{ops::RangeBounds, str::FromStr, sync::OnceLock};

use anyhow::Result;
use libnss::{
    group::{Group, GroupHooks},
    interop::Response,
    libnss_group_hooks, libnss_passwd_hooks,
    passwd::{Passwd, PasswdHooks},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Minimum UID to synthesize, inclusive
    pub uid_min: libc::uid_t,
    /// Maximum UID to synthesize, inclusive
    pub uid_max: libc::uid_t,

    /// If set, all users have this group as their primary group. If unset,
    /// each user gets their own corresponding primary group of the same name.
    pub user_group: Option<libc::gid_t>,

    /// Shell to set for each user
    pub shell: String,
}

impl Config {
    /// Get a [RangeBounds] representing the UID range
    fn uid_range(&self) -> impl RangeBounds<libc::uid_t> + Iterator<Item = libc::uid_t> {
        self.uid_min..=self.uid_max
    }

    /// Get the username for a UID, if it is in range
    ///
    /// Returns [None] when the UID is not within range
    fn name_for_uid(&self, uid: libc::uid_t) -> Option<String> {
        self.uid_range()
            .contains(&uid)
            .then(|| format!("user-{}", uid))
    }

    /// Extract a UID from a username
    ///
    /// Returns [None] when the UID is not synthesized by the module
    fn uid_from_name(&self, name: &str) -> Option<libc::uid_t> {
        let suffix = name.strip_prefix("user-")?;
        let uid = libc::uid_t::from_str(suffix).ok()?;
        self.uid_range().contains(&uid).then_some(uid)
    }

    /// Get the primary GID for a UID, if it is in range
    ///
    /// Returns [None] when the UID is not within range
    fn gid_for_uid(&self, uid: libc::uid_t) -> Option<libc::gid_t> {
        self.uid_range()
            .contains(&uid)
            .then_some(match self.user_group {
                None => uid,
                Some(gid) => gid,
            })
    }

    /// Get the name for a GID, if it is synthesized by this module
    ///
    /// Returns [None] when the GID is not synthesized by this module
    fn name_for_gid(&self, gid: libc::gid_t) -> Option<String> {
        match self.user_group {
            None => {
                // no `user_group` set, users have their own groups

                // lookup the name for the corresponding UID (will return
                // `None` if out of range)
                self.name_for_uid(gid)
            }
            Some(user_gid) => {
                // user group is set, return fixed name
                (gid == user_gid).then(|| "users".into())
            }
        }
    }

    /// Extract a GID from a username
    ///
    /// Returns [None] when the GID is not synthesized by the module
    fn gid_from_name(&self, name: &str) -> Option<libc::gid_t> {
        match self.user_group {
            None => {
                // no `user_group` set, users have their own groups
                self.uid_from_name(name)
            }
            Some(user_gid) => {
                // user group is set, return fixed name
                (name == "users").then_some(user_gid)
            }
        }
    }

    fn uid_to_passwd(&self, uid: libc::uid_t) -> Option<Passwd> {
        Some(Passwd {
            name: self.name_for_uid(uid)?,
            passwd: "x".into(),
            uid,
            gid: self.gid_for_uid(uid)?,
            gecos: "".into(),
            dir: "/tmp".into(), // XXX: maybe something smarter is possible?
            shell: self.shell.clone(),
        })
    }

    fn gid_to_group(&self, gid: libc::gid_t) -> Option<Group> {
        Some(Group {
            name: self.name_for_gid(gid)?,
            passwd: "x".into(),
            gid,
            members: Vec::new(),
        })
    }
}

/// Utility to turn `Some(foo)` to `Success(foo)` and `None` to `NotFound`
fn option_to_response<T>(o: Option<T>) -> Response<T> {
    o.map_or(Response::NotFound, Response::Success)
}

fn load_config() -> Result<Config> {
    // FIXME: actual config loading
    Ok(Config {
        uid_min: 1000,
        uid_max: 9999,
        user_group: None,
        shell: "/bin/bash".into(),
    })
}

fn config() -> &'static Config {
    static INSTANCE: OnceLock<Config> = OnceLock::new();
    INSTANCE.get_or_init(|| load_config().unwrap())
}

struct FakeDb;

libnss_passwd_hooks!(lying, FakeDb);
impl PasswdHooks for FakeDb {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        let config = config();
        Response::Success(
            config
                .uid_range()
                .map(|uid| config.uid_to_passwd(uid).unwrap())
                .collect(),
        )
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        let config = config();
        option_to_response(config.uid_to_passwd(uid))
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        let config = config();
        option_to_response(
            config
                .uid_from_name(&name)
                .map(|uid| config.uid_to_passwd(uid).unwrap()),
        )
    }
}

libnss_group_hooks!(lying, FakeDb);
impl GroupHooks for FakeDb {
    fn get_all_entries() -> Response<Vec<Group>> {
        let config = config();
        match config.user_group {
            None => {
                // group per user
                Response::Success(
                    config
                        .uid_range()
                        .map(|uid| config.gid_to_group(uid).unwrap())
                        .collect(),
                )
            }
            Some(user_gid) => Response::Success([config.gid_to_group(user_gid).unwrap()].into()),
        }
    }

    fn get_entry_by_gid(gid: libc::gid_t) -> Response<Group> {
        let config = config();
        option_to_response(config.gid_to_group(gid))
    }

    fn get_entry_by_name(name: String) -> Response<Group> {
        let config = config();
        option_to_response(
            config
                .gid_from_name(&name)
                .map(|gid| config.gid_to_group(gid).unwrap()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> Config {
        Config {
            uid_min: 1000,
            uid_max: 9999,
            user_group: None,
            shell: "/bin/bash".into(),
        }
    }

    #[test]
    fn parse_valid_name() {
        let config = base_config();
        assert_eq!(config.uid_from_name("user-9999"), Some(9999));
    }

    #[test]
    fn parse_out_of_range_name() {
        let config = base_config();
        assert_eq!(config.uid_from_name("user-99999"), None);
    }

    #[test]
    fn parse_group_name_single_group() {
        let config = Config {
            user_group: Some(1000),
            ..base_config()
        };
        assert_eq!(config.gid_from_name("users"), Some(1000));
        assert_eq!(config.gid_from_name("user-1000"), None);
        assert_eq!(config.gid_from_name("user-9999"), None);
    }

    #[test]
    fn parse_group_name_user_groups() {
        let config = Config {
            user_group: None,
            ..base_config()
        };
        assert_eq!(config.gid_from_name("users"), None);
        assert_eq!(config.gid_from_name("user-1000"), Some(1000));
        assert_eq!(config.gid_from_name("user-9999"), Some(9999));
    }

    #[test]
    fn parse_group_name_user_groups_out_of_range() {
        let config = Config {
            user_group: None,
            ..base_config()
        };
        assert_eq!(config.gid_from_name("user-99999"), None);
    }

    #[test]
    fn user_name_roundtrip() {
        let config = base_config();
        for uid in config.uid_range() {
            assert_eq!(
                config.uid_from_name(&config.name_for_uid(uid).unwrap()),
                Some(uid)
            );
        }
    }
}
