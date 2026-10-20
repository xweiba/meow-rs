//! PaoPao's manager (see [`manager`]): the user's resident owner of the
//! core, its switches and the OS system proxy, with a loopback HTTP+JSON
//! API ([`http`]) the panel and the tray programs call.
//!
//! It runs as the logged-in user: what needs root (the core with 虚拟网卡 on
//! macOS) is asked of the privileged helper by the [`manager::Core`] the
//! daemon gives it; nothing here spawns a process by itself.

pub mod data;
pub mod dns_cache;
#[cfg(feature = "desktop")]
pub mod desktop;
pub mod http;
pub mod login;
pub mod manager;
pub mod proxy;

pub use manager::{
    Builder, Core, Failure, LoginItem, Manager, Parts, Patch, ProxySwitch, Refusal, Run,
};
