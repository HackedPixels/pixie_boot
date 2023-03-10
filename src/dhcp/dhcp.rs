use crate::dhcp::options::{DHCPMessageType, DHCPOption};
use std::ffi::CStr;
use std::net::Ipv4Addr;

/// A DHCP Message
#[derive(Debug)]
pub struct DHCPMessage<'a> {
    /// Message op code / message type
    pub op: u8,
    /// Hardware address type
    pub htype: u8,
    /// Hardware address length
    pub hlen: u8,
    /// Client sets to zero, optionally used by relay-agents when booting via a relay-agent
    pub hops: u8,
    /// Transaction ID
    pub xid: u32,
    /// Seconds elapsed since client started trying to boot
    pub secs: u16,
    /// Flags
    pub flags: u16,
    /// Client IP address
    pub ciaddr: Ipv4Addr,
    /// Your (client) IP Address
    pub yiaddr: Ipv4Addr,
    /// IP Address of next server to use in bootstrap
    pub siaddr: Ipv4Addr,
    /// Relay Agent IP Address
    pub giaddr: Ipv4Addr,
    /// Client hardware address
    pub chaddr: Vec<u8>,
    /// Optional server host name, null terminated string
    pub sname: &'a [u8],
    /// Boot file name, null terminated string
    pub file: &'a [u8],
    /// Magic usually DHCP
    pub magic: Vec<u8>,
    /// Optional parameters field
    pub options: Vec<DHCPOption<'a>>,
}

#[derive(Debug)]
pub enum MaybeStr<'a> {
    Empty,
    Str(&'a CStr),
    FromUTF8Error,
}

impl<'a> DHCPMessage<'a> {
    /// Obtain Server hostname
    pub fn server_name(&self) -> MaybeStr<'a> {
        let last_index = self.sname.iter().position(|&b| b == 0);
        if last_index == Some(0) {
            return MaybeStr::Empty;
        }
        match CStr::from_bytes_with_nul(self.sname) {
            Ok(s) => MaybeStr::Str(s),
            Err(_) => MaybeStr::FromUTF8Error,
        }
    }

    /// Get the server host name
    pub fn file(&self) -> MaybeStr<'a> {
        let last_index = self.file.iter().position(|&b| b == 0);
        if last_index == Some(0) {
            return MaybeStr::Empty;
        }
        match CStr::from_bytes_with_nul(self.file) {
            Ok(s) => MaybeStr::Str(s),
            Err(_) => MaybeStr::FromUTF8Error,
        }
    }

    /// Get the client hardware address (or None if there are not enough bytes)
    pub fn hw_addr(&self) -> Option<&[u8]> {
        if self.chaddr.len() >= 6 {
            Some(&self.chaddr[..6])
        } else {
            None
        }
    }

    /// Get the message type from the options, if present
    pub fn message_type(&self) -> Option<DHCPMessageType> {
        self.options.iter().find_map(|opt| match opt {
            DHCPOption::MessageType(t) => Some(*t),
            _ => None,
        })
    }
}
