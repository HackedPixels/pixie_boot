use std::net::Ipv4Addr;

/// A DHCP Option
#[derive(Debug)]
pub enum DHCPOption<'a> {
    /// Padding (0)
    Pad,
    /// Subnet Mask (1)
    SubnetMask(Ipv4Addr),
    /// Requested IP Address (50)
    RequestedIPAddress(Ipv4Addr),
    /// IP Address Lease Time (51)
    AddressLeaseTime(u32),
    /// Option Overloaed (52)
    OptionOverload(u8),
    /// Message Type (53)
    MessageType(DHCPMessageType),
    /// Server Identifier (54)
    ServerIdentifier(Ipv4Addr),
    /// Parameter Request List (55)
    ParameterRequestList(DHCPParameterRequest<'a>),
    /// Message (56)
    Message(&'a [u8]),
    /// Maximum DHCP Message Size (57)
    MaximumSize(u16),
    /// Renewal (T1) Time Value (58)
    Renewal(u32),
    /// Rebinding (T2) Time Value (59)
    Rebinding(u32),
    /// Class Identifier (60)
    ClassIdentifier(&'a [u8]),
    /// Client Identifier (61)
    ClientIdentifier(&'a [u8]),
    /// Generic (unparsed) option
    Generic(DHCPGenericOption<'a>),
    /// End of options (255)
    End,
}

/// A DHCP Unknown Option
#[derive(Debug)]
pub struct DHCPGenericOption<'a> {
    /// Tag
    pub t: u8,
    /// Length
    pub l: u8,
    /// Value
    pub v: &'a [u8],
}

// --== Helpers ==--
impl<'a> DHCPOption<'a> {
    /// Get the numeric code for an option
    pub fn tag(&self) -> u8 {
        match self {
            DHCPOption::Pad => 0,
            DHCPOption::SubnetMask(_) => 1,
            DHCPOption::RequestedIPAddress(_) => 50,
            DHCPOption::AddressLeaseTime(_) => 51,
            DHCPOption::OptionOverload(_) => 52,
            DHCPOption::MessageType(_) => 53,
            DHCPOption::ServerIdentifier(_) => 54,
            DHCPOption::ParameterRequestList(_) => 55,
            DHCPOption::Message(_) => 56,
            DHCPOption::MaximumSize(_) => 57,
            DHCPOption::Renewal(_) => 58,
            DHCPOption::Rebinding(_) => 59,
            DHCPOption::ClassIdentifier(_) => 60,
            DHCPOption::ClientIdentifier(_) => 61,
            DHCPOption::Generic(opt) => opt.t,
            DHCPOption::End => 255,
        }
    }
}

// --== RFC 1553 ==--

/// DHCP Message Type
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DHCPMessageType(pub u8);

/// Parameter Request List
#[derive(Debug)]
pub struct DHCPParameterRequest<'a>(pub &'a [u8]);

/// DHCP Message Type Constants
impl DHCPMessageType {
    pub const DHCPDISCOVER: DHCPMessageType = DHCPMessageType(0x01);
    pub const DHCPOFFER: DHCPMessageType = DHCPMessageType(0x02);
    pub const DHCPREQUEST: DHCPMessageType = DHCPMessageType(0x03);
    pub const DHCPDECLINE: DHCPMessageType = DHCPMessageType(0x04);
    pub const DHCPACK: DHCPMessageType = DHCPMessageType(0x05);
    pub const DHCPNAK: DHCPMessageType = DHCPMessageType(0x06);
    pub const DHCPRELEASE: DHCPMessageType = DHCPMessageType(0x07);
}

impl std::fmt::Debug for DHCPMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DHCPMessageType(0x01) => write!(f, "DISCOVER"),
            DHCPMessageType(0x02) => write!(f, "OFFER"),
            DHCPMessageType(0x03) => write!(f, "REQUEST"),
            DHCPMessageType(0x04) => write!(f, "DECLINE"),
            DHCPMessageType(0x05) => write!(f, "ACK"),
            DHCPMessageType(0x06) => write!(f, "NAK"),
            DHCPMessageType(0x07) => write!(f, "RELEASE"),
            DHCPMessageType(_) => write!(f, "UNKNOWN"),
        }
    }
}
