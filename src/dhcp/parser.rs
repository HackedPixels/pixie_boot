use crate::dhcp::dhcp::*;
use crate::dhcp::options::*;

use nom::bytes::complete::take;
use nom::error::ErrorKind;
use nom::multi::many0;
use nom::multi::many_m_n;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::IResult;
use std::net::Ipv4Addr;

macro_rules! nom_err_return (
    ($i:expr, $cond:expr, $err:expr) => (
        {
            if $cond {
                return Err(::nom::Err::Error(::nom::error_position!($i, $err)));
            }
        }
    );
);

/// Parse a DHCP message
pub fn parse_dhcp_message(i: &[u8]) -> IResult<&[u8], DHCPMessage> {
    //pub fn parse_dhcp_message(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, op) = be_u8(i)?;
    let (i, htype) = be_u8(i)?;
    let (i, hlen) = be_u8(i)?;
    let (i, hops) = be_u8(i)?;
    let (i, xid) = be_u32(i)?;
    let (i, secs) = be_u16(i)?;
    let (i, flags) = be_u16(i)?;
    let (i, ciaddr) = parse_addr_v4(i)?;
    let (i, yiaddr) = parse_addr_v4(i)?;
    let (i, siaddr) = parse_addr_v4(i)?;
    let (i, giaddr) = parse_addr_v4(i)?;
    let (i, chaddr) = many_m_n(0, 16, be_u8);
    let (i, sname) = take(64usize).into()?;
    let (i, file) = take(128usize).into()?;
    let (i, magic) = take(4usize).into()?;
    let (i, options) = parse_options(i)?;

    Ok((
        i,
        DHCPMessage {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
            magic,
            options,
        },
    ))
}

fn parse_addr_v4(i: &[u8]) -> IResult<&[u8], Ipv4Addr> {
    let (i1, val) = take(4usize)(i)?;
    let addr = Ipv4Addr::new(val[0], val[1], val[2], val[3]);

    Ok((i1, addr))
}

fn parse_padding(i: &[u8]) -> IResult<&[u8], ()> {
    // inside many0, we dont want to fail if there are no more bytes
    use nom::bytes::complete::tag;
    let (rem, _) = many0(tag(b"\x00"))(i)?;
    Ok((rem, ()))
}

fn parse_generic_option(i: &[u8]) -> IResult<&[u8], DHCPGenericOption> {
    let t = be_u8(i)?.1;
    let l = be_u8(i)?.1;
    let v = take(l)(i)?.1;

    Ok((i, DHCPGenericOption { t, l, v }))
}

fn convert_generic_option<'a>(
    i: &'a [u8],
    opt: DHCPGenericOption<'a>,
) -> IResult<&'a [u8], DHCPOption<'a>> {
    let opt = match opt.t {
        1 => {
            nom_err_return!(i, opt.l != 4, ErrorKind::LengthValue);
            let (_, addr) = parse_addr_v4(opt.v)?;
            DHCPOption::SubnetMask(addr)
        }
        50 => {
            nom_err_return!(i, opt.l != 4, ErrorKind::LengthValue);
            let (_, addr) = parse_addr_v4(opt.v)?;
            DHCPOption::RequestedIPAddress(addr)
        }
        51 => {
            nom_err_return!(i, opt.l != 4, ErrorKind::LengthValue);
            let (_, v) = be_u32(opt.v)?;
            DHCPOption::AddressLeaseTime(v)
        }
        52 => {
            nom_err_return!(i, opt.l != 1, ErrorKind::LengthValue);
            let (_, v) = be_u8(opt.v)?;
            DHCPOption::OptionOverload(v)
        }
        // TODO:: Add other options here
        59 => {
            nom_err_return!(i, opt.l != 4, ErrorKind::LengthValue);
            let (_, v) = be_u32(opt.v)?;
            DHCPOption::Rebinding(v)
        }
        60 => DHCPOption::ClassIdentifier(opt.v),
        61 => DHCPOption::ClientIdentifier(opt.v),
        255 => DHCPOption::End,
        _ => DHCPOption::Generic(opt),
    };
    Ok((i, opt))
}

fn parse_options(i: &[u8]) -> IResult<&[u8], Vec<DHCPOption>> {
    let mut acc = Vec::new();
    let mut i = i;
    loop {
        let (rem, opt) = parse_generic_option(i)?;
        let (rem, opt) = convert_generic_option(rem, opt)?;
        if let DHCPOption::End = opt {
            acc.push(opt);
            return Ok((rem, acc));
        }
        acc.push(opt);
        i = rem;
    }
}
