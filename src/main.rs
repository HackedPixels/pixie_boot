mod dhcp;

fn main() {
    static DHCP_DISCOVER: &'static [u8] = include_bytes!("../assets/dhcp-discover.bin");
    let res = dhcp::parser::parse_dhcp_message(DHCP_DISCOVER);
    println!("res {:?}", res);
    let (_, msg) = res.expect("Parsed message");
    //    println!("sname: {:?}", msg.server_name());
    //    println!("chaddr: {:?}", msg.hw_addr());
}
