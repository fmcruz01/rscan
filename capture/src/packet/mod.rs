mod ethernet;
mod ipv4;
mod ipv6;
mod tcp;
mod udp;

use crate::packet::ethernet::EthernetHeader;
use crate::packet::udp::UdpHeader;
pub use ipv4::IPv4Header;
pub use ipv6::IPv6Header;
pub use tcp::TcpHeader;

pub struct ParsedPacket<'a> {
    ethernet: EthernetHeader<'a>,
    ip: IpHeader<'a>,
    transport: TransportHeader<'a>,
}

pub enum IpHeader<'a> {
    V4(IPv4Header<'a>),
    V6(IPv6Header<'a>),
}

pub enum TransportHeader<'a> {
    Tcp(TcpHeader<'a>),
    Udp(UdpHeader<'a>),
}

#[derive(Debug)]
pub enum Protocol {
    TCP,
    UDP,
}

impl<'a> IpHeader<'a> {
    pub fn get_packet_protocol(&self) -> &Protocol {
        match self {
            IpHeader::V4(h) => &h.protocol,
            IpHeader::V6(h) => &h.protocol,
        }
    }
    fn get_ip_data(&self) -> &'a [u8] {
        match self {
            IpHeader::V4(h) => h.data,
            IpHeader::V6(h) => h.data,
        }
    }
}

#[derive(Debug)]
pub enum PacketError {
    InvalidHeaderLength {
        header: &'static str,
        min: usize,
        actual: usize,
    },
    ErrorParsingHeaderFields {
        header: &'static str,
        field: &'static str,
    },
    UnsupportedFieldType {
        header: &'static str,
        field: String,
    },
}

pub fn parse_packet<'a>(bytes: &[u8]) -> Result<ParsedPacket<'_>, PacketError> {
    let eth = EthernetHeader::parse(bytes)?;
    let ip_header = match eth.ether_type {
        ethernet::EtherType::IPv4 => IpHeader::V4(IPv4Header::parse(eth.payload)?),
        ethernet::EtherType::IPv6 => IpHeader::V6(IPv6Header::parse(eth.payload)?),
    };

    let transport_header = match ip_header.get_packet_protocol() {
        Protocol::TCP => TransportHeader::Tcp(TcpHeader::parse(ip_header.get_ip_data())?),
        Protocol::UDP => TransportHeader::Udp(UdpHeader::parse(ip_header.get_ip_data())?),
    };

    Ok(ParsedPacket {
        ethernet: eth,
        ip: ip_header,
        transport: transport_header,
    })
}

impl std::fmt::Display for IpHeader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            IpHeader::V4(h) => write!(f, "{}", h),
            IpHeader::V6(h) => write!(f, "{}", h),
        }
    }
}

impl std::fmt::Display for TransportHeader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            TransportHeader::Tcp(h) => write!(f, "{}", h),
            TransportHeader::Udp(h) => write!(f, "{}", h),
        }
    }
}
impl std::fmt::Display for ParsedPacket<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "------------Packet-------------\n{}\n{}\n{}\n",
            self.ethernet, self.ip, self.transport
        )
    }
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PacketError::InvalidHeaderLength {
                header,
                min,
                actual,
            } => {
                write!(
                    f,
                    "Header {} has invalid length. Expected at least {} bytes, got {}.",
                    header, min, actual
                )
            }
            PacketError::ErrorParsingHeaderFields { header, field } => {
                write!(f, "Failed to parse header {} on field {}.", header, field)
            }
            PacketError::UnsupportedFieldType { header, field } => {
                write!(f, "{} type {} not yet supported.", header, field)
            }
        }
    }
}

impl std::error::Error for PacketError {}
