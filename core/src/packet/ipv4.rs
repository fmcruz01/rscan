use super::Protocol;
use std::fmt;

#[repr(C)]
pub struct IPv4Header<'a> {
    pub dst: [u8; 4],
    pub src: [u8; 4],
    pub ttl: u8,
    pub protocol: Protocol,
    pub data: &'a [u8],
}

impl IPv4Header<'_> {
    pub const MIN_LEN: usize = 20;
    pub const HEADER: &'static str = "ipv4";

    pub fn parse(bytes: &[u8]) -> Result<IPv4Header<'_>, super::PacketError> {
        if bytes.len() < Self::MIN_LEN {
            return Err(super::PacketError::InvalidHeaderLength {
                header: Self::HEADER,
                min: Self::MIN_LEN,
                actual: bytes.len(),
            });
        }
        Ok(IPv4Header {
            dst: bytes[16..=19].try_into().map_err(|_| {
                super::PacketError::ErrorParsingHeaderFields {
                    header: Self::HEADER,
                    field: "destination IP address",
                }
            })?,
            src: bytes[12..=15].try_into().map_err(|_| {
                super::PacketError::ErrorParsingHeaderFields {
                    header: Self::HEADER,
                    field: "source IP address",
                }
            })?,

            protocol: match bytes[9] {
                6 => Protocol::TCP,
                17 => Protocol::UDP,
                other => {
                    return Err(super::PacketError::UnsupportedFieldType {
                        header: "protocol",
                        field: other.to_string(),
                    });
                }
            },
            ttl: bytes[8],
            data: &bytes[24..],
        })
    }
}

impl fmt::Display for IPv4Header<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "IPv4:\nDestination IP: {}.{}.{}.{}\nSource IP: {}.{}.{}.{}\nProtocol: {:?}\nTTL: {}\n",
            self.dst[0],
            self.dst[1],
            self.dst[2],
            self.dst[3],
            self.src[0],
            self.src[1],
            self.src[2],
            self.src[3],
            self.protocol,
            self.ttl
        )
    }
}
