use super::Protocol;
use std::fmt;

#[repr(C)]
#[derive(Debug, PartialEq)]
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
        let ihl = ((bytes[0] - 40) * 4) as usize;
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
            data: &bytes[ihl..],
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketError;

    #[test]
    fn ipv4_header_parse_success() {
        // 45 00 00 3C 1C 46 40 00 40 06 B1 E6 AC 10 0A 02 AC 10 0A 04
        let header: &[u8; _] = &[
            45, 0, 0, 60, 28, 70, 64, 0, 64, 6, 177, 230, 172, 16, 10, 2, 172, 16, 10, 4,
        ];
        let expected = IPv4Header {
            dst: [172, 16, 10, 4],
            src: [172, 16, 10, 2],
            ttl: 64,
            protocol: Protocol::TCP,
            data: &[][..],
        };
        assert_eq!(IPv4Header::parse(header), Ok(expected));
    }

    #[test]
    fn ipv4_header_min_length_fail() {
        let header: &[u8; _] = &[
            45, 0, 0, 60, 28, 70, 64, 0, 64, 6, 177, 230, 172, 16, 10, 2, 172, 16, 10,
        ];
        let err = PacketError::InvalidHeaderLength {
            header: "ipv4",
            min: 20,
            actual: 19,
        };
        assert_eq!(IPv4Header::parse(header), Err(err));
    }

    #[test]
    fn ipv4_wrong_protocol_type() {
        // 00 1A 2B 3C 4D 5E 00 5E 4D 3C 2B 1A 08 00
        let header: &[u8; _] = &[
            45, 0, 0, 60, 28, 70, 64, 0, 64, 1, 177, 230, 172, 16, 10, 2, 172, 16, 10, 4,
        ];
        let err = PacketError::UnsupportedFieldType {
            header: "protocol",
            field: String::from("1"),
        };
        assert_eq!(IPv4Header::parse(header), Err(err));
    }
}
