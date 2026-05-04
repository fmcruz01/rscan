use super::Protocol;
use std::fmt;

#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct IPv6Header<'a> {
    pub dst: [u16; 8],
    pub src: [u16; 8],
    pub ttl: u8,
    pub protocol: Protocol,
    pub data: &'a [u8],
}

impl IPv6Header<'_> {
    pub const MIN_LEN: usize = 40;
    pub const HEADER: &'static str = "ipv6";

    pub fn parse(bytes: &[u8]) -> Result<IPv6Header<'_>, super::PacketError> {
        if bytes.len() < Self::MIN_LEN {
            return Err(super::PacketError::InvalidHeaderLength {
                header: Self::HEADER,
                min: Self::MIN_LEN,
                actual: bytes.len(),
            });
        }
        let ihl: u16 = u16::from_be_bytes(bytes[4..=5].try_into().unwrap());
        Ok(IPv6Header {
            dst: std::array::from_fn(|i| {
                let offset = 24 + i * 2;
                u16::from_be_bytes(bytes[offset..=offset + 1].try_into().unwrap())
            }),
            src: std::array::from_fn(|i| {
                let offset = 8 + i * 2;
                u16::from_be_bytes(bytes[offset..=offset + 1].try_into().unwrap())
            }),
            protocol: match bytes[6] {
                6 => Protocol::TCP,
                17 => Protocol::UDP,
                other => {
                    return Err(super::PacketError::UnsupportedFieldType {
                        header: "protocol",
                        field: other.to_string(),
                    });
                }
            },
            ttl: bytes[7],
            data: if ihl == 40 { &[][..] } else { &bytes[40..] },
        })
    }
}

impl fmt::Display for IPv6Header<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "IPv6:\nDestination IP: {:X?}:{:X?}:{:X?}:{:X?}:{:X?}:{:X?}:{:X?}:{:X?}\nSource IP: {:X?}:{:X?}:{:X?}:{:X?}:{:X?}:{:X?}:{:X?}:{:X?}\nProtocol: {:?}\nTTL: {}\n",
            self.dst[0],
            self.dst[1],
            self.dst[2],
            self.dst[3],
            self.dst[4],
            self.dst[5],
            self.dst[6],
            self.dst[7],
            self.src[0],
            self.src[1],
            self.src[2],
            self.src[3],
            self.src[4],
            self.src[5],
            self.src[6],
            self.src[7],
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
    fn ipv6_header_parse_success() {
        let header: &[u8; _] = &[
            0x60, 0x00, 0x00, 0x00, 0x00, 0x28, 0x06, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
        ];
        let expected = IPv6Header {
            dst: [
                0x2001, 0x0DB8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0008,
            ],
            src: [
                0x2001, 0x0DB8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,
            ],
            ttl: 64,
            protocol: Protocol::TCP,
            data: &[][..],
        };
        assert_eq!(IPv6Header::parse(header), Ok(expected));
    }

    #[test]
    fn ipv6_header_min_length_fail() {
        let header: &[u8] = &[][..];
        let err = PacketError::InvalidHeaderLength {
            header: "ipv6",
            min: 40,
            actual: 0,
        };
        assert_eq!(IPv6Header::parse(header), Err(err));
    }

    #[test]
    fn ipv6_wrong_protocol_type() {
        let header: &[u8; _] = &[
            0x60, 0x00, 0x00, 0x00, 0x00, 0x28, 0x01, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
        ];
        let err = PacketError::UnsupportedFieldType {
            header: "protocol",
            field: String::from("1"),
        };
        assert_eq!(IPv6Header::parse(header), Err(err));
    }
}
