use std::fmt;

#[repr(C)]
#[derive(Debug)]
pub(super) struct EthernetHeader<'a> {
    pub(super) dst: [u8; 6],
    pub(super) src: [u8; 6],
    pub(super) ether_type: EtherType,
    pub(super) payload: &'a [u8],
}
#[derive(Debug)]
pub enum EtherType {
    IPv4,
    IPv6,
}

impl EthernetHeader<'_> {
    const MIN_LEN: usize = 14;
    const HEADER: &'static str = "eth";

    pub(super) fn parse(bytes: &[u8]) -> Result<EthernetHeader<'_>, super::PacketError> {
        if bytes.len() < Self::MIN_LEN {
            return Err(super::PacketError::InvalidHeaderLength {
                header: Self::HEADER,
                min: Self::MIN_LEN,
                actual: bytes.len(),
            });
        }
        Ok(EthernetHeader {
            dst: bytes[0..=5].try_into().map_err(|_| {
                super::PacketError::ErrorParsingHeaderFields {
                    header: Self::HEADER,
                    field: "destination MAC address",
                }
            })?,
            src: bytes[6..=11].try_into().map_err(|_| {
                super::PacketError::ErrorParsingHeaderFields {
                    header: Self::HEADER,
                    field: "source MAC address",
                }
            })?,
            ether_type: match ((bytes[12] as u16) << 8) + bytes[13] as u16 {
                0x0800 => EtherType::IPv4,
                0x86DD => EtherType::IPv6,
                other => {
                    return Err(super::PacketError::UnsupportedFieldType {
                        header: "ip",
                        field: other.to_string(),
                    });
                }
            },
            payload: &bytes[14..],
        })
    }
}

impl fmt::Display for EthernetHeader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "EthHeader:\nDestination MAC: {:X?}:{:X?}:{:X?}:{:X?}:{:X?}:{:X?}\nSource MAC: {:X?}:{:X?}:{:X?}:{:X?}:{:X?}:{:X?}\nEthernet Type: {:?}\n",
            self.dst[0],
            self.dst[1],
            self.dst[2],
            self.dst[3],
            self.dst[4],
            self.dst[5],
            self.src[0],
            self.src[1],
            self.src[2],
            self.src[3],
            self.src[4],
            self.src[5],
            self.ether_type
        )
    }
}
