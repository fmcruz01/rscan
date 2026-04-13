use std::fmt;

#[repr(C)]
pub struct UdpHeader<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub data: &'a [u8],
}

impl UdpHeader<'_> {
    pub const MIN_LEN: usize = 8;
    pub const HEADER: &'static str = "udp";

    pub fn parse(bytes: &[u8]) -> Result<UdpHeader<'_>, super::PacketError> {
        if bytes.len() < Self::MIN_LEN {
            return Err(super::PacketError::InvalidHeaderLength {
                header: Self::HEADER,
                min: Self::MIN_LEN,
                actual: bytes.len(),
            });
        }
        Ok(UdpHeader {
            src_port: u16::from_be_bytes(bytes[0..=1].try_into().map_err(|_| {
                super::PacketError::ErrorParsingHeaderFields {
                    header: Self::HEADER,
                    field: "source port",
                }
            })?),
            dst_port: u16::from_be_bytes(bytes[2..=3].try_into().map_err(|_| {
                super::PacketError::ErrorParsingHeaderFields {
                    header: Self::HEADER,
                    field: "destination port",
                }
            })?),
            data: &bytes[8..],
        })
    }
}

impl fmt::Display for UdpHeader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "UDP Header:\nSource Port: {}\nDestination Port: {}",
            self.src_port, self.dst_port
        )
    }
}
