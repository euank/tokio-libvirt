use tokio_core::io;
use tokio_core::io::Codec;
use xdr::xdr;
use xdr::xdr::XdrReader;
use std;

pub struct LibvirtCodec;

// https://libvirt.org/internals/rpc.html#protocol
#[derive(PartialEq, Debug)]
pub struct Packet {
    len: u32,
    header: Header,
    body: Payload,
}

#[derive(PartialEq, Debug)]
struct Header {
    program: u32,
    version: u32,
    procedure: i32,
    type_: i32,
    serial: u32,
    status: i32,
}

#[derive(PartialEq, Debug)]
enum Payload {
    Call(Call),
}

// Since XdrPrimitive is unsized, we spell out all the variants here.
// Ideally, I'd just do 'Vec<XdrPrimitive>' as the payload, but yeah, unsized!
// If there's a nicer solution to this (I guess I could do Vec<Box<XdrType>>?; feels icky) then let
// me know!
// Listing everything out isn't too icky though, so *shrug
#[derive(PartialEq, Debug)]
enum XdrType {
    Vec(Vec<XdrType>),
    Bool(bool),
    F32(f32),
    F64(f64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    String(String),
}

#[derive(PartialEq, Debug)]
struct Call {
    params: Vec<XdrType>,
}

enum Error {
    Io(std::io::Error),
}

impl From<xdr::Error> for Error {
    fn from(err: xdr::Error) -> Self {
        match err {
            xdr::Error::Io(err) => Error::Io(err),
            xdr::Error::InvalidValue => {
                Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid xdr value"))
            }
            xdr::Error::InvalidType => {
                Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid xdr type"))
            }
        }
    }
}

impl From<Error> for std::io::Error {
    fn from(err: Error) -> Self {
        // There has to be a better way...
        let Error::Io(e) = err;
        e
    }
}

fn parse_header(reader: &mut XdrReader) -> Result<Header, Error> {
    Ok(Header {
        program: reader.unpack::<u32>()?,
        version: reader.unpack::<u32>()?,
        procedure: reader.unpack::<i32>()?,
        type_: reader.unpack::<i32>()?,
        serial: reader.unpack::<u32>()?,
        status: reader.unpack::<i32>()?,
    })
}

// https://github.com/libvirt/libvirt/blob/866641d4c5706413393913fdb3bb1cd077683d21/src/remote/remote_protocol.x#L3358-L3360
const LIBVIRT_PROGRAM: u32 = 0x20008086;
const LIBVIRT_PROTO_VERSION: u32 = 1;

// Call params depend totally on the header's program+version
fn parse_call_body(reader: &mut XdrReader, header: &Header) -> Result<Payload, Error> {
    let mut params: Vec<XdrType> = Vec::new();

    if header.program != LIBVIRT_PROGRAM || header.version != LIBVIRT_PROTO_VERSION {
        Err(Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid program; not recognized as libvirt")))?
    }

    if header.procedure == 4 {
        // Get version
        params.push(XdrType::U64(reader.unpack::<u64>()?));
    }

    Ok(Payload::Call(Call { params: params }))
}


impl Codec for LibvirtCodec {
    type In = Packet;
    type Out = Packet;

    fn decode(&mut self, buf: &mut io::EasyBuf) -> Result<Option<Packet>, std::io::Error> {
        if buf.len() < 4 {
            // Need to read at least 4 bytes; the 'len' of the packet
            return Ok(None);
        }

        let len = {
            // scope this mut borrow down so we can do it again when we drain
            let len_data = Vec::from(&buf.as_slice()[0..4]);
            let mut length_reader = XdrReader::new(&len_data);
            match length_reader.unpack::<u32>() {
                Ok(x) => x,
                Err(err) => {
                    Err(std::io::Error::new(std::io::ErrorKind::Other,
                                            format!("error unpacking length: {}", err)))?
                }
            }
        };

        // We need to wait on more data before we can decode this
        if buf.len() < len as usize {
            return Ok(None);
        }


        if len < 7 * 4 {
            // length = 1 u32, header = 6 u32, 7 u32 total
            // if the header is missing, this is a malformed packet. nothing we can do
            Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                                    "too short buffer to be an rpc call; must have header + \
                                     length"))?;
        }

        let mut remaining_bytes = buf.drain_to(len as usize);
        // Skip the length since we already read it above
        let mut remaining_bytes = remaining_bytes.split_off(4);
        let bufmut = remaining_bytes.get_mut();

        let mut reader = XdrReader::new(&bufmut);
        let header = parse_header(&mut reader)?;
        let body = match header.type_ {
            0 => parse_call_body(&mut reader, &header)?,
            _ => Err(std::io::Error::new(std::io::ErrorKind::Other, "TODO"))?,
        };

        Ok(Some(Packet {
            len: len,
            header: header,
            body: body,
        }))
    }

    fn encode(&mut self, msg: Packet, buf: &mut Vec<u8>) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use xdr::xdr::XdrWriter;
    use tokio_core::io::Codec;
    use tokio_core::io::EasyBuf;
    use std;
    #[test]
    fn it_retries_under_4_bytes() {
        // Any packet under 4 bytes cannot be read because we need at least the length bit
        let mut codec = super::LibvirtCodec;
        for i in 1..3 {
            let bytes = std::iter::repeat(10).take(i).collect::<Vec<_>>();
            let mut buf = EasyBuf::from(bytes);
            let packet = codec.decode(&mut buf).unwrap();
            assert!(packet.is_none());
        }
    }

    #[test]
    fn decode_version_call() {
        let mut wr = XdrWriter::new();
        wr.pack(36 as u32); // len
        wr.pack(super::LIBVIRT_PROGRAM); // program
        wr.pack(super::LIBVIRT_PROTO_VERSION); // version
        wr.pack(4 as i32); // procedure 'version'
        wr.pack(0 as i32); // type
        wr.pack(1 as u32); // serial
        wr.pack(0 as i32); // status
        // return value
        wr.pack(1 as u64);
        let buf = wr.into_buffer();

        let mut codec = super::LibvirtCodec;
        let mut buf = EasyBuf::from(buf);

        let packet = codec.decode(&mut buf).unwrap().unwrap();
        let expected_packet = super::Packet {
            len: 36,
            header: super::Header {
                program: super::LIBVIRT_PROGRAM,
                version: super::LIBVIRT_PROTO_VERSION,
                procedure: 4,
                type_: 0,
                serial: 1,
                status: 0,
            },
            body: super::Payload::Call(super::Call {
                params: vec![super::XdrType::U64(1)],
            }),
        };
        assert_eq!(expected_packet, packet);
    }
}
