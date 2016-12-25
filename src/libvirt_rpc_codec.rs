use tokio_core::io;
use tokio_core::io::Codec;
use xdr::xdr::XdrReader;
use std;

pub struct LibvirtCodec;

// https://libvirt.org/internals/rpc.html#protocol
pub struct Packet {
    len: u32,
    header: Header,
    body: Payload,
}


struct Header {
    program: u32,
    version: u32,
    procedure: i32,
    type_: i32,
    serial: u32,
    status: i32,
}

enum Payload {
    Call(Call),
}

// Since XdrPrimitive is unsized, we spell out all the variants here.
// Ideally, I'd just do 'Vec<XdrPrimitive>' as the payload, but yeah, unsized!
// If there's a nicer solution to this (I guess I could do Vec<Box<XdrType>>?; feels icky) then let
// me know!
// Listing everything out isn't too icky though, so *shrug
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

struct Call {
    params: Vec<XdrType>,
}


impl Codec for LibvirtCodec {
    type In = Packet;
    type Out = Packet;

    fn decode(&mut self, buf: &mut io::EasyBuf) -> Result<Option<Packet>, std::io::Error> {
        if buf.len() < 4 {
            // Need to read at least 4 bytes; the 'len' of the packet
            return Ok(None);
        }

        let mutbuf = buf.get_mut();

        let mut reader = XdrReader::new(&mutbuf);
        let len = match reader.unpack::<u32>() {
            Ok(x) => x,
            Err(err) => {
                Err(std::io::Error::new(std::io::ErrorKind::Other,
                                               format!("error unpacking length: {}", err)))?
            }
        };

        if len == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "wtf"));
        }

        let body = Payload::Call(Call { params: Vec::new() });

        Ok(Some(Packet {
            len: len,
            header: Header {
                program: 0,
                version: 0,
                procedure: 0,
                type_: 0,
                serial: 0,
                status: 0,
            },
            body: body,
        }))
    }

    fn encode(&mut self, msg: Packet, buf: &mut Vec<u8>) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
    fn decode_length() {
        // The trivial packet is a 4 byte packet that says its length is 4
        let mut codec = super::LibvirtCodec;
        let buf = vec![0, 0, 0, 4];
        let mut buf = EasyBuf::from(buf);
        let packet = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(packet.len, 4);
    }
}
