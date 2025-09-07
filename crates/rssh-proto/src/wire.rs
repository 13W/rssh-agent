use std::io::{self, Read, Write};

/// SSH agent message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    // Requests
    RequestIdentities = 11,
    SignRequest = 13,
    AddIdentity = 17,
    RemoveIdentity = 18,
    RemoveAllIdentities = 19,
    AddSmartcardKey = 20,
    RemoveSmartcardKey = 21,
    Lock = 22,
    Unlock = 23,
    AddIdConstrained = 25,
    Extension = 27,

    // Responses
    Failure = 5,
    Success = 6,
    IdentitiesAnswer = 12,
    SignResponse = 14,
    ExtensionFailure = 28,
}

impl MessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            5 => Some(Self::Failure),
            6 => Some(Self::Success),
            11 => Some(Self::RequestIdentities),
            12 => Some(Self::IdentitiesAnswer),
            13 => Some(Self::SignRequest),
            14 => Some(Self::SignResponse),
            17 => Some(Self::AddIdentity),
            18 => Some(Self::RemoveIdentity),
            19 => Some(Self::RemoveAllIdentities),
            20 => Some(Self::AddSmartcardKey),
            21 => Some(Self::RemoveSmartcardKey),
            22 => Some(Self::Lock),
            23 => Some(Self::Unlock),
            25 => Some(Self::AddIdConstrained),
            27 => Some(Self::Extension),
            28 => Some(Self::ExtensionFailure),
            _ => None,
        }
    }
}

/// SSH agent constraint types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constraint {
    Lifetime(u32),
    Confirm,
    Unknown(u8),
}

impl Constraint {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Lifetime(0), // Will be filled in
            2 => Self::Confirm,
            x => Self::Unknown(x),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            Self::Lifetime(_) => 1,
            Self::Confirm => 2,
            Self::Unknown(x) => *x,
        }
    }
}

/// Read a length-prefixed message from the stream
pub fn read_message<R: Read>(reader: &mut R, max_size: usize) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > max_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Message too large: {} > {}", len, max_size),
        ));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Write a length-prefixed message to the stream
pub fn write_message<W: Write>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(data)?;
    writer.flush()?;
    Ok(())
}

/// Read a string from the buffer (length-prefixed)
pub fn read_string(buf: &[u8], offset: &mut usize) -> Option<Vec<u8>> {
    if *offset + 4 > buf.len() {
        return None;
    }

    let len = u32::from_be_bytes([
        buf[*offset],
        buf[*offset + 1],
        buf[*offset + 2],
        buf[*offset + 3],
    ]) as usize;
    *offset += 4;

    if *offset + len > buf.len() {
        return None;
    }

    let data = buf[*offset..*offset + len].to_vec();
    *offset += len;
    Some(data)
}

/// Write a string to the buffer (length-prefixed)
pub fn write_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Read a u32 from the buffer
pub fn read_u32(buf: &[u8], offset: &mut usize) -> Option<u32> {
    if *offset + 4 > buf.len() {
        return None;
    }

    let value = u32::from_be_bytes([
        buf[*offset],
        buf[*offset + 1],
        buf[*offset + 2],
        buf[*offset + 3],
    ]);
    *offset += 4;
    Some(value)
}

/// Write a u32 to the buffer
pub fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

/// Read a u8 from the buffer
pub fn read_u8(buf: &[u8], offset: &mut usize) -> Option<u8> {
    if *offset >= buf.len() {
        return None;
    }

    let value = buf[*offset];
    *offset += 1;
    Some(value)
}

/// Write a u8 to the buffer
pub fn write_u8(buf: &mut Vec<u8>, value: u8) {
    buf.push(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_framing() {
        let data = b"test message";
        let mut buf = Vec::new();

        write_message(&mut buf, data).unwrap();
        assert_eq!(buf.len(), 4 + data.len());
        assert_eq!(&buf[0..4], &(data.len() as u32).to_be_bytes());
        assert_eq!(&buf[4..], data);

        let mut reader = &buf[..];
        let read_data = read_message(&mut reader, 1024).unwrap();
        assert_eq!(read_data, data);
    }

    #[test]
    fn test_message_too_large() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1000u32.to_be_bytes());

        let mut reader = &buf[..];
        let result = read_message(&mut reader, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_string_encoding() {
        let mut buf = Vec::new();
        let data = b"hello world";

        write_string(&mut buf, data);
        assert_eq!(buf.len(), 4 + data.len());

        let mut offset = 0;
        let read_data = read_string(&buf, &mut offset).unwrap();
        assert_eq!(read_data, data);
        assert_eq!(offset, buf.len());
    }

    #[test]
    fn test_u32_encoding() {
        let mut buf = Vec::new();
        let value = 0x12345678u32;

        write_u32(&mut buf, value);
        assert_eq!(buf.len(), 4);

        let mut offset = 0;
        let read_value = read_u32(&buf, &mut offset).unwrap();
        assert_eq!(read_value, value);
        assert_eq!(offset, 4);
    }
}
