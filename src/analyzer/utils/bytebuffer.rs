use std::borrow::Cow;
use std::{error::Error, str::from_utf8};

pub struct ByteBuffer {
    buf: Vec<u8>,
}

impl ByteBuffer {
    pub fn new() -> Self {
        ByteBuffer { buf: Vec::new() }
    }

    pub fn append(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn index(&self, sep: &[u8]) -> Option<usize> {
        self.buf.windows(sep.len()).position(|window| window == sep)
    }

    pub fn get(&mut self, len: usize, consume: bool) -> Option<Cow<[u8]>> {
        if self.buf.len() < len {
            return None;
        }
        let data = if consume {
            Cow::Owned(self.buf.drain(..len).collect())
        } else {
            Cow::Borrowed(&self.buf[..len])
        };

        Some(data)
    }
    pub fn get_string(&mut self, len: usize, consume: bool) -> Result<&str, Box<dyn Error>> {
        match self.get(len, consume) {
            Some(data) => {
                let string_data = from_utf8(data.as_ref())
                    .map_err(|err| err.into())
                    .and_then(|s| Ok(Cow::Borrowed(s)));
                Ok(string_data)
            }
            None => Err("Insufficient data".into()),
        }
    }

    pub fn get_u16(&mut self, little_endian: bool, consume: bool) -> Result<u16, Box<dyn Error>> {
        let data = match self.get(2, consume) {
            Some(data) => data,
            None => return Err("Insufficient data".into()),
        };

        let value = if little_endian {
            u16::from(data[0]) | (u16::from(data[1]) << 8)
        } else {
            u16::from(data[1]) | (u16::from(data[0]) << 8)
        };

        Ok(value)
    }

    pub fn get_u32(&mut self, little_endian: bool, consume: bool) -> Result<u32, Box<dyn Error>> {
        let data = match self.get(4, consume) {
            Some(data) => data,
            None => return Err("Insufficient data".into()),
        };

        let value = if little_endian {
            u32::from(data[0])
                | (u32::from(data[1]) << 8)
                | (u32::from(data[2]) << 16)
                | (u32::from(data[3]) << 24)
        } else {
            u32::from(data[3])
                | (u32::from(data[2]) << 8)
                | (u32::from(data[1]) << 16)
                | (u32::from(data[0]) << 24)
        };

        Ok(value)
    }

    pub fn get_until(&mut self, sep: &[u8], include_sep: bool, consume: bool) -> Option<Cow<[u8]>> {
        if let Some(idx) = self.index(sep) {
            let len = if include_sep { idx + sep.len() } else { idx };
            self.get(idx, consume)
        } else {
            None
        }
    }

    pub fn get_sub_buffer(&mut self, len: usize, consume: bool) -> ByteBuffer {
        ByteBuffer {
            buf: self.get(len, consume).unwrap().to_vec(),
        }
    }

    pub fn skip(&mut self, len: usize) -> bool {
        if self.buf.len() < len {
            return false;
        }
        self.buf.drain(..len);
        return true;
    }

    pub fn reset(&mut self) {
        self.buf.clear()
    }
}

pub fn byte_slices_to_strings(bss: Vec<Vec<u8>>) -> Vec<String> {
    bss.into_iter()
        .map(|bs| String::from_utf8(bs).unwrap())
        .collect()
}
