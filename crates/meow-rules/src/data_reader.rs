//! Bounded borrowed reader for sing-box's varbin containers.

pub(crate) const MAX_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_ITEMS: usize = 1_000_000;
pub(crate) const MAX_RULES: usize = 16_384;
pub(crate) const MAX_DEPTH: usize = 32;

pub(crate) struct DataReader<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> DataReader<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, String> {
        if data.len() > MAX_BYTES {
            return Err("data exceeds 64 MiB".into());
        }
        Ok(Self { data, pos: 0 })
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.data.len())
            .ok_or("truncated sing-box data")?;
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }
    pub fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    pub fn boolean(&mut self) -> Result<bool, String> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("invalid boolean".into()),
        }
    }
    pub fn varint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let b = self.byte()?;
            if shift == 63 && b > 1 {
                return Err("varint overflow".into());
            }
            value |= u64::from(b & 127) << shift;
            if b & 128 == 0 {
                return Ok(value);
            }
        }
        Err("varint overflow".into())
    }
    pub fn count(&mut self, max: usize) -> Result<usize, String> {
        let n = usize::try_from(self.varint()?).map_err(|_| "count overflow")?;
        if n > max {
            return Err("sing-box item count exceeds limit".into());
        }
        Ok(n)
    }
    pub fn u64_be(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| "truncated u64")?,
        ))
    }
    pub fn string(&mut self) -> Result<&'a str, String> {
        let len = self.count(16 * 1024)?;
        std::str::from_utf8(self.take(len)?).map_err(|_| "invalid UTF-8".into())
    }
    pub fn finish(&self) -> Result<(), String> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err("trailing sing-box data".into())
        }
    }
}
