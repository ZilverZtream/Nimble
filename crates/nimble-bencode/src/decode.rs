use std::collections::BTreeMap;
use thiserror::Error;

const MAX_INPUT_SIZE: usize = 128 * 1024 * 1024;
const MAX_NESTING_DEPTH: usize = 32;
const MAX_STRING_LENGTH: usize = 64 * 1024 * 1024;
const MAX_DICT_KEY_LENGTH: usize = 256;
const MAX_INTEGER_DIGITS: usize = 20;

#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("unexpected end of input")]
    UnexpectedEof,
    #[error("invalid bencode format: {0}")]
    InvalidFormat(String),
    #[error("nesting depth exceeded (max {MAX_NESTING_DEPTH})")]
    NestingDepthExceeded,
    #[error("input size exceeded (max {MAX_INPUT_SIZE})")]
    InputSizeExceeded,
    #[error("string length exceeded (max {MAX_STRING_LENGTH})")]
    StringLengthExceeded,
    #[error("integer too large")]
    IntegerTooLarge,
}

pub type Result<T> = std::result::Result<T, DecodeError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value<'a> {
    Integer(i64),
    ByteString(&'a [u8]),
    List(Vec<Value<'a>>),
    Dict(BTreeMap<&'a [u8], Value<'a>>),
}

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8]) -> Result<Self> {
        if input.len() > MAX_INPUT_SIZE {
            return Err(DecodeError::InputSizeExceeded);
        }
        Ok(Decoder {
            input,
            pos: 0,
            depth: 0,
        })
    }

    fn peek(&self) -> Result<u8> {
        self.input
            .get(self.pos)
            .copied()
            .ok_or(DecodeError::UnexpectedEof)
    }

    fn consume(&mut self) -> Result<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Ok(byte)
    }

    fn expect(&mut self, expected: u8) -> Result<()> {
        let byte = self.consume()?;
        if byte != expected {
            return Err(DecodeError::InvalidFormat(format!(
                "expected '{}', got '{}'",
                expected as char, byte as char
            )));
        }
        Ok(())
    }

    fn decode_value(&mut self) -> Result<Value<'a>> {
        if self.depth >= MAX_NESTING_DEPTH {
            return Err(DecodeError::NestingDepthExceeded);
        }

        let byte = self.peek()?;
        match byte {
            b'i' => self.decode_integer(),
            b'l' => self.decode_list(),
            b'd' => self.decode_dict(),
            b'0'..=b'9' => self.decode_byte_string(),
            _ => Err(DecodeError::InvalidFormat(format!(
                "unexpected byte: {}",
                byte as char
            ))),
        }
    }

    fn decode_integer(&mut self) -> Result<Value<'a>> {
        self.expect(b'i')?;

        let negative = if self.peek()? == b'-' {
            self.consume()?;
            true
        } else {
            false
        };

        let start = self.pos;
        let mut has_digits = false;

        while self.pos < self.input.len() && self.input[self.pos] != b'e' {
            if !self.input[self.pos].is_ascii_digit() {
                return Err(DecodeError::InvalidFormat(
                    "invalid integer character".to_string(),
                ));
            }
            has_digits = true;
            self.pos += 1;

            if self.pos - start > MAX_INTEGER_DIGITS {
                return Err(DecodeError::IntegerTooLarge);
            }
        }

        if !has_digits {
            return Err(DecodeError::InvalidFormat("empty integer".to_string()));
        }

        let num_bytes = &self.input[start..self.pos];
        let num_str = std::str::from_utf8(num_bytes)
            .map_err(|_| DecodeError::InvalidFormat("invalid integer UTF-8".to_string()))?;

        if num_str.len() > 1 && num_str.starts_with('0') {
            return Err(DecodeError::InvalidFormat(
                "leading zeros not allowed".to_string(),
            ));
        }

        if negative && num_str == "0" {
            return Err(DecodeError::InvalidFormat("negative zero".to_string()));
        }

        let mut value: i64 = num_str
            .parse()
            .map_err(|_| DecodeError::IntegerTooLarge)?;

        if negative {
            value = -value;
        }

        self.expect(b'e')?;
        Ok(Value::Integer(value))
    }

    fn decode_byte_string(&mut self) -> Result<Value<'a>> {
        let start = self.pos;

        while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
            self.pos += 1;
        }

        if start == self.pos {
            return Err(DecodeError::InvalidFormat(
                "missing string length".to_string(),
            ));
        }

        let len_bytes = &self.input[start..self.pos];
        let len_str = std::str::from_utf8(len_bytes)
            .map_err(|_| DecodeError::InvalidFormat("invalid length UTF-8".to_string()))?;

        let length: usize = len_str
            .parse()
            .map_err(|_| DecodeError::InvalidFormat("invalid length".to_string()))?;

        if length > MAX_STRING_LENGTH {
            return Err(DecodeError::StringLengthExceeded);
        }

        self.expect(b':')?;

        if self.pos + length > self.input.len() {
            return Err(DecodeError::UnexpectedEof);
        }

        let bytes = &self.input[self.pos..self.pos + length];
        self.pos += length;

        Ok(Value::ByteString(bytes))
    }

    fn decode_list(&mut self) -> Result<Value<'a>> {
        self.expect(b'l')?;
        self.depth += 1;

        let mut list = Vec::new();

        while self.peek()? != b'e' {
            list.push(self.decode_value()?);
        }

        self.expect(b'e')?;
        self.depth -= 1;

        Ok(Value::List(list))
    }

    fn decode_dict_key(&mut self, prev_key: Option<&[u8]>) -> Result<&'a [u8]> {
        let start = self.pos;

        while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
            self.pos += 1;
        }

        if start == self.pos {
            return Err(DecodeError::InvalidFormat(
                "missing string length".to_string(),
            ));
        }

        let len_bytes = &self.input[start..self.pos];
        let len_str = std::str::from_utf8(len_bytes)
            .map_err(|_| DecodeError::InvalidFormat("invalid length UTF-8".to_string()))?;

        let length: usize = len_str
            .parse()
            .map_err(|_| DecodeError::InvalidFormat("invalid length".to_string()))?;

        if length > MAX_DICT_KEY_LENGTH {
            return Err(DecodeError::InvalidFormat(
                format!("dictionary key too large: {} bytes (max {})", length, MAX_DICT_KEY_LENGTH),
            ));
        }

        self.expect(b':')?;

        if self.pos + length > self.input.len() {
            return Err(DecodeError::UnexpectedEof);
        }

        let bytes = &self.input[self.pos..self.pos + length];

        if let Some(prev) = prev_key {
            if bytes <= prev {
                return Err(DecodeError::InvalidFormat(
                    "dictionary keys must be sorted".to_string(),
                ));
            }
        }

        self.pos += length;
        Ok(bytes)
    }

    fn decode_dict(&mut self) -> Result<Value<'a>> {
        self.expect(b'd')?;
        self.depth += 1;

        let mut dict = BTreeMap::new();
        let mut last_key: Option<&[u8]> = None;

        while self.peek()? != b'e' {
            let key = self.decode_dict_key(last_key)?;
            last_key = Some(key);

            let value = self.decode_value()?;
            dict.insert(key, value);
        }

        self.expect(b'e')?;
        self.depth -= 1;

        Ok(Value::Dict(dict))
    }
}

pub fn decode(input: &[u8]) -> Result<Value> {
    let mut decoder = Decoder::new(input)?;
    let value = decoder.decode_value()?;

    if decoder.pos != decoder.input.len() {
        return Err(DecodeError::InvalidFormat(
            "trailing data after value".to_string(),
        ));
    }

    Ok(value)
}

pub fn decode_prefix(input: &[u8]) -> Result<(Value, usize)> {
    let mut decoder = Decoder::new(input)?;
    let value = decoder.decode_value()?;
    Ok((value, decoder.pos))
}

impl<'a> Value<'a> {
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&'a [u8]> {
        match self {
            Value::ByteString(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&'a str> {
        self.as_bytes().and_then(|b| std::str::from_utf8(b).ok())
    }

    pub fn as_list(&self) -> Option<&[Value<'a>]> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&BTreeMap<&'a [u8], Value<'a>>> {
        match self {
            Value::Dict(d) => Some(d),
            _ => None,
        }
    }

    pub fn dict_get(&self, key: &[u8]) -> Option<&Value<'a>> {
        self.as_dict().and_then(|d| d.get(key))
    }

    pub fn dict_get_str(&self, key: &str) -> Option<&Value<'a>> {
        self.dict_get(key.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_prefix_allows_trailing_data() {
        let payload = b"d3:foo3:barextra";
        let (value, consumed) = decode_prefix(payload).unwrap();
        let dict = value.as_dict().unwrap();
        assert_eq!(dict.get(b"foo".as_ref()).unwrap().as_str(), Some("bar"));
        assert_eq!(consumed, 12);
        assert_eq!(&payload[consumed..], b"xtra");
    }
}
