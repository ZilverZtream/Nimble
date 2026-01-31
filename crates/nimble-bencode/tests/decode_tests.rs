use nimble_bencode::{decode, DecodeError, Value};

#[test]
fn test_decode_integer_positive() {
    let result = decode(b"i42e").unwrap();
    assert_eq!(result.as_integer(), Some(42));
}

#[test]
fn test_decode_integer_negative() {
    let result = decode(b"i-42e").unwrap();
    assert_eq!(result.as_integer(), Some(-42));
}

#[test]
fn test_decode_integer_zero() {
    let result = decode(b"i0e").unwrap();
    assert_eq!(result.as_integer(), Some(0));
}

#[test]
fn test_decode_integer_leading_zero_rejected() {
    let result = decode(b"i042e");
    assert!(matches!(result, Err(DecodeError::InvalidFormat(_))));
}

#[test]
fn test_decode_integer_negative_zero_rejected() {
    let result = decode(b"i-0e");
    assert!(matches!(result, Err(DecodeError::InvalidFormat(_))));
}

#[test]
fn test_decode_integer_large() {
    let result = decode(b"i9223372036854775807e").unwrap();
    assert_eq!(result.as_integer(), Some(9223372036854775807));
}

#[test]
fn test_decode_byte_string_simple() {
    let result = decode(b"4:spam").unwrap();
    assert_eq!(result.as_bytes(), Some(b"spam".as_ref()));
    assert_eq!(result.as_str(), Some("spam"));
}

#[test]
fn test_decode_byte_string_empty() {
    let result = decode(b"0:").unwrap();
    assert_eq!(result.as_bytes(), Some(b"".as_ref()));
}

#[test]
fn test_decode_byte_string_binary() {
    let result = decode(b"5:\x00\x01\x02\x03\x04").unwrap();
    assert_eq!(result.as_bytes(), Some(b"\x00\x01\x02\x03\x04".as_ref()));
}

#[test]
fn test_decode_list_empty() {
    let result = decode(b"le").unwrap();
    assert_eq!(result.as_list(), Some(&[][..]));
}

#[test]
fn test_decode_list_simple() {
    let result = decode(b"l4:spam4:eggse").unwrap();
    let list = result.as_list().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].as_str(), Some("spam"));
    assert_eq!(list[1].as_str(), Some("eggs"));
}

#[test]
fn test_decode_list_mixed() {
    let result = decode(b"li42e4:spame").unwrap();
    let list = result.as_list().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].as_integer(), Some(42));
    assert_eq!(list[1].as_str(), Some("spam"));
}

#[test]
fn test_decode_list_nested() {
    let result = decode(b"ll4:spamee").unwrap();
    let outer = result.as_list().unwrap();
    assert_eq!(outer.len(), 1);
    let inner = outer[0].as_list().unwrap();
    assert_eq!(inner.len(), 1);
    assert_eq!(inner[0].as_str(), Some("spam"));
}

#[test]
fn test_decode_dict_empty() {
    let result = decode(b"de").unwrap();
    let dict = result.as_dict().unwrap();
    assert_eq!(dict.len(), 0);
}

#[test]
fn test_decode_dict_simple() {
    let result = decode(b"d3:cow3:moo4:spam4:eggse").unwrap();
    let dict = result.as_dict().unwrap();
    assert_eq!(dict.len(), 2);
    assert_eq!(
        dict.get(b"cow".as_ref()).and_then(|v| v.as_str()),
        Some("moo")
    );
    assert_eq!(
        dict.get(b"spam".as_ref()).and_then(|v| v.as_str()),
        Some("eggs")
    );
}

#[test]
fn test_decode_dict_helper_methods() {
    let result = decode(b"d3:cow3:moo4:spam4:eggse").unwrap();
    assert_eq!(result.dict_get_str("cow").and_then(|v| v.as_str()), Some("moo"));
    assert_eq!(result.dict_get_str("spam").and_then(|v| v.as_str()), Some("eggs"));
    assert_eq!(result.dict_get_str("missing"), None);
}

#[test]
fn test_decode_dict_unsorted_keys_rejected() {
    let result = decode(b"d4:spam4:eggs3:cow3:mooe");
    assert!(matches!(result, Err(DecodeError::InvalidFormat(_))));
}

#[test]
fn test_decode_dict_nested() {
    let result = decode(b"d4:spamd3:cow3:mooee").unwrap();
    let outer = result.as_dict().unwrap();
    assert_eq!(outer.len(), 1);
    let inner = outer.get(b"spam".as_ref()).unwrap().as_dict().unwrap();
    assert_eq!(
        inner.get(b"cow".as_ref()).and_then(|v| v.as_str()),
        Some("moo")
    );
}

#[test]
fn test_decode_nesting_depth_limit() {
    let mut deeply_nested = Vec::new();
    for _ in 0..50 {
        deeply_nested.push(b'l');
    }
    for _ in 0..50 {
        deeply_nested.push(b'e');
    }

    let result = decode(&deeply_nested);
    assert!(matches!(result, Err(DecodeError::NestingDepthExceeded)));
}

#[test]
fn test_decode_trailing_data_rejected() {
    let result = decode(b"i42eextra");
    assert!(matches!(result, Err(DecodeError::InvalidFormat(_))));
}

#[test]
fn test_decode_unexpected_eof() {
    assert!(matches!(decode(b"i42"), Err(DecodeError::UnexpectedEof)));
    assert!(matches!(decode(b"4:spa"), Err(DecodeError::UnexpectedEof)));
    assert!(matches!(decode(b"l"), Err(DecodeError::UnexpectedEof)));
    assert!(matches!(decode(b"d"), Err(DecodeError::UnexpectedEof)));
}

#[test]
fn test_decode_invalid_format() {
    assert!(matches!(decode(b"x42e"), Err(DecodeError::InvalidFormat(_))));
    assert!(matches!(decode(b"iabc"), Err(DecodeError::InvalidFormat(_))));
    assert!(matches!(decode(b":spam"), Err(DecodeError::InvalidFormat(_))));
}

#[test]
fn test_decode_torrent_like_structure() {
    let torrent = b"d8:announce21:http://example.com:804:infod6:lengthi1024e4:name8:test.txt12:piece lengthi262144e6:pieces20:\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13ee";

    let result = decode(torrent).unwrap();
    let dict = result.as_dict().unwrap();

    assert_eq!(
        dict.get(b"announce".as_ref()).and_then(|v| v.as_str()),
        Some("http://example.com:80")
    );

    let info = dict.get(b"info".as_ref()).unwrap().as_dict().unwrap();
    assert_eq!(
        info.get(b"name".as_ref()).and_then(|v| v.as_str()),
        Some("test.txt")
    );
    assert_eq!(
        info.get(b"length".as_ref()).and_then(|v| v.as_integer()),
        Some(1024)
    );
    assert_eq!(
        info.get(b"piece length".as_ref()).and_then(|v| v.as_integer()),
        Some(262144)
    );
    assert_eq!(
        info.get(b"pieces".as_ref()).and_then(|v| v.as_bytes()).map(|b| b.len()),
        Some(20)
    );
}

#[test]
fn test_string_length_cap() {
    let huge_len = (8 * 1024 * 1024 + 1).to_string();
    let mut input = huge_len.into_bytes();
    input.push(b':');

    let result = decode(&input);
    assert!(matches!(result, Err(DecodeError::StringLengthExceeded)));
}
