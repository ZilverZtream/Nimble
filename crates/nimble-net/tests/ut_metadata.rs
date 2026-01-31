use nimble_net::ut_metadata::{
    verify_metadata_infohash, UtMetadataMessage, UtMetadataMessageType, UtMetadataState,
};
use nimble_util::hash::sha1;

#[test]
fn parse_data_message_and_assemble() {
    let payload = b"d8:msg_typei1e5:piecei0e10:total_sizei5eeabcde";
    let msg = UtMetadataMessage::parse(payload).unwrap();
    assert!(matches!(msg.msg_type, UtMetadataMessageType::Data));
    assert_eq!(msg.piece, 0);
    assert_eq!(msg.total_size, Some(5));
    assert_eq!(msg.data, b"abcde");

    let mut state = UtMetadataState::new(5).unwrap();
    let metadata = state.insert_piece(msg.piece, &msg.data).unwrap().unwrap();
    assert_eq!(metadata, b"abcde");
}

#[test]
fn request_message_round_trip() {
    let payload = UtMetadataMessage::build_request(3);
    let msg = UtMetadataMessage::parse(&payload).unwrap();
    assert!(matches!(msg.msg_type, UtMetadataMessageType::Request));
    assert_eq!(msg.piece, 3);
}

#[test]
fn metadata_size_cap_enforced() {
    let too_large = 2 * 1024 * 1024 + 1;
    assert!(UtMetadataState::new(too_large).is_err());
}

#[test]
fn metadata_infohash_is_verified() {
    let metadata = b"d4:name4:test6:lengthi4e12:piece lengthi4e6:pieces20:aaaaaaaaaaaaaaaaaaaae";
    let expected = sha1(metadata);

    assert!(verify_metadata_infohash(metadata, expected));

    let mut wrong = expected;
    wrong[0] ^= 0xFF;
    assert!(!verify_metadata_infohash(metadata, wrong));
}
