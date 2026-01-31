use nimble_net::ut_metadata::{UtMetadataMessage, UtMetadataMessageType, UtMetadataState};

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
