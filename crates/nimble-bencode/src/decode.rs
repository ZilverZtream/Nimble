// Placeholder: minimal bencode decoder with strict caps.
//
// Planned API:
//   - decode::Value<'a> (borrowed)
//   - decode::decode(input: &[u8]) -> Result<Value>
//   - zero-copy slices into the original buffer
