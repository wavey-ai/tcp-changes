//! Framing utilities for length-prefixed tagged messages.
//!
//! Wire format: [4 bytes length (big-endian)][4 bytes tag][data]
//! Length includes the tag (4 bytes) + data length.

use bytes::{Bytes, BytesMut, BufMut};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A framed message with a 4-byte tag and data payload.
#[derive(Debug, Clone)]
pub struct Frame {
    pub tag: [u8; 4],
    pub data: Bytes,
}

impl Frame {
    pub fn new(tag: [u8; 4], data: impl Into<Bytes>) -> Self {
        Self { tag, data: data.into() }
    }

    /// Check if tag matches a string (for convenience)
    pub fn tag_matches(&self, s: &[u8; 4]) -> bool {
        &self.tag == s
    }
}

/// Read a single framed message from a stream.
///
/// Returns `Ok(None)` on EOF, `Ok(Some(frame))` on success.
pub async fn read_frame<R: AsyncRead + Unpin>(stream: &mut R) -> io::Result<Option<Frame>> {
    // Read length prefix (4 bytes, big-endian)
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let frame_len = u32::from_be_bytes(len_buf) as usize;
    if frame_len < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Frame length must be at least 4 bytes for tag",
        ));
    }

    // Read tag (4 bytes)
    let mut tag = [0u8; 4];
    stream.read_exact(&mut tag).await?;

    // Read data (frame_len - 4 bytes)
    let data_len = frame_len - 4;
    let data = if data_len > 0 {
        let mut buf = vec![0u8; data_len];
        stream.read_exact(&mut buf).await?;
        Bytes::from(buf)
    } else {
        Bytes::new()
    };

    Ok(Some(Frame { tag, data }))
}

/// Write a single framed message to a stream.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    stream: &mut W,
    tag: &[u8; 4],
    data: &[u8],
) -> io::Result<()> {
    let frame_len = 4 + data.len(); // tag + data

    // Build the frame: [len][tag][data]
    let mut buf = BytesMut::with_capacity(4 + frame_len);
    buf.put_u32(frame_len as u32);
    buf.put_slice(tag);
    buf.put_slice(data);

    stream.write_all(&buf).await?;
    Ok(())
}

/// Write a frame and flush the stream.
pub async fn write_frame_flush<W: AsyncWrite + Unpin>(
    stream: &mut W,
    tag: &[u8; 4],
    data: &[u8],
) -> io::Result<()> {
    write_frame(stream, tag, data).await?;
    stream.flush().await?;
    Ok(())
}

/// Standard tags
pub mod tags {
    /// Decode request - client sends encoded audio
    pub const DCOD: &[u8; 4] = b"DCOD";
    /// PCM response - server sends decoded PCM chunk
    pub const PCMS: &[u8; 4] = b"PCMS";
    /// Done - signals end of stream
    pub const DONE: &[u8; 4] = b"DONE";
    /// Error - signals an error occurred
    pub const EROR: &[u8; 4] = b"EROR";
    /// Audio metadata (sample rate, channels, bits)
    pub const META: &[u8; 4] = b"META";
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    #[tokio::test]
    async fn test_frame_roundtrip() {
        let (mut client, mut server) = duplex(1024);

        // Write a frame
        write_frame(&mut client, b"TEST", b"hello world").await.unwrap();

        // Read it back
        let frame = read_frame(&mut server).await.unwrap().unwrap();
        assert_eq!(&frame.tag, b"TEST");
        assert_eq!(&frame.data[..], b"hello world");
    }

    #[tokio::test]
    async fn test_empty_data() {
        let (mut client, mut server) = duplex(1024);

        write_frame(&mut client, b"DONE", b"").await.unwrap();

        let frame = read_frame(&mut server).await.unwrap().unwrap();
        assert_eq!(&frame.tag, b"DONE");
        assert!(frame.data.is_empty());
    }

    #[tokio::test]
    async fn test_eof() {
        let (client, mut server) = duplex(1024);
        drop(client); // Close the write side

        let result = read_frame(&mut server).await.unwrap();
        assert!(result.is_none());
    }

    // =========================================================================
    // MP3-like streaming tests
    // =========================================================================

    /// Generate deterministic test data that can be verified
    fn generate_chunk(chunk_index: usize, size: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(size);
        // First 4 bytes: chunk index (for ordering verification)
        data.extend_from_slice(&(chunk_index as u32).to_be_bytes());
        // Fill rest with deterministic pattern based on index
        let mut hasher = DefaultHasher::new();
        chunk_index.hash(&mut hasher);
        let seed = hasher.finish();
        for i in 4..size {
            data.push(((seed.wrapping_add(i as u64)) & 0xFF) as u8);
        }
        data
    }

    /// Verify chunk data matches expected pattern
    fn verify_chunk(data: &[u8], expected_index: usize, expected_size: usize) -> bool {
        if data.len() != expected_size {
            return false;
        }
        if data.len() < 4 {
            return false;
        }
        // Check chunk index
        let index = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if index != expected_index {
            return false;
        }
        // Verify pattern
        let mut hasher = DefaultHasher::new();
        expected_index.hash(&mut hasher);
        let seed = hasher.finish();
        for i in 4..data.len() {
            let expected = ((seed.wrapping_add(i as u64)) & 0xFF) as u8;
            if data[i] != expected {
                return false;
            }
        }
        true
    }

    #[tokio::test]
    async fn test_multiple_chunks_in_order() {
        // Simulate sending multiple MP3 chunks and verify order
        let (mut client, mut server) = duplex(64 * 1024);

        const NUM_CHUNKS: usize = 10;
        const CHUNK_SIZE: usize = 4096;

        // Send all chunks
        for i in 0..NUM_CHUNKS {
            let data = generate_chunk(i, CHUNK_SIZE);
            write_frame(&mut client, tags::DCOD, &data).await.unwrap();
        }
        write_frame(&mut client, tags::DONE, &[]).await.unwrap();
        drop(client);

        // Receive and verify order
        let mut received_count = 0;
        loop {
            let frame = read_frame(&mut server).await.unwrap();
            match frame {
                Some(f) if f.tag_matches(tags::DCOD) => {
                    assert!(
                        verify_chunk(&f.data, received_count, CHUNK_SIZE),
                        "Chunk {} data mismatch or out of order",
                        received_count
                    );
                    received_count += 1;
                }
                Some(f) if f.tag_matches(tags::DONE) => {
                    break;
                }
                Some(f) => panic!("Unexpected tag: {:?}", f.tag),
                None => break,
            }
        }

        assert_eq!(received_count, NUM_CHUNKS, "Did not receive all chunks");
    }

    #[tokio::test]
    async fn test_rapid_small_chunks() {
        // Simulate rapid small chunk sending (like HTTP/3 behavior)
        let (mut client, mut server) = duplex(256 * 1024);

        const NUM_CHUNKS: usize = 100;
        const CHUNK_SIZE: usize = 1024; // 1KB chunks like HTTP/3

        // Send all chunks rapidly
        for i in 0..NUM_CHUNKS {
            let data = generate_chunk(i, CHUNK_SIZE);
            write_frame(&mut client, tags::DCOD, &data).await.unwrap();
        }
        write_frame(&mut client, tags::DONE, &[]).await.unwrap();
        drop(client);

        // Receive and verify
        let mut received_count = 0;
        let mut total_bytes = 0;
        loop {
            let frame = read_frame(&mut server).await.unwrap();
            match frame {
                Some(f) if f.tag_matches(tags::DCOD) => {
                    assert!(
                        verify_chunk(&f.data, received_count, CHUNK_SIZE),
                        "Chunk {} verification failed",
                        received_count
                    );
                    total_bytes += f.data.len();
                    received_count += 1;
                }
                Some(f) if f.tag_matches(tags::DONE) => break,
                Some(_) => panic!("Unexpected tag"),
                None => break,
            }
        }

        assert_eq!(received_count, NUM_CHUNKS);
        assert_eq!(total_bytes, NUM_CHUNKS * CHUNK_SIZE);
    }

    #[tokio::test]
    async fn test_variable_chunk_sizes() {
        // Test with variable chunk sizes like real MP3 frames
        let (mut client, mut server) = duplex(256 * 1024);

        let chunk_sizes = vec![417, 418, 417, 418, 417, 418, 1044, 1045, 522, 523];

        // Send chunks with varying sizes
        for (i, &size) in chunk_sizes.iter().enumerate() {
            let data = generate_chunk(i, size);
            write_frame(&mut client, tags::DCOD, &data).await.unwrap();
        }
        write_frame(&mut client, tags::DONE, &[]).await.unwrap();
        drop(client);

        // Receive and verify
        let mut received_count = 0;
        loop {
            let frame = read_frame(&mut server).await.unwrap();
            match frame {
                Some(f) if f.tag_matches(tags::DCOD) => {
                    let expected_size = chunk_sizes[received_count];
                    assert!(
                        verify_chunk(&f.data, received_count, expected_size),
                        "Chunk {} verification failed (expected size {})",
                        received_count,
                        expected_size
                    );
                    received_count += 1;
                }
                Some(f) if f.tag_matches(tags::DONE) => break,
                Some(_) => panic!("Unexpected tag"),
                None => break,
            }
        }

        assert_eq!(received_count, chunk_sizes.len());
    }

    #[tokio::test]
    async fn test_large_payload() {
        // Test with large payloads (simulating buffered audio data)
        let (mut client, mut server) = duplex(1024 * 1024);

        const PAYLOAD_SIZE: usize = 262144; // 256KB

        let data = generate_chunk(0, PAYLOAD_SIZE);
        write_frame(&mut client, tags::PCMS, &data).await.unwrap();
        drop(client);

        let frame = read_frame(&mut server).await.unwrap().unwrap();
        assert!(frame.tag_matches(tags::PCMS));
        assert!(verify_chunk(&frame.data, 0, PAYLOAD_SIZE));
    }

    #[tokio::test]
    async fn test_interleaved_tags() {
        // Test interleaved DCOD and PCMS (bidirectional simulation)
        let (mut client, mut server) = duplex(64 * 1024);

        // Send pattern: DCOD, DCOD, PCMS, DCOD, PCMS, DONE
        let sequence = vec![
            (tags::DCOD, 0, 1024),
            (tags::DCOD, 1, 1024),
            (tags::PCMS, 2, 2048),
            (tags::DCOD, 3, 1024),
            (tags::PCMS, 4, 4096),
        ];

        for (tag, idx, size) in &sequence {
            let data = generate_chunk(*idx, *size);
            write_frame(&mut client, tag, &data).await.unwrap();
        }
        write_frame(&mut client, tags::DONE, &[]).await.unwrap();
        drop(client);

        // Verify sequence
        for (expected_tag, expected_idx, expected_size) in &sequence {
            let frame = read_frame(&mut server).await.unwrap().unwrap();
            assert_eq!(&frame.tag, *expected_tag);
            assert!(
                verify_chunk(&frame.data, *expected_idx, *expected_size),
                "Frame {} verification failed",
                expected_idx
            );
        }

        let done = read_frame(&mut server).await.unwrap().unwrap();
        assert!(done.tag_matches(tags::DONE));
    }

    #[tokio::test]
    async fn test_concurrent_send_receive() {
        // Test concurrent sending and receiving (like real streaming)
        let (mut client, mut server) = duplex(64 * 1024);

        const NUM_CHUNKS: usize = 50;
        const CHUNK_SIZE: usize = 2048;

        // Spawn sender
        let sender = tokio::spawn(async move {
            for i in 0..NUM_CHUNKS {
                let data = generate_chunk(i, CHUNK_SIZE);
                write_frame(&mut client, tags::DCOD, &data).await.unwrap();
                // Small yield to simulate real-world timing
                if i % 10 == 0 {
                    tokio::task::yield_now().await;
                }
            }
            write_frame(&mut client, tags::DONE, &[]).await.unwrap();
        });

        // Receive concurrently
        let mut received = Vec::new();
        loop {
            let frame = read_frame(&mut server).await.unwrap();
            match frame {
                Some(f) if f.tag_matches(tags::DCOD) => {
                    received.push(f.data);
                }
                Some(f) if f.tag_matches(tags::DONE) => break,
                Some(_) => panic!("Unexpected tag"),
                None => break,
            }
        }

        sender.await.unwrap();

        // Verify all chunks received in order
        assert_eq!(received.len(), NUM_CHUNKS);
        for (i, data) in received.iter().enumerate() {
            assert!(
                verify_chunk(data, i, CHUNK_SIZE),
                "Chunk {} verification failed",
                i
            );
        }
    }

    #[tokio::test]
    async fn test_metadata_frame() {
        // Test META frame format (7 bytes: sample_rate + channels + bits + encoding)
        let (mut client, mut server) = duplex(1024);

        // Encode metadata: 16000 Hz, 1 channel, 16 bits, signed (0)
        let mut meta = [0u8; 7];
        meta[0..4].copy_from_slice(&16000u32.to_be_bytes());
        meta[4] = 1;  // channels
        meta[5] = 16; // bits
        meta[6] = 0;  // encoding (signed)

        write_frame(&mut client, tags::META, &meta).await.unwrap();
        drop(client);

        let frame = read_frame(&mut server).await.unwrap().unwrap();
        assert!(frame.tag_matches(tags::META));
        assert_eq!(frame.data.len(), 7);

        // Decode and verify
        let sample_rate = u32::from_be_bytes([frame.data[0], frame.data[1], frame.data[2], frame.data[3]]);
        assert_eq!(sample_rate, 16000);
        assert_eq!(frame.data[4], 1);  // channels
        assert_eq!(frame.data[5], 16); // bits
        assert_eq!(frame.data[6], 0);  // encoding
    }

    #[tokio::test]
    async fn test_simulated_mp3_decode_session() {
        // Full simulation of an MP3 decode session
        let (mut client, mut server) = duplex(256 * 1024);

        // Simulate 3 MP3 files concatenated (like the test_tcp_mp3_concatenation test)
        let file_chunks = vec![
            vec![4096, 4096, 4096, 2000],     // File 1: ~14KB
            vec![4096, 4096, 4096, 3000],     // File 2: ~15KB
            vec![4096, 4096, 4096, 4096, 1000], // File 3: ~17KB
        ];

        let mut chunk_index = 0;
        let mut expected_chunks = Vec::new();

        // Send all file chunks as continuous stream
        for file_chunk_sizes in &file_chunks {
            for &size in file_chunk_sizes {
                let data = generate_chunk(chunk_index, size);
                expected_chunks.push((chunk_index, size));
                write_frame(&mut client, tags::DCOD, &data).await.unwrap();
                chunk_index += 1;
            }
        }
        // Signal end
        write_frame(&mut client, tags::DCOD, &[]).await.unwrap();
        drop(client);

        // Receive and verify all chunks
        let mut received_index = 0;
        loop {
            let frame = read_frame(&mut server).await.unwrap();
            match frame {
                Some(f) if f.tag_matches(tags::DCOD) => {
                    if f.data.is_empty() {
                        // EOF signal
                        break;
                    }
                    let (expected_idx, expected_size) = expected_chunks[received_index];
                    assert!(
                        verify_chunk(&f.data, expected_idx, expected_size),
                        "Chunk {} verification failed",
                        received_index
                    );
                    received_index += 1;
                }
                Some(_) => panic!("Unexpected tag"),
                None => break,
            }
        }

        assert_eq!(received_index, expected_chunks.len(),
            "Expected {} chunks, received {}", expected_chunks.len(), received_index);
    }

    #[tokio::test]
    async fn test_checksum_integrity() {
        // Verify data integrity with checksums
        let (mut client, mut server) = duplex(128 * 1024);

        const NUM_CHUNKS: usize = 20;

        let mut sent_checksums = Vec::new();

        for i in 0..NUM_CHUNKS {
            // Variable sizes
            let size = 1024 + (i * 100);
            let data = generate_chunk(i, size);

            // Calculate checksum
            let mut hasher = DefaultHasher::new();
            data.hash(&mut hasher);
            sent_checksums.push((hasher.finish(), size));

            write_frame(&mut client, tags::DCOD, &data).await.unwrap();
        }
        write_frame(&mut client, tags::DONE, &[]).await.unwrap();
        drop(client);

        // Receive and verify checksums match
        let mut received_index = 0;
        loop {
            let frame = read_frame(&mut server).await.unwrap();
            match frame {
                Some(f) if f.tag_matches(tags::DCOD) => {
                    let mut hasher = DefaultHasher::new();
                    f.data.to_vec().hash(&mut hasher);
                    let received_checksum = hasher.finish();

                    let (expected_checksum, expected_size) = sent_checksums[received_index];
                    assert_eq!(f.data.len(), expected_size,
                        "Chunk {} size mismatch", received_index);
                    assert_eq!(received_checksum, expected_checksum,
                        "Chunk {} checksum mismatch", received_index);

                    received_index += 1;
                }
                Some(f) if f.tag_matches(tags::DONE) => break,
                Some(_) => panic!("Unexpected tag"),
                None => break,
            }
        }

        assert_eq!(received_index, NUM_CHUNKS);
    }
}
