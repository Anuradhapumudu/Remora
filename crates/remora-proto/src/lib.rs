//! Remora wire protocol (docs/protocol.md): length-prefixed frames, protobuf
//! messages, connection codes and the clear media-datagram header.
//!
//! Every parser here receives attacker-controlled bytes. Each one checks its
//! size limit **before** allocating anything proportional to the input
//! (threat model INV7, phase3-criteria A26) and never panics (A27 fuzzing).

#![forbid(unsafe_code)]

pub mod code;
mod crc32;
pub mod datagram;
pub mod frame;
pub mod limits;
pub mod messages;
