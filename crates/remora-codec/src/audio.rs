//! Sound: Opus encode (host) and decode (viewer), phase4.8-criteria.
//!
//! * 48 kHz stereo, 20 ms packets ([`FRAME`] samples per channel).
//! * The encoder uses libopus's restricted-low-delay mode: it removes the
//!   mode's 4 ms delay compensation (libopus 1.6.1 `src/opus_encoder.c`:
//!   `delay_compensation = Fs/250`, set to 0 for RESTRICTED_LOWDELAY at
//!   lines 1903–1904) and the speech-only SILK layer, which matters little
//!   at [`DEFAULT_BITRATE`].
//! * The decoder only ever sees packets that passed
//!   `remora_proto::audio::AudioPacket::parse` (A3). libopus is C code
//!   (bundled 1.6.1); this wrapper also refuses oversized input itself and
//!   never trusts a returned sample count beyond its own buffer.
//! * A lost packet is concealed by libopus (packet-loss concealment): call
//!   [`AudioDecoder::conceal`] instead of skipping the 20 ms.

use remora_proto::audio::MAX_OPUS_BYTES;

/// Samples per second.
pub const RATE: u32 = 48_000;
/// Channels (stereo, interleaved L R L R …).
pub const CHANNELS: usize = 2;
/// Samples per channel in one 20 ms packet.
pub const FRAME: usize = 960;
/// Default bitrate (spike S-A1: the owner heard 128 kbit/s as good).
pub const DEFAULT_BITRATE: u32 = 128_000;

/// An Opus error, without detail that could carry sound.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AudioCodecError {
    /// libopus refused (code from `opus::ErrorCode`, as text).
    #[error("opus: {0}")]
    Opus(String),
    /// The input was not one 20 ms stereo frame / was too large.
    #[error("wrong audio size")]
    Size,
}

fn opus_err(e: opus::Error) -> AudioCodecError {
    AudioCodecError::Opus(format!("{:?}", e.code()))
}

/// Encodes 20 ms stereo frames.
pub struct AudioEncoder {
    enc: opus::Encoder,
}

impl std::fmt::Debug for AudioEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AudioEncoder")
    }
}

impl AudioEncoder {
    /// An encoder at `bitrate` bits per second.
    pub fn new(bitrate: u32) -> Result<Self, AudioCodecError> {
        let mut enc = opus::Encoder::new(RATE, opus::Channels::Stereo, opus::Application::LowDelay)
            .map_err(opus_err)?;
        let bits = i32::try_from(bitrate).map_err(|_| AudioCodecError::Size)?;
        enc.set_bitrate(opus::Bitrate::Bits(bits))
            .map_err(opus_err)?;
        Ok(Self { enc })
    }

    /// One frame of `FRAME * CHANNELS` interleaved samples in -1..=1.
    pub fn encode(&mut self, pcm: &[f32]) -> Result<Vec<u8>, AudioCodecError> {
        if pcm.len() != FRAME * CHANNELS {
            return Err(AudioCodecError::Size);
        }
        let mut out = vec![0u8; MAX_OPUS_BYTES];
        let n = self.enc.encode_float(pcm, &mut out).map_err(opus_err)?;
        out.truncate(n.min(MAX_OPUS_BYTES));
        Ok(out)
    }
}

/// Decodes packets into 20 ms stereo frames.
pub struct AudioDecoder {
    dec: opus::Decoder,
}

impl std::fmt::Debug for AudioDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AudioDecoder")
    }
}

impl AudioDecoder {
    /// A decoder for 48 kHz stereo.
    pub fn new() -> Result<Self, AudioCodecError> {
        Ok(Self {
            dec: opus::Decoder::new(RATE, opus::Channels::Stereo).map_err(opus_err)?,
        })
    }

    /// Decodes one packet (already checked by the protocol parser) into
    /// interleaved samples; at most one 20 ms frame is kept.
    pub fn decode(&mut self, packet: &[u8]) -> Result<Vec<f32>, AudioCodecError> {
        if packet.is_empty() || packet.len() > MAX_OPUS_BYTES {
            return Err(AudioCodecError::Size);
        }
        self.run(packet)
    }

    /// 20 ms of concealment for a lost packet.
    pub fn conceal(&mut self) -> Result<Vec<f32>, AudioCodecError> {
        self.run(&[])
    }

    fn run(&mut self, packet: &[u8]) -> Result<Vec<f32>, AudioCodecError> {
        let mut out = vec![0f32; FRAME * CHANNELS];
        let n = self
            .dec
            .decode_float(packet, &mut out, false)
            .map_err(opus_err)?;
        out.truncate(n.saturating_mul(CHANNELS).min(FRAME * CHANNELS));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sine(hz: f32, frame: usize) -> Vec<f32> {
        (0..FRAME)
            .flat_map(|i| {
                let t = (frame * FRAME + i) as f32 / RATE as f32;
                let v = 0.5 * (2.0 * std::f32::consts::PI * hz * t).sin();
                [v, v]
            })
            .collect()
    }

    fn energy(s: &[f32]) -> f32 {
        s.iter().map(|x| x * x).sum::<f32>() / s.len() as f32
    }

    #[test]
    fn a_tone_survives_encode_and_decode() {
        let mut enc = AudioEncoder::new(DEFAULT_BITRATE).expect("enc");
        let mut dec = AudioDecoder::new().expect("dec");
        let mut last = Vec::new();
        for f in 0..10 {
            let pkt = enc.encode(&sine(440.0, f)).expect("encode");
            assert!(
                !pkt.is_empty() && pkt.len() <= MAX_OPUS_BYTES,
                "{}",
                pkt.len()
            );
            last = dec.decode(&pkt).expect("decode");
            assert_eq!(last.len(), FRAME * CHANNELS);
        }
        // A 0.5-amplitude sine has energy 0.125; allow codec loss.
        let e = energy(&last);
        assert!((0.08..0.17).contains(&e), "energy {e}");
    }

    #[test]
    fn wrong_sizes_are_refused_and_loss_is_concealed() {
        let mut enc = AudioEncoder::new(DEFAULT_BITRATE).expect("enc");
        assert_eq!(enc.encode(&[0.0; 10]), Err(AudioCodecError::Size));
        let mut dec = AudioDecoder::new().expect("dec");
        assert_eq!(dec.decode(&[]), Err(AudioCodecError::Size));
        assert_eq!(
            dec.decode(&vec![0; MAX_OPUS_BYTES + 1]),
            Err(AudioCodecError::Size)
        );
        assert_eq!(dec.conceal().expect("plc").len(), FRAME * CHANNELS);
        // Exactly the limit reaches libopus (which may refuse it as Opus
        // data, but not as too large).
        assert_ne!(
            dec.decode(&vec![0; MAX_OPUS_BYTES]),
            Err(AudioCodecError::Size)
        );
    }

    #[test]
    fn a4_codecs_print_only_their_name() {
        let enc = AudioEncoder::new(DEFAULT_BITRATE).expect("enc");
        let dec = AudioDecoder::new().expect("dec");
        assert_eq!(format!("{enc:?} {dec:?}"), "AudioEncoder AudioDecoder");
    }

    #[test]
    fn garbage_packets_never_panic() {
        let mut dec = AudioDecoder::new().expect("dec");
        for len in [1usize, 2, 3, 17, 255, MAX_OPUS_BYTES] {
            for seed in 0..32u8 {
                let pkt: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(seed)).collect();
                if let Ok(pcm) = dec.decode(&pkt) {
                    assert!(pcm.len() <= FRAME * CHANNELS);
                }
            }
        }
    }
}
