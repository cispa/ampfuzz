use crate::byte_count::AmpByteCount;
use crate::branches::BitmapHash;

#[derive(Debug, Clone, PartialEq)]
pub enum StatusType {
    Normal,
    Timeout,
    Crash,
    Skip,
    Error,
    Amp(BitmapHash, AmpByteCount),
}
