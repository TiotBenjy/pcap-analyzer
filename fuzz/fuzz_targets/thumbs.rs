//! Thumbnails of extracted objects (`netsift_engine::thumbs::render`: PNG, JPEG, GIF, WebP,
//! BMP, ICO decoders of `image`, within the decoding limits, then PNG encoding).
#![no_main]

use libfuzzer_sys::fuzz_target;
use netsift_engine::thumbs::{self, THUMB_SIZE};

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = thumbs::render(data, THUMB_SIZE) {
        assert!(r.width <= thumbs::MAX_DIMENSION && r.height <= thumbs::MAX_DIMENSION);
    }
});
