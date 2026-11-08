use netsift_fixtures::images;

use super::*;

fn decoded(png: &[u8]) -> (u32, u32) {
    let img = image::load_from_memory_with_format(png, ImageFormat::Png).unwrap();
    (img.width(), img.height())
}

#[test]
fn raster_formats_give_bounded_png_thumbnails() {
    for (data, name) in [
        (images::png(800, 400, 0), "png"),
        (images::jpeg(800, 400, 1), "jpeg"),
        (images::gif(800, 400, 2), "gif"),
        (images::webp(800, 400, 3), "webp"),
        (images::bmp(800, 400, 4), "bmp"),
    ] {
        let r = render(&data, THUMB_SIZE).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!((r.width, r.height), (800, 400), "{name}");
        assert!(r.png.starts_with(b"\x89PNG"), "{name}");
        assert_eq!(decoded(&r.png), (320, 160), "{name}: ratio kept");
    }
    let icon = render(&images::ico(32), THUMB_SIZE).unwrap();
    assert_eq!((icon.width, icon.height), (32, 32));
    // Never enlarged.
    let small = render(&images::png(40, 30, 1), THUMB_SIZE).unwrap();
    assert_eq!(decoded(&small.png), (40, 30));
    let pixel = render(&images::pixel_gif(), THUMB_SIZE).unwrap();
    assert_eq!(decoded(&pixel.png), (1, 1));
}

#[test]
fn hostile_or_foreign_content_fails_cleanly() {
    // Cut right after the start of the file: no image can be decoded.
    assert!(matches!(
        render(&images::truncated_jpeg(320, 240, 300), THUMB_SIZE),
        Err(ThumbError::Decode(_))
    ));
    // Cut in the middle of the data: whatever the decoder makes of it, no panic.
    let _ = render(&images::truncated_jpeg(320, 240, 2000), THUMB_SIZE);
    let mut png = images::png(64, 64, 0);
    png.truncate(png.len() / 2);
    assert!(render(&png, THUMB_SIZE).is_err());
    // 100000 x 100000 announced: refused from the header, nothing allocated.
    let started = Instant::now();
    assert!(matches!(
        render(&images::dimension_bomb_png(100_000, 100_000), THUMB_SIZE),
        Err(ThumbError::Decode(_))
    ));
    // Within the dimension limit but beyond the allocation limit (16384^2 RGB = 768 MiB).
    assert!(render(&images::dimension_bomb_png(16_384, 16_384), THUMB_SIZE).is_err());
    assert!(started.elapsed() < Duration::from_secs(5));
    // Not raster images: SVG is never rasterized, text and empty input are not images.
    assert_eq!(
        render(&images::svg(), THUMB_SIZE),
        Err(ThumbError::Unsupported)
    );
    assert_eq!(
        render(b"<html></html>", THUMB_SIZE),
        Err(ThumbError::Unsupported)
    );
    assert_eq!(render(b"", THUMB_SIZE), Err(ThumbError::Unsupported));
    assert_eq!(
        render(&vec![0u8; MAX_INPUT_BYTES + 1], THUMB_SIZE),
        Err(ThumbError::TooLarge)
    );
}

#[test]
fn every_prefix_of_an_image_is_handled_without_panic() {
    for data in [
        images::png(24, 24, 1),
        images::gif(24, 24, 2),
        images::jpeg(24, 24, 3),
        images::webp(24, 24, 4),
        images::bmp(12, 12, 5),
        images::ico(16),
    ] {
        for len in (0..data.len()).step_by(7) {
            let _ = render(&data[..len], THUMB_SIZE);
        }
    }
}

#[test]
fn read_blob_checks_the_recorded_size() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("blob");
    std::fs::write(&path, b"12345").unwrap();
    assert_eq!(read_blob(&path, 5).as_deref(), Some(&b"12345"[..]));
    assert!(read_blob(&path, 6).is_none());
    assert!(read_blob(&tmp.path().join("missing"), 5).is_none());
}
