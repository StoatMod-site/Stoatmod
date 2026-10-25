import io
import unittest

from PIL import Image, UnidentifiedImageError

from case_images import case_copy
from image_safety import SAFE_IMAGE_FORMATS, open_image


def encoded(fmt: str) -> bytes:
    output = io.BytesIO()
    Image.new("RGB", (32, 32), (200, 40, 40)).save(output, format=fmt)
    return output.getvalue()


class ImageSafetyTests(unittest.TestCase):
    def test_allowed_formats_open(self) -> None:
        for fmt in SAFE_IMAGE_FORMATS:
            with self.subTest(fmt=fmt), open_image(encoded(fmt)) as image:
                self.assertEqual(image.format, fmt)

    def test_other_decoders_are_never_reached(self) -> None:
        for fmt in ("TIFF", "BMP", "PDF", "ICO", "TGA"):
            with self.subTest(fmt=fmt), self.assertRaises(UnidentifiedImageError):
                open_image(encoded(fmt))

    def test_case_copies_skip_unsupported_formats(self) -> None:
        self.assertIsNone(case_copy(encoded("TIFF"), ["violence"]))
        self.assertIsNotNone(case_copy(encoded("PNG"), ["violence"]))


if __name__ == "__main__":
    unittest.main()
