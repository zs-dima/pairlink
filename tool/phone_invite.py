"""Prints the pairing invite the wired phone shows as a QR, for `tool/peer.dart panel --invite`.

Reads the screen with `adb exec-out screencap -p` and decodes it with OpenCV (`pip install
opencv-python`). Exit 1 when no QR is on screen. Kept out of the Dart package: decoding a QR is the
one thing this tool needs that pure Dart has no dependency-free answer for.
"""

import subprocess
import sys

import cv2
import numpy


def main() -> int:
    png = subprocess.run(['adb', 'exec-out', 'screencap', '-p'], capture_output=True, check=True).stdout
    image = cv2.imdecode(numpy.frombuffer(png, numpy.uint8), cv2.IMREAD_COLOR)
    text, _, _ = cv2.QRCodeDetector().detectAndDecode(image)
    if not text:
        print('no QR code on the phone screen', file=sys.stderr)
        return 1
    print(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
