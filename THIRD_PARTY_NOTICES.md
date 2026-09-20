# Third-party notices

PhotoSigning's project license is Apache-2.0. It does not replace the licenses of
third-party code, models, fonts, or other assets. This file describes the source
repository; it is not a complete notice bundle for an installer or container.

## Adapted source included in this repository

`photosigning/majik_image.py` is a modified Python adaptation of Majik Signature,
copyright (c) 2026 Majikah Solutions OPC, under Apache-2.0.

- [Upstream revision](https://github.com/Majikah/majik-signature/tree/e10d3984fdc25e5bde62f03362461d2344422bbc)
- [Retained upstream license](third_party/majik-signature/LICENSE)
- [Source files and modifications](third_party/majik-signature/NOTICE.md)

On 2026-09-20 the retained license was compared byte-for-byte with the upstream
license at that revision. Its complete Git tree contained no separate NOTICE
file. The four credited TypeScript files contained no additional copyright or
license headers. The Python file prominently identifies the adaptation.

## Direct runtime dependencies

Versions below were inspected in the local environment on 2026-09-20. The lockfile
also contains alternatives for other platforms. License summaries are based on
installed metadata and license files; the actual license texts control.

| Dependency | Inspected version | License summary |
| --- | --- | --- |
| cryptography | 48.0.1 | Apache-2.0 OR BSD-3-Clause |
| Pillow | 12.3.0 | MIT-CMU |
| Streamlit | 1.64.0 | Apache-2.0 |
| NumPy | 2.5.3 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 |
| reedsolo | 1.7.0 | Unlicense OR MIT-0, per its included LICENSE |
| opencv-python-headless | 4.14.0.94 | MIT packaging; Apache-2.0 OpenCV; additional bundled-library licenses |
| c2pa-python | 0.37.10 | MIT OR Apache-2.0 |
| trustmark | 0.9.2 | MIT |
| torch | 2.14.0+cpu | Apache-2.0 AND Apache-2.0 WITH LLVM-exception AND BSD-2-Clause AND BSD-3-Clause AND BSL-1.0 AND MIT |
| torchvision | 0.29.0+cpu | BSD; preserve its distributed LICENSE |

These packages are installed separately; their code and native libraries are not
vendored into this source repository. See the
[installed dependency inventory](docs/dependency-license-inventory.md) for the
broader metadata review, including development tools and transitive dependencies.

### Native libraries and transitive dependencies

OpenCV's packaging license is not the entire wheel's license. Its installed
`LICENSE-3RD-PARTY.txt` includes FFmpeg and other libraries, and upstream identifies
the included FFmpeg as LGPLv2.1. See
[OpenCV's licensing explanation](https://github.com/opencv/opencv-python#licensing).

The installed environment also includes `certifi` under MPL-2.0 and `tqdm` under
MPL-2.0 AND MIT. These do not by themselves require unrelated PhotoSigning files
to use MPL; MPL obligations attach to covered files when distributed. See
[Mozilla's MPL FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/).

Before distributing dependency wheels, native libraries, a container, or a frozen
executable, collect the licenses for the actual artifacts being shipped and satisfy
their source-availability and other redistribution obligations, including applicable
LGPL requirements. This metadata inventory does not perform that artifact review.

## TrustMark models

Adobe explicitly states that the MIT license covers both its code and the model
files downloaded on first use. PhotoSigning uses TrustMark Q and its crop detector.
Model weights are not included in this source repository. If redistributing them,
include Adobe's copyright and MIT permission notice. See
[TrustMark's license statement](https://github.com/adobe/trustmark#license) and
[license text](https://github.com/adobe/trustmark/blob/main/LICENSE).

## Fonts and images

`app.py` references Google Fonts for DM Sans and Manrope through a remote stylesheet;
font binaries are not bundled. Both families have SIL Open Font License 1.1 notices:
[DM Sans](https://github.com/google/fonts/blob/main/ofl/dmsans/OFL.txt) and
[Manrope](https://github.com/google/fonts/blob/main/ofl/manrope/OFL.txt).
Preserve those notices if fonts are bundled in a future release.

The demo landscape is drawn locally by `photosigning/demo.py`. `ui-preview.png`
shows the app's empty interface, with no uploaded photograph or visible personal
details; its PNG contains no EXIF or text metadata. No separate stock-photo or
downloaded image files were found among the publication candidates.
