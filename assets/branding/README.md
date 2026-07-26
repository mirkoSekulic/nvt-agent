# NVT Agent branding assets

`source/nvt-logo-source.png` is the untouched canonical supplied artwork. Its
SHA-256 is:

```text
ecc3b84860236edc1b2550a1e89ffb38c5a145639cff26d8b05e3c0aff754212
```

All product assets preserve the complete supplied artwork. They are direct,
aspect-preserving resizes: there is no tracing, generative redraw, cropping,
recoloring, simplification, or background removal. The
`nvt-agent-mark-*.png` files are the same artwork at product sizes; the 512 px
asset is also used by the repository README.

`generate.sh` uses ImageMagick 6 `convert` with Lanczos resampling to create
512, 192, 64, 32, and 16 px images and a real 16/32/48/64-size `favicon.ico`
(the 48 px layer is generated directly into the ICO and is not committed as a
standalone duplicate). code-server uses the 192/512 assets for both regular
and maskable PWA filenames because the source already includes a safe quiet
area. code-server expects SVG favicon filenames, so `nvt-agent-mark.svg` is an explicitly
documented raster wrapper around the 64 px PNG—not a claimed vector asset.
The script also refreshes the byte-identical copies required by Go embed in
`gateway/internal/gateway/branding/`.

Run from the repository root:

```sh
bash assets/branding/generate.sh
```

The script verifies the canonical source hash before writing anything. Image
generation tooling is development-only and is not installed in NVT product
images.

The fixed runtime/Helm override contract consists of `nvt-agent-mark.svg`,
`favicon.ico`, and the 64, 192, and 512 px PNG files. The 16 and 32 px PNGs are
kept only as reproducible inputs to the multi-size ICO.
