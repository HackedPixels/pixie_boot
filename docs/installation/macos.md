# macOS / OS X

This page explains how to install Pixie Boot on a MacOs Server System

!!! note
    Pixie Boot on MacOS is not recommended for production environments and should only be used
    for development / testing purposes.

### Pre-built archives

The easiest way is to install PixieBoot via a pre-built binary package.

```bash
curl -LO https://get.pixieboot.net/releases/macos/x86_64/pixieboot-0.1.tar.xz
tar -xf pixieboot-0.1.tar.xz
./pixieboot/bin/pxsrv
```

### Cargo

Since Pixie Boot is written in Rust, it can be easily installed via Cargo.

!!! note
    Since that builds Pixie Boot from source, this can take a while.

`cargo install pixieboot`