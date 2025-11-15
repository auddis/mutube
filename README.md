# μTube

MuTube enhances YouTube on Apple TV with [TizenTube Cobalt](https://github.com/reisxd/TizenTubeCobalt)'s userscript,
which removes ads and adds support for features like SponsorBlock.

## Setup

MuTube has been tested with YouTube 4.51.08 on an Apple TV 4K.

### Prerequisites

1. Xcode Command Line Tools (for building the hook dylib)
2. [insert_dylib](https://github.com/Tyilo/insert_dylib)

    ```bash
    git clone https://github.com/Tyilo/insert_dylib
    cd insert_dylib
    xcodebuild
    cp build/Release/insert_dylib /usr/local/bin/insert_dylib
    ```

### Building

1. Run `make`. Make sure `Makefile` points to the correct IPA file.
2. Different versions of YouTube will require different hook addresses.
   Update the offsets in `MuTubeHooks.mm` (currently `0xed5270` and `0x152d508`) accordingly.

## Usage

Sideload the generated `mutube.ipa` onto your Apple TV using a tool like [Sideloadly](https://sideloadly.io/).
Once installed, open the YouTube app and you should see a popup on the top right corner indicating that
TizenTube has loaded successfully.

## Technical Details

MuTube uses inline ARM64 hooking to intercept two key functions in the YouTube app:

1. **HTMLScriptElement::Execute** (`0xed5270`) - Intercepts JavaScript execution to inject the TizenTube userscript
2. **DirectiveList::AddDirective** (`0x152d508`) - Modifies Content Security Policy to whitelist required domains

The custom `MuTubeHooks.dylib` is injected at runtime and installs hooks using memory trampolines,
eliminating the need for external dependencies like Frida.
