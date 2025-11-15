# μTube

MuTube enhances YouTube on Apple TV with [TizenTube Cobalt](https://github.com/reisxd/TizenTubeCobalt)'s userscript,
which removes ads and adds support for features like SponsorBlock.

## Setup

MuTube has been tested with YouTube 4.51.08 on an Apple TV 4K.

### Prerequisites

1. Xcode Command Line Tools (for building the hook dylib)
2. Python 3 (for binary modification script)
3. [insert_dylib](https://github.com/Tyilo/insert_dylib)

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

MuTube uses a two-step approach to enable runtime hooking without Frida:

### 1. Binary Modification (`make_code_writable.py`)
- Modifies the Mach-O `__TEXT` segment protection flags
- Adds `VM_PROT_WRITE` to `maxprot` and `initprot`
- This allows code pages to be made writable at runtime (normally prohibited on iOS/tvOS)
- Replaces Frida's gum-graft functionality

### 2. Runtime Hooking (`MuTubeHooks.dylib`)
The dylib installs inline ARM64 hooks at two addresses:

1. **HTMLScriptElement::Execute** (`0xed5270`)
   - Intercepts JavaScript execution in the Cobalt browser
   - Prepends TizenTube userscript injection code
   - Enables 4K playback by manipulating `MediaSource.isTypeSupported()`

2. **DirectiveList::AddDirective** (`0x152d508`)
   - Modifies Content Security Policy directives
   - Whitelists domains: `sponsorblock.inf.re`, `sponsor.ajay.app`, `dearrow-thumb.ajay.app`, `cdn.jsdelivr.net`
   - Allows TizenTube to fetch SponsorBlock data and assets

### Implementation
- Hooks use memory trampolines created with `mmap(PROT_EXEC)`
- Original instructions are preserved in trampolines
- Hook functions modify `std::string` parameters using libc++ functions
- No external dependencies (no Frida, no gum-graft)
