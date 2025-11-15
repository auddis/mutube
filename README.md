# μTube

MuTube enhances YouTube on Apple TV with [TizenTube Cobalt](https://github.com/reisxd/TizenTubeCobalt)'s userscript,
which removes ads and adds support for features like SponsorBlock.

## Setup

MuTube has been tested with YouTube 4.51.08 on an Apple TV 4K.

### Prerequisites

1. Xcode Command Line Tools (for building the hook dylib)
2. [insert_dylib](https://github.com/Tyilo/insert_dylib)
3. `wget` (for downloading gum-graft)

    ```bash
    # Install insert_dylib
    git clone https://github.com/Tyilo/insert_dylib
    cd insert_dylib
    xcodebuild
    cp build/Release/insert_dylib /usr/local/bin/insert_dylib

    # Install wget (if not already installed)
    brew install wget
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

MuTube uses **gum-graft** (Frida's static binary patcher) with a custom dylib that replaces Frida Gadget:

### 1. Static Binary Patching (`gum-graft`)
- Downloads gum-graft at build time (version-agnostic tool)
- Instruments two code offsets in the YouTube binary:
  - `0xed5270` - HTMLScriptElement::Execute
  - `0x152d508` - DirectiveList::AddDirective
- Creates trampolines and a `GumGraftedHeader` structure in the binary
- No Frida Gadget dependency = no tvOS version compatibility issues

### 2. Runtime Hook Handler (`MuTubeHooks.dylib`)
The dylib hooks into gum-graft's infrastructure:

1. On load, finds the `GumGraftedHeader` in memory
2. Fills in `begin_invocation` and `end_invocation` function pointers
3. Activates hooks by setting flags in `GumGraftedHook` entries

**Hook implementations:**

- **HTMLScriptElement::Execute** (`0xed5270`)
  - Receives CPU context with function arguments
  - Checks if script contains "yttv"
  - Prepends TizenTube userscript injection code
  - Enables 4K playback support

- **DirectiveList::AddDirective** (`0x152d508`)
  - Receives CPU context with CSP directive value
  - Prepends domain whitelist for SponsorBlock and CDN access
  - Domains: `sponsorblock.inf.re`, `sponsor.ajay.app`, `dearrow-thumb.ajay.app`, `cdn.jsdelivr.net`

### Why This Approach?

- **Version stability**: gum-graft is version-agnostic, only Frida Gadget had compatibility issues
- **No runtime dependencies**: Custom dylib is simple and tvOS-version independent
- **Proven patching**: Uses Frida's battle-tested binary modification tool
- **Simpler than full reimplementation**: Leverages existing infrastructure
