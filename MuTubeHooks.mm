#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <dlfcn.h>
#import <string>
#import <cstring>

// Injected JavaScript content that loads TizenTube
static const char* injectedContent =
    "(function(){"
    "const n=document.createElement(\"script\");"
    "n.src=\"https://cdn.jsdelivr.net/npm/@foxreis/tizentube/dist/userScript.js\";"
    "document.head.appendChild(n);"
    "const o=window.MediaSource.isTypeSupported;"
    "window.MediaSource.isTypeSupported=function(e){"
    "return o.call(this,e.replace(/; width=\\\\d+/,\\\"\\\").replace(/; height=\\\\d+/,\\\"\\\"))"
    "};"
    "})();";

// Domains to whitelist in CSP
static const char* cspWhitelist = "sponsorblock.inf.re sponsor.ajay.app dearrow-thumb.ajay.app cdn.jsdelivr.net ";

// gum-graft structures (from gumdarwingrafter-priv.h)
#define GUM_DARWIN_GRAFTER_ABI_VERSION 1

#pragma pack(push, 1)

struct GumGraftedHeader {
    uint32_t abi_version;
    uint32_t num_hooks;
    uint32_t num_imports;
    uint32_t padding;
    uint64_t begin_invocation;
    uint64_t end_invocation;
};

struct GumGraftedHook {
    uint32_t code_offset;
    uint32_t trampoline_offset;
    uint32_t flags;
    uint64_t user_data;
};

#pragma pack(pop)

// libc++ insert function pointer
typedef void* (*insert_fn)(void* str, size_t pos, const char* s, size_t n);
static insert_fn std_string_insert = nullptr;

// Hook addresses
static const uint64_t HTMLSCRIPT_EXECUTE_OFFSET = 0xed5270;
static const uint64_t DIRECTIVE_LIST_ADD_OFFSET = 0x152d508;

// Helper function to read std::string
struct StdStringData {
    const char* data;
    size_t length;
};

StdStringData readStdString(void* stdStringPtr) {
    StdStringData result;

    // std::string layout (short string optimization)
    struct ShortString {
        char data[23];
        uint8_t size;
    };

    struct LongString {
        char* data;
        size_t size;
        size_t capacity;
    };

    union StringUnion {
        ShortString shortStr;
        LongString longStr;
    };

    StringUnion* str = (StringUnion*)stdStringPtr;
    uint8_t sizeIndicator = str->shortStr.size;

    if (sizeIndicator & 1) {
        // Long string
        result.data = str->longStr.data;
        result.length = str->longStr.size;
    } else {
        // Short string
        result.data = str->shortStr.data;
        result.length = sizeIndicator >> 1;
    }

    return result;
}

// Helper function to prepend content to std::string
void prependToStdString(void* stdStringPtr, const char* content) {
    if (!std_string_insert) return;

    size_t contentLen = strlen(content);
    std_string_insert(stdStringPtr, 0, content, contentLen);
}

// ARM64 CPU context (registers passed to hooks)
struct CpuContext {
    uint64_t x[29];  // X0-X28
    uint64_t fp;     // X29 (frame pointer)
    uint64_t lr;     // X30 (link register)
    uint64_t sp;
    uint64_t pc;
};

// Invocation context (similar to Frida's GumInvocationContext)
extern "C" void mutube_begin_invocation(CpuContext* cpu_context, void* user_data) {
    GumGraftedHook* hook = (GumGraftedHook*)user_data;

    // Determine which function is being called based on code_offset
    uint32_t code_offset = hook->code_offset;

    if (code_offset == HTMLSCRIPT_EXECUTE_OFFSET) {
        // HTMLScriptElement::Execute hook
        // X0 = this pointer
        // X1 = pointer to std::string (content)

        void* contentPtr = (void*)cpu_context->x[1];

        // Read the content string
        StdStringData content = readStdString(contentPtr);

        // Check if content contains "yttv"
        if (content.data && content.length > 0) {
            std::string contentStr(content.data, content.length);
            if (contentStr.find("yttv") != std::string::npos) {
                // Prepend injected content
                prependToStdString(contentPtr, injectedContent);
            }
        }
    }
    else if (code_offset == DIRECTIVE_LIST_ADD_OFFSET) {
        // DirectiveList::AddDirective hook
        // X0 = this pointer
        // X1 = type
        // X2 = pointer to std::string (value)

        void* valuePtr = (void*)cpu_context->x[2];

        // Prepend CSP whitelist
        prependToStdString(valuePtr, cspWhitelist);
    }
}

extern "C" void mutube_end_invocation(CpuContext* cpu_context, void* user_data) {
    // Nothing to do on function exit for our hooks
}

// Find the GumGraftedHeader in the binary
GumGraftedHeader* findGraftedHeader() {
    const struct mach_header_64* header = (const struct mach_header_64*)_dyld_get_image_header(0);
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);

    unsigned long size = 0;

    // Try different segment names that gum-graft might use
    const char* segment_names[] = {"__DATA_CONST", "__DATA", "__HOOKS_DATA"};

    for (const char* seg_name : segment_names) {
        uint8_t* section_data = getsectiondata((const struct mach_header_64*)header,
                                                seg_name, "__gum_graft", &size);
        if (section_data) {
            GumGraftedHeader* graft_header = (GumGraftedHeader*)(section_data + slide);
            if (graft_header->abi_version == GUM_DARWIN_GRAFTER_ABI_VERSION) {
                return graft_header;
            }
        }
    }

    // If not found in sections, scan memory for the header
    // gum-graft places it in a data segment after the hooks
    const uint8_t* start = (const uint8_t*)header;
    const uint8_t* end = start + 0x10000000; // Search first 256MB

    for (const uint8_t* p = start; p < end - sizeof(GumGraftedHeader); p += 8) {
        GumGraftedHeader* candidate = (GumGraftedHeader*)p;
        if (candidate->abi_version == GUM_DARWIN_GRAFTER_ABI_VERSION &&
            candidate->num_hooks > 0 && candidate->num_hooks < 1000) {
            return candidate;
        }
    }

    return nullptr;
}

// Constructor function - runs when dylib is loaded
__attribute__((constructor))
static void initializeHooks() {
    NSLog(@"[MuTubeHooks] Initializing...");

    // Load libc++ and get std::string::insert function
    void* libcpp = dlopen("/usr/lib/libc++.1.dylib", RTLD_NOW);
    if (libcpp) {
        std_string_insert = (insert_fn)dlsym(libcpp, "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertEmPKcm");
        if (std_string_insert) {
            NSLog(@"[MuTubeHooks] Found std::string::insert");
        } else {
            NSLog(@"[MuTubeHooks] Failed to find std::string::insert");
        }
    } else {
        NSLog(@"[MuTubeHooks] Failed to load libc++");
    }

    // Find the GumGraftedHeader
    GumGraftedHeader* header = findGraftedHeader();
    if (!header) {
        NSLog(@"[MuTubeHooks] Failed to find GumGraftedHeader!");
        return;
    }

    NSLog(@"[MuTubeHooks] Found GumGraftedHeader:");
    NSLog(@"[MuTubeHooks]   ABI version: %u", header->abi_version);
    NSLog(@"[MuTubeHooks]   Num hooks: %u", header->num_hooks);
    NSLog(@"[MuTubeHooks]   Num imports: %u", header->num_imports);

    // Fill in the function pointers
    header->begin_invocation = (uint64_t)&mutube_begin_invocation;
    header->end_invocation = (uint64_t)&mutube_end_invocation;

    NSLog(@"[MuTubeHooks] Installed hook handlers:");
    NSLog(@"[MuTubeHooks]   begin_invocation: %p", (void*)header->begin_invocation);
    NSLog(@"[MuTubeHooks]   end_invocation: %p", (void*)header->end_invocation);

    // Activate hooks by setting flags
    GumGraftedHook* hooks = (GumGraftedHook*)(header + 1);
    for (uint32_t i = 0; i < header->num_hooks; i++) {
        hooks[i].flags |= 1; // Set active bit
        NSLog(@"[MuTubeHooks] Activated hook at offset 0x%x", hooks[i].code_offset);
    }

    NSLog(@"[MuTubeHooks] Hook initialization complete");
}
