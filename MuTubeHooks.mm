#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach/vm_prot.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <libkern/OSCacheControl.h>
#import <string>
#import <cstring>
#import <pthread.h>
#import <sys/mman.h>

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

// Structure to hold original function bytes and trampoline
struct HookInfo {
    void* targetAddress;
    void* hookFunction;
    void* trampoline;
    uint32_t originalBytes[4];
};

// Hook information for our two hooks
static HookInfo htmlScriptHook = {0};
static HookInfo directiveListHook = {0};

// libc++ insert function pointer
typedef void* (*insert_fn)(void* str, size_t pos, const char* s, size_t n);
static insert_fn std_string_insert = nullptr;

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

    // Check if it's a short string (size & 1 == 0) or long string (size & 1 == 1)
    // The lowest bit of the size byte indicates whether it's short (0) or long (1)
    uint8_t sizeIndicator = str->shortStr.size;

    if (sizeIndicator & 1) {
        // Long string
        result.data = str->longStr.data;
        result.length = str->longStr.size;
    } else {
        // Short string
        result.data = str->shortStr.data;
        result.length = sizeIndicator >> 1; // Size is stored shifted by 1
    }

    return result;
}

// Helper function to prepend content to std::string
void prependToStdString(void* stdStringPtr, const char* content) {
    if (!std_string_insert) return;

    size_t contentLen = strlen(content);
    std_string_insert(stdStringPtr, 0, content, contentLen);
}

// Create executable trampoline
void* createTrampoline(void* originalFunc, uint32_t* originalBytes) {
    // Allocate executable memory for trampoline
    void* trampoline = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (trampoline == MAP_FAILED) {
        NSLog(@"[MuTubeHooks] Failed to allocate trampoline memory");
        return nullptr;
    }

    uint32_t* trampolineCode = (uint32_t*)trampoline;

    // Copy original bytes (first 16 bytes / 4 instructions)
    memcpy(trampolineCode, originalBytes, 16);

    // Add branch back to original function + 16 bytes
    // Calculate offset for branch
    intptr_t offset = ((intptr_t)originalFunc + 16 - (intptr_t)&trampolineCode[4]) / 4;

    // B instruction: 0x14000000 | (offset & 0x03FFFFFF)
    trampolineCode[4] = 0x14000000 | (offset & 0x03FFFFFF);

    // Flush instruction cache
    sys_icache_invalidate(trampoline, 20);

    return trampoline;
}

// Install inline hook
bool installHook(HookInfo* hookInfo, void* targetAddr, void* hookFunc) {
    hookInfo->targetAddress = targetAddr;
    hookInfo->hookFunction = hookFunc;

    // Save original bytes
    memcpy(hookInfo->originalBytes, targetAddr, 16);

    // Create trampoline
    hookInfo->trampoline = createTrampoline(targetAddr, hookInfo->originalBytes);
    if (!hookInfo->trampoline) {
        return false;
    }

    // Make target memory writable
    vm_address_t page = (vm_address_t)targetAddr & ~(vm_page_size - 1);
    vm_size_t size = vm_page_size;

    kern_return_t kr = vm_protect(mach_task_self(), page, size, FALSE,
                                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[MuTubeHooks] vm_protect failed for write: %d", kr);
        return false;
    }

    // Calculate branch offset to hook function
    intptr_t offset = ((intptr_t)hookFunc - (intptr_t)targetAddr) / 4;

    // Write branch instruction: B hookFunc
    uint32_t* target = (uint32_t*)targetAddr;
    target[0] = 0x14000000 | (offset & 0x03FFFFFF);

    // Write NOPs for the rest
    for (int i = 1; i < 4; i++) {
        target[i] = 0xD503201F; // NOP
    }

    // Restore memory protection
    kr = vm_protect(mach_task_self(), page, size, FALSE,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[MuTubeHooks] vm_protect failed for exec: %d", kr);
    }

    // Flush instruction cache
    sys_icache_invalidate(targetAddr, 16);

    return true;
}

// Hook for HTMLScriptElement::Execute
// Signature: void HTMLScriptElement::Execute(void* this, std::string* content)
extern "C" void htmlScriptExecuteHook(void* thisPtr, void* contentPtr) {
    // Read the content std::string
    StdStringData content = readStdString(contentPtr);

    // Check if content contains "yttv"
    if (content.data && content.length > 0) {
        std::string contentStr(content.data, content.length);
        if (contentStr.find("yttv") != std::string::npos) {
            // Prepend injected content
            prependToStdString(contentPtr, injectedContent);
        }
    }

    // Call original function via trampoline
    typedef void (*orig_fn)(void*, void*);
    orig_fn originalFunc = (orig_fn)htmlScriptHook.trampoline;
    originalFunc(thisPtr, contentPtr);
}

// Hook for DirectiveList::AddDirective
// Signature: void DirectiveList::AddDirective(void* this, int type, std::string* value)
extern "C" void directiveListAddDirectiveHook(void* thisPtr, int type, void* valuePtr) {
    // Prepend CSP whitelist to the value
    prependToStdString(valuePtr, cspWhitelist);

    // Call original function via trampoline
    typedef void (*orig_fn)(void*, int, void*);
    orig_fn originalFunc = (orig_fn)directiveListHook.trampoline;
    originalFunc(thisPtr, type, valuePtr);
}

// Constructor function - runs when dylib is loaded
__attribute__((constructor))
static void initializeHooks() {
    NSLog(@"[MuTubeHooks] Initializing hooks...");

    // Get base address of the main executable
    const struct mach_header* header = _dyld_get_image_header(0);
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    uintptr_t baseAddr = (uintptr_t)header + slide;

    NSLog(@"[MuTubeHooks] Base address: 0x%lx, slide: 0x%lx", baseAddr, slide);

    // Load libc++ and get std::string::insert function
    void* libcpp = dlopen("/usr/lib/libc++.1.dylib", RTLD_NOW);
    if (libcpp) {
        // std::string::insert symbol
        std_string_insert = (insert_fn)dlsym(libcpp, "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertEmPKcm");
        if (std_string_insert) {
            NSLog(@"[MuTubeHooks] Found std::string::insert");
        } else {
            NSLog(@"[MuTubeHooks] Failed to find std::string::insert");
        }
    } else {
        NSLog(@"[MuTubeHooks] Failed to load libc++");
    }

    // Calculate actual addresses
    void* htmlScriptExecuteAddr = (void*)(baseAddr + 0xed5270);
    void* directiveListAddDirectiveAddr = (void*)(baseAddr + 0x152d508);

    NSLog(@"[MuTubeHooks] HTMLScriptElement::Execute at: %p", htmlScriptExecuteAddr);
    NSLog(@"[MuTubeHooks] DirectiveList::AddDirective at: %p", directiveListAddDirectiveAddr);

    // Install hooks
    if (installHook(&htmlScriptHook, htmlScriptExecuteAddr, (void*)htmlScriptExecuteHook)) {
        NSLog(@"[MuTubeHooks] Successfully hooked HTMLScriptElement::Execute");
    } else {
        NSLog(@"[MuTubeHooks] Failed to hook HTMLScriptElement::Execute");
    }

    if (installHook(&directiveListHook, directiveListAddDirectiveAddr, (void*)directiveListAddDirectiveHook)) {
        NSLog(@"[MuTubeHooks] Successfully hooked DirectiveList::AddDirective");
    } else {
        NSLog(@"[MuTubeHooks] Failed to hook DirectiveList::AddDirective");
    }

    NSLog(@"[MuTubeHooks] Hook initialization complete");
}
