#!/usr/bin/env python3
"""
Modify Mach-O segment protections to make __TEXT writable.
This allows runtime code modifications to work despite code signing.
"""

import struct
import sys

# Mach-O constants
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
VM_PROT_READ = 0x1
VM_PROT_WRITE = 0x2
VM_PROT_EXECUTE = 0x4

def modify_segment_protection(binary_path):
    """Modify __TEXT segment to be writable"""

    with open(binary_path, 'rb') as f:
        data = bytearray(f.read())

    # Check Mach-O magic
    magic = struct.unpack('<I', data[0:4])[0]
    if magic != MH_MAGIC_64:
        print(f"[!] Not a 64-bit Mach-O binary (magic: 0x{magic:08x})")
        return False

    print(f"[*] Processing Mach-O binary: {binary_path}")

    # Read Mach-O header
    ncmds = struct.unpack('<I', data[16:20])[0]
    print(f"[*] Number of load commands: {ncmds}")

    # Start after mach_header_64 (32 bytes)
    offset = 32
    modified = False

    for i in range(ncmds):
        cmd = struct.unpack('<I', data[offset:offset+4])[0]
        cmdsize = struct.unpack('<I', data[offset+4:offset+8])[0]

        if cmd == LC_SEGMENT_64:
            # Read segment name (16 bytes at offset+8)
            segname = data[offset+8:offset+24].rstrip(b'\x00').decode('utf-8')

            if segname == '__TEXT':
                # Read current protections
                maxprot_offset = offset + 40
                initprot_offset = offset + 44

                maxprot = struct.unpack('<I', data[maxprot_offset:maxprot_offset+4])[0]
                initprot = struct.unpack('<I', data[initprot_offset:initprot_offset+4])[0]

                print(f"[*] Found __TEXT segment:")
                print(f"    maxprot:  0x{maxprot:x} (R:{bool(maxprot & VM_PROT_READ)} W:{bool(maxprot & VM_PROT_WRITE)} X:{bool(maxprot & VM_PROT_EXECUTE)})")
                print(f"    initprot: 0x{initprot:x} (R:{bool(initprot & VM_PROT_READ)} W:{bool(initprot & VM_PROT_WRITE)} X:{bool(initprot & VM_PROT_EXECUTE)})")

                # Make writable
                new_maxprot = maxprot | VM_PROT_WRITE
                new_initprot = initprot | VM_PROT_WRITE

                struct.pack_into('<I', data, maxprot_offset, new_maxprot)
                struct.pack_into('<I', data, initprot_offset, new_initprot)

                print(f"[*] Modified __TEXT segment:")
                print(f"    maxprot:  0x{new_maxprot:x} (R:{bool(new_maxprot & VM_PROT_READ)} W:{bool(new_maxprot & VM_PROT_WRITE)} X:{bool(new_maxprot & VM_PROT_EXECUTE)})")
                print(f"    initprot: 0x{new_initprot:x} (R:{bool(new_initprot & VM_PROT_READ)} W:{bool(new_initprot & VM_PROT_WRITE)} X:{bool(new_initprot & VM_PROT_EXECUTE)})")

                modified = True

        offset += cmdsize

    if not modified:
        print("[!] __TEXT segment not found")
        return False

    # Save modified binary
    with open(binary_path, 'wb') as f:
        f.write(data)

    print(f"[*] Saved modified binary: {binary_path}")
    return True

def main():
    if len(sys.argv) < 2:
        print("Usage: make_code_writable.py <binary_path>")
        sys.exit(1)

    binary_path = sys.argv[1]

    if modify_segment_protection(binary_path):
        print("[*] Success!")
    else:
        print("[!] Failed to modify binary")
        sys.exit(1)

if __name__ == '__main__':
    main()
