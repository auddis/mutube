#!/usr/bin/env python3
"""
Mach-O segment injector - adds a new executable segment with hook code.

This creates a new __HOOKS segment in the binary containing our hook
implementations, then patches the target functions to branch there.
"""

import struct
import sys
import os

class MachOSegmentInjector:
    # Mach-O constants
    MH_MAGIC_64 = 0xFEEDFACF
    LC_SEGMENT_64 = 0x19
    LC_CODE_SIGNATURE = 0x1D

    VM_PROT_READ = 0x1
    VM_PROT_WRITE = 0x2
    VM_PROT_EXECUTE = 0x4

    BASE_VM = 0x100000000

    def __init__(self, binary_path):
        self.binary_path = binary_path
        with open(binary_path, 'rb') as f:
            self.data = bytearray(f.read())

        magic = struct.unpack('<I', self.data[0:4])[0]
        if magic != self.MH_MAGIC_64:
            raise ValueError("Not a 64-bit Mach-O binary")

        self.parse_header()
        print(f"[*] Loaded: {binary_path}")
        print(f"[*] {self.ncmds} load commands, {len(self.data)} bytes")

    def parse_header(self):
        """Parse Mach-O header"""
        self.ncmds = struct.unpack('<I', self.data[16:20])[0]
        self.sizeofcmds = struct.unpack('<I', self.data[20:24])[0]

        # Find existing segments
        self.segments = []
        self.codesign_offset = None
        offset = 32  # After mach_header_64

        for i in range(self.ncmds):
            cmd = struct.unpack('<I', self.data[offset:offset+4])[0]
            cmdsize = struct.unpack('<I', self.data[offset+4:offset+8])[0]

            if cmd == self.LC_SEGMENT_64:
                segname = self.data[offset+8:offset+24].rstrip(b'\x00').decode('utf-8')
                vmaddr = struct.unpack('<Q', self.data[offset+24:offset+32])[0]
                vmsize = struct.unpack('<Q', self.data[offset+32:offset+40])[0]
                fileoff = struct.unpack('<Q', self.data[offset+40:offset+48])[0]
                filesize = struct.unpack('<Q', self.data[offset+48:offset+56])[0]

                self.segments.append({
                    'name': segname,
                    'vmaddr': vmaddr,
                    'vmsize': vmsize,
                    'fileoff': fileoff,
                    'filesize': filesize,
                    'cmd_offset': offset
                })

            elif cmd == self.LC_CODE_SIGNATURE:
                self.codesign_offset = offset

            offset += cmdsize

    def find_insertion_point(self):
        """Find where to insert new segment - before code signature"""
        # Find the last segment before code signature
        last_seg = max(self.segments, key=lambda s: s['fileoff'] + s['filesize'])
        return last_seg['fileoff'] + last_seg['filesize']

    def create_branch(self, from_vm, to_vm):
        """Create ARM64 B instruction"""
        offset = to_vm - from_vm
        if abs(offset) > 0x7FFFFFF * 4:
            raise ValueError(f"Branch offset out of range: {offset}")
        return 0x14000000 | ((offset >> 2) & 0x03FFFFFF)

    def vm_to_file(self, vm_addr):
        """Convert VM address to file offset"""
        for seg in self.segments:
            if seg['vmaddr'] <= vm_addr < seg['vmaddr'] + seg['vmsize']:
                return seg['fileoff'] + (vm_addr - seg['vmaddr'])
        return vm_addr - self.BASE_VM

    def read_u32(self, offset):
        return struct.unpack('<I', self.data[offset:offset+4])[0]

    def write_u32(self, offset, value):
        struct.pack_into('<I', self.data, offset, value)

    def add_hooks_segment(self, hook_code, hook_vm_base):
        """
        Add a new __HOOKS segment to the binary.
        Returns the VM address where it was added.
        """
        # Align hook code to page size
        hook_size = len(hook_code)
        hook_size_aligned = (hook_size + 0xFFF) & ~0xFFF

        # Pad hook code
        hook_code_padded = hook_code + bytes(hook_size_aligned - len(hook_code))

        # Find insertion point (append at end, before code signature)
        insert_fileoff = self.find_insertion_point()

        # Create LC_SEGMENT_64 load command
        segment_cmd = bytearray(72)  # sizeof(segment_command_64) without sections
        struct.pack_into('<I', segment_cmd, 0, self.LC_SEGMENT_64)  # cmd
        struct.pack_into('<I', segment_cmd, 4, 72)  # cmdsize (no sections)
        segment_cmd[8:24] = b'__HOOKS\x00' + b'\x00' * 9  # segname
        struct.pack_into('<Q', segment_cmd, 24, hook_vm_base)  # vmaddr
        struct.pack_into('<Q', segment_cmd, 32, hook_size_aligned)  # vmsize
        struct.pack_into('<Q', segment_cmd, 40, insert_fileoff)  # fileoff
        struct.pack_into('<Q', segment_cmd, 48, hook_size_aligned)  # filesize
        struct.pack_into('<I', segment_cmd, 56, self.VM_PROT_READ | self.VM_PROT_EXECUTE)  # maxprot
        struct.pack_into('<I', segment_cmd, 60, self.VM_PROT_READ | self.VM_PROT_EXECUTE)  # initprot
        struct.pack_into('<I', segment_cmd, 64, 0)  # nsects
        struct.pack_into('<I', segment_cmd, 68, 0)  # flags

        # Insert the load command after last segment command
        # Find where to insert in load commands
        last_seg_cmd_end = max(s['cmd_offset'] for s in self.segments) + 72  # Assuming all are 72 bytes

        # Insert segment command
        self.data[last_seg_cmd_end:last_seg_cmd_end] = segment_cmd

        # Update Mach-O header
        self.ncmds += 1
        self.sizeofcmds += 72
        struct.pack_into('<I', self.data, 16, self.ncmds)
        struct.pack_into('<I', self.data, 20, self.sizeofcmds)

        # Insert hook code at end of file
        self.data[insert_fileoff:insert_fileoff] = hook_code_padded

        # Update code signature offset if present
        if self.codesign_offset is not None:
            # Code signature dataoff needs to be updated
            codesign_dataoff_offset = self.codesign_offset + 8
            old_dataoff = struct.unpack('<I', self.data[codesign_dataoff_offset:codesign_dataoff_offset+4])[0]
            new_dataoff = old_dataoff + hook_size_aligned
            struct.pack_into('<I', self.data, codesign_dataoff_offset, new_dataoff)

        print(f"[*] Added __HOOKS segment:")
        print(f"    VM: 0x{hook_vm_base:x}")
        print(f"    File offset: 0x{insert_fileoff:x}")
        print(f"    Size: 0x{hook_size_aligned:x}")

        return hook_vm_base

    def patch_target(self, target_offset, trampoline_vm):
        """Patch target function to branch to trampoline"""
        target_vm = self.BASE_VM + target_offset
        file_offset = self.vm_to_file(target_vm)

        print(f"\n[*] Patching 0x{target_offset:x}")
        print(f"    VM: 0x{target_vm:x}, File: 0x{file_offset:x}")

        # Read original instructions
        original = []
        for i in range(4):
            original.append(self.read_u32(file_offset + i*4))
        print(f"    Original: {' '.join(f'{x:08x}' for x in original)}")

        # Write branch
        branch = self.create_branch(target_vm, trampoline_vm)
        self.write_u32(file_offset, branch)

        # NOP the rest
        for i in range(1, 4):
            self.write_u32(file_offset + i*4, 0xD503201F)

        print(f"    Patched: branch to 0x{trampoline_vm:x}")

        return original

    def save(self, output_path=None):
        if output_path is None:
            output_path = self.binary_path
        with open(output_path, 'wb') as f:
            f.write(self.data)
        print(f"\n[*] Saved: {output_path}")


def create_simple_trampoline(original_insns, return_vm, current_vm):
    """Create a simple trampoline that executes original code and returns"""
    code = bytearray()

    # Write original instructions
    for insn in original_insns:
        code.extend(struct.pack('<I', insn))

    # Branch back
    offset = return_vm - (current_vm + len(code))
    branch_back = 0x14000000 | ((offset >> 2) & 0x03FFFFFF)
    code.extend(struct.pack('<I', branch_back))

    return code


def main():
    if len(sys.argv) < 2:
        print("Usage: inject_segment.py <binary> --instrument=<addr> ...")
        sys.exit(1)

    binary_path = sys.argv[1]

    # Parse addresses
    addresses = []
    for arg in sys.argv[2:]:
        if arg.startswith('--instrument='):
            addr_str = arg.split('=', 1)[1]
            addr = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
            addresses.append(addr)

    if not addresses:
        print("Error: No --instrument addresses")
        sys.exit(1)

    print(f"[*] Binary: {binary_path}")
    print(f"[*] Addresses: {[hex(a) for a in addresses]}\n")

    injector = MachOSegmentInjector(binary_path)

    # Choose a VM address for our hooks segment (after existing segments)
    max_vm = max(s['vmaddr'] + s['vmsize'] for s in injector.segments)
    hook_vm_base = (max_vm + 0xFFFFF) & ~0xFFFFF  # Align to 1MB

    # Build hook code with trampolines
    hook_code = bytearray()
    trampolines = []

    for addr in addresses:
        target_vm = 0x100000000 + addr
        file_offset = injector.vm_to_file(target_vm)

        # Read original instructions
        original_insns = []
        for i in range(4):
            original_insns.append(injector.read_u32(file_offset + i*4))

        # Create trampoline
        trampoline_vm = hook_vm_base + len(hook_code)
        return_vm = target_vm + 16
        trampoline_code = create_simple_trampoline(original_insns, return_vm, trampoline_vm)

        trampolines.append({'addr': addr, 'vm': trampoline_vm})
        hook_code.extend(trampoline_code)

        # Align to 16 bytes
        while len(hook_code) % 16 != 0:
            hook_code.extend(struct.pack('<I', 0xD503201F))  # NOP

    # Add hooks segment
    injector.add_hooks_segment(hook_code, hook_vm_base)

    # Re-parse to get updated offsets
    injector.parse_header()

    # Patch target functions
    for item in trampolines:
        injector.patch_target(item['addr'], item['vm'])

    injector.save()
    print("\n[*] Done!")


if __name__ == '__main__':
    main()
