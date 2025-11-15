#!/usr/bin/env python3
"""
ARM64 hook code builder.

Generates ARM64 machine code for hooks that can be injected into the binary.
"""

import struct

class ARM64Builder:
    """Helper to build ARM64 machine code"""

    @staticmethod
    def nop():
        return 0xD503201F

    @staticmethod
    def ret():
        return 0xD65F03C0

    @staticmethod
    def mov_reg(rd, rn):
        """MOV Xd, Xn (actually ORR Xd, XZR, Xn)"""
        return 0xAA0003E0 | (rn << 16) | rd

    @staticmethod
    def stp(rt, rt2, rn, imm):
        """STP Xt, Xt2, [Xn, #imm]"""
        # Pre-indexed: imm is in 8-byte units, signed 7-bit
        imm_encoded = (imm >> 3) & 0x7F
        return 0xA9000000 | (imm_encoded << 15) | (rt2 << 10) | (rn << 5) | rt

    @staticmethod
    def ldp(rt, rt2, rn, imm):
        """LDP Xt, Xt2, [Xn, #imm]"""
        imm_encoded = (imm >> 3) & 0x7F
        return 0xA9400000 | (imm_encoded << 15) | (rt2 << 10) | (rn << 5) | rt

    @staticmethod
    def sub_sp(imm):
        """SUB SP, SP, #imm"""
        return 0xD10003FF | ((imm & 0xFFF) << 10)

    @staticmethod
    def add_sp(imm):
        """ADD SP, SP, #imm"""
        return 0x910003FF | ((imm & 0xFFF) << 10)

    @staticmethod
    def bl(from_addr, to_addr):
        """BL (branch with link)"""
        offset = to_addr - from_addr
        return 0x94000000 | ((offset >> 2) & 0x03FFFFFF)

    @staticmethod
    def b(from_addr, to_addr):
        """B (branch)"""
        offset = to_addr - from_addr
        return 0x14000000 | ((offset >> 2) & 0x03FFFFFF)

    @staticmethod
    def adrp(rd, pc_addr, target_addr):
        """ADRP Xd, page"""
        page_offset = (target_addr & ~0xFFF) - (pc_addr & ~0xFFF)
        page_offset_shifted = page_offset >> 12
        immlo = (page_offset_shifted >> 0) & 0x3
        immhi = (page_offset_shifted >> 2) & 0x7FFFF
        return 0x90000000 | (immlo << 29) | (immhi << 5) | rd

    @staticmethod
    def add_imm(rd, rn, imm):
        """ADD Xd, Xn, #imm"""
        return 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd

    @staticmethod
    def ldr_literal(rt, offset):
        """LDR Xt, [PC, #offset]"""
        # offset in words (divided by 4)
        offset_encoded = (offset >> 2) & 0x7FFFF
        return 0x58000000 | (offset_encoded << 5) | rt


def build_htmlscript_hook(base_vm, injected_str_addr, std_string_insert_addr, original_insns, return_addr):
    """
    Build ARM64 code for HTMLScriptElement::Execute hook.

    Args:
        base_vm: Base VM address where this code will be placed
        injected_str_addr: Address of the injected JavaScript string
        std_string_insert_addr: Address of std::string::insert function
        original_insns: Original 4 instructions from hooked function
        return_addr: Address to return to after hook

    Returns:
        bytearray of ARM64 machine code
    """
    code = []
    builder = ARM64Builder()

    current_addr = base_vm

    # Function receives:
    # X0 = this pointer
    # X1 = pointer to std::string (content)

    # Save registers we'll use
    code.append(builder.sub_sp(0x40))  # Allocate stack space
    current_addr += 4

    code.append(builder.stp(0, 1, 31, 0))  # STP X0, X1, [SP]
    current_addr += 4
    code.append(builder.stp(2, 3, 31, 16))  # STP X2, X3, [SP, #16]
    current_addr += 4
    code.append(builder.stp(4, 5, 31, 32))  # STP X4, X5, [SP, #32]
    current_addr += 4
    code.append(builder.stp(30, 31, 31, 48))  # STP X30, XZR, [SP, #48] (save LR)
    current_addr += 4

    # TODO: Check if string contains "yttv"
    # For now, always inject

    # Call std::string::insert(X1, 0, injected_content, length)
    # X0 = std::string pointer (X1)
    code.append(builder.mov_reg(0, 1))
    current_addr += 4

    # X1 = position (0)
    code.append(0xD2800001)  # MOV X1, #0
    current_addr += 4

    # X2 = pointer to injected string
    # Use ADRP + ADD to load address
    code.append(builder.adrp(2, current_addr, injected_str_addr))
    current_addr += 4
    code.append(builder.add_imm(2, 2, injected_str_addr & 0xFFF))
    current_addr += 4

    # X3 = length of injected string (hardcoded for now)
    # TODO: Calculate actual length
    code.append(0xD2801A03)  # MOV X3, #208 (approximate length)
    current_addr += 4

    # Call std::string::insert
    code.append(builder.bl(current_addr, std_string_insert_addr))
    current_addr += 4

    # Restore registers
    code.append(builder.ldp(0, 1, 31, 0))
    current_addr += 4
    code.append(builder.ldp(2, 3, 31, 16))
    current_addr += 4
    code.append(builder.ldp(4, 5, 31, 32))
    current_addr += 4
    code.append(builder.ldp(30, 31, 31, 48))  # Restore LR
    current_addr += 4

    code.append(builder.add_sp(0x40))  # Deallocate stack
    current_addr += 4

    # Execute original instructions
    for insn in original_insns:
        code.append(insn)
        current_addr += 4

    # Branch back to original function
    code.append(builder.b(current_addr, return_addr))

    return bytearray(b''.join(struct.pack('<I', insn) for insn in code))


def build_directive_hook(base_vm, csp_str_addr, std_string_insert_addr, original_insns, return_addr):
    """
    Build ARM64 code for DirectiveList::AddDirective hook.

    Similar to htmlscript_hook but prepends CSP whitelist.
    """
    code = []
    builder = ARM64Builder()

    current_addr = base_vm

    # Function receives:
    # X0 = this pointer
    # X1 = type
    # X2 = pointer to std::string (value)

    # Save registers
    code.append(builder.sub_sp(0x40))
    current_addr += 4

    code.append(builder.stp(0, 1, 31, 0))
    current_addr += 4
    code.append(builder.stp(2, 3, 31, 16))
    current_addr += 4
    code.append(builder.stp(4, 5, 31, 32))
    current_addr += 4
    code.append(builder.stp(30, 31, 31, 48))
    current_addr += 4

    # Call std::string::insert(X2, 0, csp_whitelist, length)
    code.append(builder.mov_reg(0, 2))  # X0 = X2 (string pointer)
    current_addr += 4

    code.append(0xD2800001)  # MOV X1, #0
    current_addr += 4

    # X2 = CSP whitelist string address
    code.append(builder.adrp(2, current_addr, csp_str_addr))
    current_addr += 4
    code.append(builder.add_imm(2, 2, csp_str_addr & 0xFFF))
    current_addr += 4

    # X3 = length (hardcoded)
    code.append(0xD2800A03)  # MOV X3, #80 (approximate)
    current_addr += 4

    # Call std::string::insert
    code.append(builder.bl(current_addr, std_string_insert_addr))
    current_addr += 4

    # Restore registers
    code.append(builder.ldp(0, 1, 31, 0))
    current_addr += 4
    code.append(builder.ldp(2, 3, 31, 16))
    current_addr += 4
    code.append(builder.ldp(4, 5, 31, 32))
    current_addr += 4
    code.append(builder.ldp(30, 31, 31, 48))
    current_addr += 4

    code.append(builder.add_sp(0x40))
    current_addr += 4

    # Execute original instructions
    for insn in original_insns:
        code.append(insn)
        current_addr += 4

    # Branch back
    code.append(builder.b(current_addr, return_addr))

    return bytearray(b''.join(struct.pack('<I', insn) for insn in code))


if __name__ == '__main__':
    # Test
    code = build_htmlscript_hook(
        base_vm=0x200000000,
        injected_str_addr=0x200001000,
        std_string_insert_addr=0x1001234,
        original_insns=[0xD503201F] * 4,
        return_addr=0x100ed5280
    )
    print(f"Generated {len(code)} bytes of hook code")
    print("First 16 instructions:")
    for i in range(min(16, len(code) // 4)):
        insn = struct.unpack('<I', code[i*4:(i+1)*4])[0]
        print(f"  0x{insn:08x}")
