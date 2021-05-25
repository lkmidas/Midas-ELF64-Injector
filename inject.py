import lief
from pwn import *
import sys
import os
context.arch = "amd64"

injected_main_addr = 0

injected_text_start_addr = 0
injected_text_end_addr = 0
injected_text_size = 0

injected_data_start_addr = 0
injected_data_end_addr = 0
injected_data_size = 0


def get_c_snapshot(build_file):
    '''
    Function to compile the input C file and dump its memory snapshot at main
    '''

    global injected_main_addr, injected_text_start_addr, injected_text_end_addr, injected_text_size, injected_data_start_addr, injected_data_end_addr, injected_data_size

    build_command = open(build_file, "r").read()
    os.system(build_command)
    b = lief.parse("./tmp.bin")

    injected_main_addr = b.get_function_address("main")
    injected_text_start_addr = b.get_section(".init").virtual_address & 0xff0000
    injected_text_end_addr = (b.get_section(".gcc_except_table").virtual_address & 0xfff000) + 0x1000 # 0x1000 is hard-coded
    injected_text_size = injected_text_end_addr - injected_text_start_addr
    injected_data_start_addr = b.get_section(".tdata").virtual_address & 0xfff000
    injected_data_end_addr = (b.get_section(".bss").virtual_address & 0xfff000) + 0x25000 # 0x25000 is hard-coded, don't know how to get it
    injected_data_size = injected_data_end_addr - injected_data_start_addr

    gdb_script = '''
        file ./tmp.bin
        b main
        r
        dump memory ./tmp.text {} {}
        dump memory ./tmp.data {} {}
        quit
    '''.format(injected_text_start_addr, injected_text_end_addr, injected_data_start_addr, injected_data_end_addr)
    open("tmp.gdb", "w").write(gdb_script)

    os.system("gdb -q --command=tmp.gdb >> /dev/null")


def build_shellcode():
    '''
    Function to build the shellcode
    '''
    global injected_data_addr

    # Get seccomp text and data
    injected_text = open("./tmp.text", "rb").read()
    injected_data = open("./tmp.data", "rb").read()

    # Save state
    shellcode = asm("push rax; push rbx; push rcx; push rdx; push rdi; push rsi")

    # Map fixed pages for injected code and data
    shellcode += asm(shellcraft.amd64.linux.syscall('SYS_mmap', injected_text_start_addr, injected_text_size, 'PROT_READ | PROT_WRITE | PROT_EXEC', 'MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE', -1, 0))
    shellcode += asm(shellcraft.amd64.linux.syscall('SYS_mmap', injected_data_start_addr, injected_data_size, 'PROT_READ | PROT_WRITE | PROT_EXEC', 'MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE', -1, 0))
    
    # Copy injected code and data to mapped pages
    shellcode += asm("lea rax, [rip+{}]; push {}; pop rbx".format(417, injected_text_start_addr))
    shellcode += asm(shellcraft.amd64.memcpy('rbx', 'rax', len(injected_text)))
    shellcode += asm("lea rax, [rip+{}]; push {}; pop rbx".format(384 + len(injected_text), injected_data_start_addr))
    shellcode += asm(shellcraft.amd64.memcpy('rbx', 'rax', len(injected_data)))

    # Call injected
    shellcode += asm("push {}; pop rax".format(injected_main_addr))
    shellcode += asm("push 0") # alignment
    shellcode += asm("call rax")
    shellcode += asm("pop rbx") # alignment

    # Unmap injected
    shellcode += asm(shellcraft.amd64.linux.syscall('SYS_munmap', injected_text_start_addr, injected_text_size))
    shellcode += asm(shellcraft.amd64.linux.syscall('SYS_munmap', injected_data_start_addr, injected_data_size))

    # Restore state
    shellcode += asm("pop rsi; pop rdi; pop rdx; pop rcx; pop rbx; pop rax")

    # Last __libc_csu_init instructions
    shellcode += asm("pop r12; pop r13; pop r14; pop r15; ret")

    # Add injected snapshot
    shellcode += b"\x90"*(0x200 - len(shellcode))
    shellcode += injected_text
    shellcode += injected_data
    return shellcode


def patch_binary(binary):
    '''
    Function to add new segment into binary and patch init routine to jump to it
    '''

    b = lief.parse(binary)

    # Build new segment
    segment = lief.ELF.Segment()
    segment = lief.ELF.Segment()
    segment.type = lief.ELF.SEGMENT_TYPES.LOAD
    segment.add(lief.ELF.SEGMENT_FLAGS.R)
    segment.add(lief.ELF.SEGMENT_FLAGS.X)

    # Add shellcode as content
    shellcode = build_shellcode()
    segment.content = list(shellcode)
    segment.alignment = 8
    segment = b.add(segment, base=0x1000)

    # Patch hook into __libc_csu_init
    try:
        init = b.get_function_address("__libc_csu_init")
    except:
        init = int(input("__libc_csu_init not found, enter manually (in hex): "), 16)
    hook_addr = init + 92 # 92 is hard-coded, this is the offset to pop r12; pop r13; ... in __libc_csu_init
    hook = asm("jmp $+{}".format(segment.virtual_address - hook_addr))
    hook += b"\x90"*4
    b.patch_address(hook_addr, list(hook))
    
    # Patch binary
    b.write("patched_{}".format(binary))
    os.system("chmod +x patched_{}".format(binary))


def cleanup():
    '''
    Function to cleanup tmp files created in the process
    '''
    os.system("rm tmp.*")


if __name__ == "__main__":
    # Check argc
    if len(sys.argv) != 3:
        print("Usage: python3 inject.py <binary> <build_file>")
        sys.exit()
    # Check if files exist
    if not os.path.isfile(sys.argv[1]) or not os.path.isfile(sys.argv[2]):
        print("Usage: python3 inject.py <binary> <build_file>")
        sys.exit()
    # Get C program memory snapshot
    get_c_snapshot(sys.argv[2])
    # Patch the binary
    patch_binary(sys.argv[1])
    # Cleanup tmp files
    cleanup()
    