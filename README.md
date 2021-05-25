# Midas ELF64 Injector
## Description
**Midas ELF64 Injector** is a tool that will help you inject a C program from source code into an ELF64 binary. All you need is to write a C program like you always do, and this tool will compile and inject it into the target binary for you, no shellcoding required. The advantage of this over shellcode injection is that you can actually include any library and it would still work, also of course it's more comfortable writing C than ASM.

*Note: This tool was written for an Attack & Defense CTF with an intention to be a one-time-use thing. Therefore, I was only trying to make it works without caring too much about scalability or maintainability.*

## Dependencies
Please note that all the dependencies ***MUST*** be installed with the exact version stated below. Any other version will almost certainly won't work.

1. gcc 9.3.0: [link](http://ftp.gnu.org/gnu/gcc/gcc-9.3.0/)
2. lief 0.11.5: `pip3 install lief==0.11.5`
3. pwntools 4.4.0: `pip3 install pwntools==4.4.0`
4. gdb (any version)

## Usage
```
python3 inject.py <binary> <build_file>
```

- `<binary>`: the target binary to be injected to
- `<build_file>`: a file contains the build command of the C file you want to inject, it ***MUST*** be statically compiled with `-static`, and the output file name ***MUST*** be `tmp.bin`

## How it works?
1. It compiles the C code using the provided build command.
2. It executes the compiled file in `gdb`, use a temporary gdb script to break at `main` and dump the process's `text` and `data`.
3. It adds a segment into the target binary to store some shellcode and the memory snapshot dumped above.
4. It patches `__libc_csu_init` of the target binary to jump to that shellcode. This is what that shellcode does:
   - Map 2 fixed pages for the `text` and `data` at the exact same addresses as a statically compiled binary.
   - Copy injected `text` and `data` to the mapped pages.
   - Call injected `main`.
   - Unmap the 2 pages.
   - Return back to the original target process.

## Limitations
1. There are a lot of hard-coded values, so I'm not sure if it will work 100% of the time.
2. Rely on exact dependencies version.
3. Take a while to run.
4. Will inflate your target size by a lot (expect around 1MB).
5. The target file ***MUST*** be an ELF64 dynamically compiled with PIE enabled.
6. No checking for input files, you have to make sure they are correct by yourself.
