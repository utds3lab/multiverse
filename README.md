# Multiverse

*Multiverse* is a static binary rewriter with an emphasis on simplicity and correctness.  It does not rely on heuristics to perform its rewriting, and it attempts to make as few assumptions as possible to produce a rewritten binary.  Details about Multiverse can be found in the paper "Superset Disassembly: Statically Rewriting x86 Binaries Without Heuristics."

Multiverse currently supports 32-bit and 64-bit x86 binaries.

## Requirements

Multiverse requires the following Python libraries:
* capstone (linear disassembler) (we use a slightly modified version that is needed to rewrite 64-bit binaries.  Our modified version can be found [here](https://github.com/baumane/capstone))
* pwntools (for its assembler bindings)
* pyelftools (for reading elf binaries)
* elfmanip (for modifying elf binaries) (can be found [here](https://github.com/schieb/ELFManip))

## Compiling

Multiverse is written in Python, but its code to generate a binary's global mapping is written in C.  This must be compiled before binaries can be rewritten.  To do so, run `make` and the global mapping code will be compiled.

## Running

Multiverse can be run directly, but this will only rewrite binaries with no instrumentation.  This can be used to make sure that everything is installed correctly or to debug changes to the rewriter.  Running `multiverse.py` on a binary will rewrite it.  It can be run like this: `./multiverse.py [options] <filename>`.  There are several flags that can be passed to Multiverse to control how a binary is rewritten:
* --so to rewrite a shared object
* --execonly to rewrite only a main binary (it will use the original, unmodified libraries)
* --nopic to write a binary without support for arbitrary position-independent code.  It still supports common compiler-generated pic, but not arbitrary accesses to the program counter.  This is not currently recommended for 64-bit binaries.
* --arch to select the architecture of the binary.  Current supported architectures are `x86` and `x86-64`.  The default is `x86`.

Rewritten binaries are named as the original filename with "-r" appended (e.g. `simplest64` becomes `simplest64-r`).

Rewritten binaries *must* be run with the `LD_BIND_NOW` environment variable set to 1.  This prevents control from flowing to the dynamic linker at runtime.  Since we do not rewrite the dynamic linker, this is necessary for correct execution (e.g. to run `simplest-r`, type `LD_BIND_NOW=1 ./simplest-r`).

A very simple example program is provided (`simplest.c`), which is automatically compiled when building Multiverse's global mapping code.  This can be used to test that Multiverse is installed correctly.  For example, to rewrite only the main executable for `simplest64`, the 64-bit version of `simplest`, type `./multiverse.py --execonly --arch x86-64 simplest64` and then run it with `LD_BIND_NOW=1 ./simplest64-r`.

`rewrite.py` is a utility script to rewrite a binary and its libraries, so that `multiverse.py` does not have to be run manually for each library, and it automatically creates a directory for the rewritten libraries, plus a shell script to run the rewritten binary.  For simplicity when rewriting binaries, we recommend using this script.  For example, to rewrite `simplest64`, type `./rewrite.py -64 simplest64`, and the script will rewrite the main binary and all its required libraries (as long as they are not dynamically loaded via a mechanism such as `dlopen`; since statically determining dynamically loaded libraries is difficult, they must be manually extracted and their paths be placed in `<filename>-dynamic-libs.txt`, and then `rewrite.py` will rewrite them).  This may take several minutes.  When it is complete, run the rewritten binary with `bash simplest64-r.sh`.

## Instrumentation

Multiverse is used as a Python library to instrument binaries.  Right now, the instrumentation API is very simple and consists only of the function `set_before_inst_callback`, which takes a function that is called for every instruction that is encountered and will insert whichever bytes the callback function returns before the corresponding instruction.  The callback function should accept a single argument: an instruction object, as created by the Capstone disassembler.  It should return a byte array containing the assembled instructions to be inserted.

In order to use multiverse, a script should import the Rewriter object (`from multiverse import Rewriter`) and then create an instance of Rewriter.  Its constructor takes three boolean arguments:
* `write_so` to rewrite a shared object
* `exec_only` to rewrite only a main binary (it will use the original, unmodified libraries)
* `no_pic` to write a binary without support for arbitrary position-independent code.  It still supports common compiler-generated pic, but not arbitrary accesses to the program counter.  This is not currently recommended for 64-bit binaries.

`exec_only` and `no_pic` are performance optimizations that will not work on all binaries.  For a main executable, `write_so` should be False, and for shared objects, `write_so` should be True.  If `exec_only` is False, then all shared objects used by the binary must be rewritten.

Two simple instrumentation examples can be found in `icount.py` (insert code to increment a counter before every instruction) and `addnop.py` (insert a nop before every instruction).  These are currently configured to instrument only the main executable of 64-bit binaries.  For example, to insert nops into `simplest64`, type `python addnop.py simplest64`, and to run the instrumented binary, type `LD_BIND_NOW=1 ./simplest64-r`.

We are working on a higher-level API that will allow code written in C to be seamlessly called at instrumentation points, but it is not yet available.

## Citing

If you create a research work that uses Multiverse, please cite the associated paper:

```
@inproceedings{Multiverse:NDSS18,
  author    = {Erick Bauman and Zhiqiang Lin and Kevin Hamlen},
  title     = {Superset Disassembly: Statically Rewriting x86 Binaries Without Heuristics},
  booktitle = {Proceedings of the 25th Annual Network and Distributed System Security Symposium (NDSS'18)},
  address   = {San Diego, CA},
  month     = {February},
  year      = 2018,
}
```
