# Multiverse

*Multiverse* is a static binary rewriter with an emphasis on simplicity and correctness.  It does not rely on heuristics to perfrom its rewriting, and it attempts to make as few assumptions as possible to produce a rewritten binary.  Details about Multiverse can be found in the paper "Superset Disassembly: Statically Rewriting x86 Binaries Without Heuristics."

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

Multiverse can be run directly, but this will only rewrite binaries with no instrumentation.  This can be used to make sure that everything is installed correctly or to debug changes to the rewriter.  Running `multiverse.py` on a binary will rewrite it.  It can be run like this: `python multiverse.py [options] <filename>`.  There are several flags that can be passed to Multiverse to control how a binary is rewritten:
* --so to rewrite a shared object
* --execonly to rewrite only a main binary (it will use the original, unmodified libraries)
* --nopic to write a binary without support for arbitrary position-independent code.  It still supports common compiler-generated pic, but not arbitrary accesses to the program counter.
* --arch to select the architecture of the binary.  Current supported architectures are `x86` and `x86-64`.  The default is `x86`.

`rewrite.py` is a utility script to rewrite a binary and its libraries, so that `multiverse.py` does not have to be run manually.

## Instrumentation

Multiverse is used as a Python library to instrument binaries.  Right now, the instrumentation API is very simple and consists only of the function `set_before_inst_callback`, which takes a function that is called for every instruction that is encountered and will insert whichever bytes the callback function returns before the corresponding instruction.  The callback function should accept a single argument: an instruction object, as created by the Capstone disassembler.  It should return a byte array containing the assembled instructions to be inserted.

In order to use multiverse, a script should import the Rewriter object (`from multiverse import Rewriter`) and then create an instance of Rewriter.  Its constructor takes three boolean arguments:
* `write_so` to rewrite a shared object
* `exec_only` to rewrite only a main binary (it will use the original, unmodified libraries)
* `no_pic` to write a binary without support for arbitrary position-independent code.  It still supports common compiler-generated pic, but not arbitrary accesses to the program counter.

`exec_only` and `no_pic` are performance optimizations that will not work on all binaries.  For a main executable, `write_so` should be False, and for shared objects, `write_so` should be True.  If `exec_only` is False, then all shared objects used by the binary must be rewritten.

Two simple instrumentation examples can be found in `icount.py` (insert code to increment a counter before every instruction) and `addnop.py` (insert a nop before every instruction).

We are working on a higher-level API that will allow code written in C to be seamlessly called at instrumentation points, but it is not yet available.
