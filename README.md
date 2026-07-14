# bpf-mini

A ~90-line Rust interpreter that models the *shape* of the original
Berkeley Packet Filter: one accumulator, no general-purpose registers,
a linear list of instructions, and a conditional jump. It loads two
fake "packets" and decides accept/reject based on a hardcoded filter
program.

```
$ cargo run
tcp_packet: ACCEPT
udp_packet: REJECT
```

It's not a byte-exact reimplementation of real cBPF opcodes — it's
small on purpose, so the model fits in your head. The point of this
repo isn't the code, it's the idea the code stands in for.

## What is BPF

BPF — Berkeley Packet Filter — showed up in 1992 as a way to filter
network packets without a full syscall round-trip into the kernel for
every single packet. The trick: let the *filter itself* be a tiny
program, expressed in a deliberately minimal instruction set, and run
it directly in kernel space against each packet's bytes.

The instruction set is intentionally weak. One accumulator, one index
register, a handful of ALU and jump ops, no loops that can't
terminate. That weakness is the feature — a filter program is trivial
to verify as safe before you ever run it, because there isn't enough
expressive power to do anything dangerous. `tcpdump`'s `-dd` flag will
still print you real cBPF bytecode today if you want to see the actual
opcode encoding.

The interpreter in this repo is that same shape, minus the kernel and
minus byte-exact opcodes: an accumulator, a program, a packet, a
verdict.

## How eBPF is an upgrade

eBPF (extended BPF, landed in Linux ~2014) took the same "run a small
sandboxed program against kernel data" idea and generalized it hard:

- **1 accumulator → 10 general-purpose registers.** It's a real
  register machine now, not an accumulator machine.
- **Packet filtering only → attach almost anywhere.** Tracepoints,
  kprobes, XDP, cgroups, syscalls — eBPF programs hook into all of it,
  not just sockets.
- **Interpreted only → JIT compiled.** Programs get compiled to native
  machine code before running, so the overhead approaches zero.
- **Stateless → maps.** eBPF programs can read and write persistent
  key-value maps, shared with userspace. That turns "filter" into
  "general small sandboxed program with state."
- **Trust by simplicity → an actual verifier.** Because eBPF is
  expressive enough to write real logic, the kernel runs a static
  analysis pass over every program before loading it — checking
  bounded loops, safe memory access, reachable exit — to prove it's
  safe *without running it*.

Short version: cBPF filters packets. eBPF runs programs.

## A hint of sBPF

Solana's on-chain programs run on SBF (Solana Bytecode Format) — a
fork of eBPF, executed via `rbpf`, a Rust eBPF virtual machine. That's
not a coincidence of convenience. A blockchain VM needs exactly what
eBPF had already built: deterministic execution, a sandbox with no
escape hatch, a verifier that rejects unsafe or unbounded programs
*before* they run (you really don't want a validator to discover a
program loops forever only after spending the gas), and a JIT for
speed since every validator re-executes every program. Rather than
design all of that from scratch, Solana started from a VM that had
already solved it for the kernel.

That's as far as this post goes — the actual sBPF differences (custom
syscalls, its own ISA quirks, how the verifier rules differ from
Linux's) are their own piece.

## Running it

```
cargo run
cargo test
```
