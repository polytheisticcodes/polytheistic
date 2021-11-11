# Polytheistic Codes

In the beginning there was hardware and there was software.

Hardware was the physical "stuff" of computers... these physical things
were [strung together](https://en.wikipedia.org/wiki/Magnetic-core_memory),
[wrapped up](https://en.wikipedia.org/wiki/Wire_wrap),
and [melted](https://www.google.com/search?q=solder+images).

Software was maliable and mutable. Maybe programs were punched on
[paper](https://en.wikipedia.org/wiki/Punched_tape) or [cards](https://en.wikipedia.org/wiki/Punched_card),
stored on [magnetic tape](https://en.wikipedia.org/wiki/Magnetic_tape), or [rotating magnetic media](https://en.wikipedia.org/wiki/History_of_hard_disk_drives).
In all cases, changing the program was editing (physically splicing punched tape, re-arranging punched cards, saving a new verion on
magnetic media) and re-running.

As hardware got more complex, associating physically masked gates with increasingly complex logic overwhelmed
human brain caches... and verification of logic designs begat tools for "softly" describing a system
and then verifying it: [Verilog](https://en.wikipedia.org/wiki/Verilog).

Increasingly, hardware was described like software.

And software tooling evolved from sequences of instructions where the sequence mattered to
more abstract descriptions of relationships and transformations... where the current
state of the art is embodied by [Haskell](https://en.wikipedia.org/wiki/Haskell_(programming_language))
and [Excel](https://en.wikipedia.org/wiki/Spreadsheet).

With [Field Programmable Gate Arrays](https://en.wikipedia.org/wiki/Field-programmable_gate_array), there
is a partial integration of software and hardware concepts... the hardware can be programmed and
re-programmed. However, because FPGAs present a collection of gates, the tooling around FPGAs
has evolved from the hardware side.

So... why can't we simply compile code to run as hardware? The [halting problem](https://en.wikipedia.org/wiki/Halting_problem).

If we can't determine if a program will terminate, we cannot create a linear circuit that describes the
transformations the program makes... or more specifically, the circuit would be infinitely large.

But certain classes of programs can deterministically halt... there are verification techniques
that guarantee termination. [eBPF](https://ebpf.io/) programs run in the Linux
Kernel and are guaranteed to [terminate](https://lwn.net/Articles/773605/).

So, you can pray to the hardware gods or the software gods... and being able
to use eBPF tooling to generate hardware descriptions lets you use
modern and [evolving](https://thenewstack.io/isovalent-harnesses-ebpf-for-cloud-native-security-visibility/)
tooling to describe code that can run in the Linux Kernel, in [user-space](https://docs.rs/rbpf/0.1.0/rbpf/),
and maybe now in hardware.

Polytheistic is a project to convert eBPF (and maybe a subset of [WASM](https://en.wikipedia.org/wiki/WebAssembly))
code to Verilog to use to describe hardware.

Dual License: Apache 2.0 or MIT at your choice.

Info on [Twitter](https://twitter.com/polytheisticcd)
