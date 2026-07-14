//! A minimal classic-BPF-style interpreter.
//!
//! This is not a real cBPF implementation — no byte-exact opcode
//! encoding, no `jt`/`jf` dual-branch instructions. It's a deliberately
//! small model of the *idea*: one accumulator, no general-purpose
//! registers, a linear instruction stream, and conditional jumps.
//! That's the whole shape of the original BPF machine, and it's the
//! shape eBPF later generalized. See README.md for the full story.

#[derive(Debug, Clone, Copy)]
enum Instruction {
    /// Load a byte from the packet at `offset` into the accumulator.
    LoadByte { offset: usize },
    /// Add an immediate value to the accumulator.
    Add { value: u32 },
    /// Jump `offset` instructions forward if accumulator == value.
    JumpIfEqual { value: u32, offset: usize },
    /// Halt and reject the packet.
    Reject,
    /// Halt and accept the packet.
    Accept,
}

struct Interpreter<'a> {
    program: &'a [Instruction],
    packet: &'a [u8],
    accumulator: u32,
    pc: usize,
}

impl<'a> Interpreter<'a> {
    fn new(program: &'a [Instruction], packet: &'a [u8]) -> Self {
        Self {
            program,
            packet,
            accumulator: 0,
            pc: 0,
        }
    }

    /// Runs the program to completion. Returns true if the packet is accepted.
    fn run(&mut self) -> bool {
        loop {
            match self.program[self.pc] {
                Instruction::LoadByte { offset } => {
                    self.accumulator = *self.packet.get(offset).unwrap_or(&0) as u32;
                    self.pc += 1;
                }
                Instruction::Add { value } => {
                    self.accumulator = self.accumulator.wrapping_add(value);
                    self.pc += 1;
                }
                Instruction::JumpIfEqual { value, offset } => {
                    if self.accumulator == value {
                        self.pc += offset;
                    } else {
                        self.pc += 1;
                    }
                }
                Instruction::Reject => return false,
                Instruction::Accept => return true,
            }
        }
    }
}

fn main() {
    // A fake "packet": byte 0 stands in for an IP protocol number.
    // 6 == TCP, 17 == UDP, in the style of real IP protocol numbers.
    let tcp_packet = [6u8, 0, 0, 0];
    let udp_packet = [17u8, 0, 0, 0];

    // Program: "accept only if byte 0 == 6 (TCP)"
    let program = [
        Instruction::LoadByte { offset: 0 },
        Instruction::JumpIfEqual { value: 6, offset: 2 }, // match -> skip Reject
        Instruction::Reject,
        Instruction::Accept,
    ];

    for (name, packet) in [("tcp_packet", &tcp_packet[..]), ("udp_packet", &udp_packet[..])] {
        let mut vm = Interpreter::new(&program, packet);
        let verdict = if vm.run() { "ACCEPT" } else { "REJECT" };
        println!("{name}: {verdict}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_only_filter() -> [Instruction; 4] {
        [
            Instruction::LoadByte { offset: 0 },
            Instruction::JumpIfEqual { value: 6, offset: 2 },
            Instruction::Reject,
            Instruction::Accept,
        ]
    }

    #[test]
    fn accepts_tcp() {
        let packet = [6u8, 0, 0, 0];
        let program = tcp_only_filter();
        let mut vm = Interpreter::new(&program, &packet);
        assert!(vm.run());
    }

    #[test]
    fn rejects_udp() {
        let packet = [17u8, 0, 0, 0];
        let program = tcp_only_filter();
        let mut vm = Interpreter::new(&program, &packet);
        assert!(!vm.run());
    }
}
