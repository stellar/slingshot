//! Type-safe program builder

use crate::{Program, ProgramItem, String};

// What we want: ".dup::<N>()" is available on a state that has N+1 items, expands state and records the bytecode.

/// Value type that is encoded as String type on VM stack
pub trait StringArgument {
    /// Encodes the abstract argument into a VM String
    fn to_string(&self) -> String;
}

/// Value type that can be copied in the VM
pub trait CopyableArgument {
    /// Produces a copy of the argument
    fn copy(&self) -> Self;
}

/// Value type that is encoded as Program type on VM stack
pub trait ProgramArgument {
    /// Encodes the abstract argument into a VM ProgramItem
    fn to_program(&self) -> ProgramItem;
}

/// Represents a state of the machine alongside with a program that produces it.
pub struct ProgramState<S0, S> {
    /// Beginning state of the VM to which the program is applied
    base_state: S0,

    /// Final state produced by the program
    state: S,

    /// Program that brings the VM state from S0 to S.
    program: Program,
}

impl<S0, S> ProgramState<S0, S> {
    /// Creates an empty program
    pub fn new() -> ProgramState<(), ()> {
        ProgramState {
            base_state: (),
            state: (),
            program: Program::new(),
        }
    }

    /// Creates an empty program with one-value base state
    pub fn new1<T1: Clone>(v1: T1) -> ProgramState<((), T1), ((), T1)> {
        ProgramState {
            base_state: ((), v1.clone()),
            state: ((), v1),
            program: Program::new(),
        }
    }

    /// Creates an empty program with two-values base state
    pub fn new2<T1: Clone, T2: Clone>(
        v1: T1,
        v2: T2,
    ) -> ProgramState<(((), T1), T2), (((), T1), T2)> {
        ProgramState {
            base_state: (((), v1.clone()), v2.clone()),
            state: (((), v1), v2),
            program: Program::new(),
        }
    }

    /// Pushes a string argument.
    pub fn push<T: StringArgument>(self, value: T) -> ProgramState<S0, (S, T)> {
        let mut program = self.program;
        program.push(value.to_string());
        ProgramState {
            base_state: self.base_state,
            state: (self.state, value),
            program,
        }
    }

    /// Pushes a program argument.
    pub fn program<T: ProgramArgument>(self, value: T) -> ProgramState<S0, (S, T)> {
        let mut program = self.program;
        program.program(value.to_program());
        ProgramState {
            base_state: self.base_state,
            state: (self.state, value),
            program,
        }
    }
}

// For `eval` we need to have top item on the stack such that
// it's a ProgramState whose S0 is equal to the prev state.
impl<S0, S, X> ProgramState<S0, (S, ProgramState<S, X>)> {
    //                           ^               ^
    //                           |_______________|
    //                           |
    // We require program on stack to be bound
    // to the same state S as the stack it's on.
    // This guarantees that the number and types of arguments expected
    // by the inner program are the same as produced by the outer program
    // before the "push prog, eval" instructions are added.

    /// Executes a program that extends the current state S into state X
    pub fn eval(self) -> ProgramState<S0, X> {
        let mut outer_program = self.program;
        outer_program.eval();
        let inner_program = self.state.1;
        ProgramState {
            base_state: self.base_state,
            state: inner_program.state,
            program: outer_program,
        }
    }
}

// For `output` and `contract` instructions
// we want

/// roll:0 is no-op - it simply puts the top item back on top
impl<S0, S, T> ProgramState<S0, (S, T)> {
    /// Implements `roll:0` instruction.
    pub fn roll_0(self) -> ProgramState<S0, (S, T)> {
        let mut program = self.program;
        program.roll(0);
        ProgramState {
            base_state: self.base_state,
            state: self.state,
            program,
        }
    }

    /// Implements `dup:0` instruction.
    pub fn dup_0(self) -> ProgramState<S0, ((S, T), T)>
    where
        T: CopyableArgument,
    {
        let mut program = self.program;
        program.dup(0);
        let value = self.state.1.copy();
        ProgramState {
            base_state: self.base_state,
            state: (self.state, value),
            program,
        }
    }
}

/// roll:1 is a swap of two top items. This means we need a state to have at least two items.
impl<S0, S, T1, T0> ProgramState<S0, ((S, T1), T0)> {
    /// Implements `roll:1` instruction.
    pub fn roll_1(self) -> ProgramState<S0, ((S, T0), T1)> {
        let mut program = self.program;
        program.roll(1);
        ProgramState {
            base_state: self.base_state,
            state: ((self.state.0 .0, self.state.1), self.state.0 .1),
            program,
        }
    }

    /// Implements `dup:1` instruction.
    pub fn dup_1(self) -> ProgramState<S0, (((S, T1), T0), T1)>
    where
        T1: CopyableArgument,
    {
        let mut program = self.program;
        program.dup(1);
        let value = self.state.0 .1.copy();
        ProgramState {
            base_state: self.base_state,
            state: (self.state, value),
            program,
        }
    }
}
