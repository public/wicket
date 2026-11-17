//! Where a run supervisor's own output goes. A run started by the operator prints to this
//! process's stdout and stderr; a spawned child's supervisor runs in its parent's process (#257
//! slice 4c), on a thread of its own, and prints to its log in the parent's `children/` instead.
//! [`say!`] and [`say_err!`] are `println!` and `eprintln!` that follow that thread's log, and
//! never panic: a supervisor whose stdout is gone (a closed pipe, a full disk) carries on
//! supervising its box, and loses only what it would have printed.
//!
//! Here (#219) so that wicket-home's modules that long-running processes call ([`crate::nodeauth`])
//! print the same way, to the same thread's log; wicket-cli's guard test checks them too.

use std::cell::RefCell;
use std::io::Write;

thread_local! {
    static LOG: RefCell<Option<std::fs::File>> = const { RefCell::new(None) };
}

/// Sends what this thread's supervisor prints to `log` from now on.
pub fn to(log: std::fs::File) {
    LOG.with(|l| *l.borrow_mut() = Some(log));
}

#[doc(hidden)]
pub fn line(err: bool, a: std::fmt::Arguments<'_>) {
    LOG.with(|l| match &mut *l.borrow_mut() {
        Some(f) => {
            let _ = writeln!(f, "{a}");
        }
        None if err => {
            let _ = writeln!(std::io::stderr().lock(), "{a}");
        }
        None => {
            let _ = writeln!(std::io::stdout().lock(), "{a}");
        }
    })
}

/// `println!`, to this thread's supervisor log if it has one.
#[macro_export]
macro_rules! say {
    () => { $crate::out::line(false, format_args!("")) };
    ($($t:tt)*) => { $crate::out::line(false, format_args!($($t)*)) };
}

/// `eprintln!`, to this thread's supervisor log if it has one.
#[macro_export]
macro_rules! say_err {
    ($($t:tt)*) => { $crate::out::line(true, format_args!($($t)*)) };
}
