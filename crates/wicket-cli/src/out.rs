//! Where a run supervisor's own output goes. A run started by the operator prints to this
//! process's stdout and stderr; a spawned child's supervisor runs in its parent's process (#257
//! slice 4c), on a thread of its own, and prints to its log in the parent's `children/` instead.
//! [`say!`] and [`say_err!`] are `println!` and `eprintln!` that follow that thread's log.

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
        None if err => eprintln!("{a}"),
        None => println!("{a}"),
    })
}

/// `println!`, to this thread's supervisor log if it has one.
macro_rules! say {
    () => { $crate::out::line(false, format_args!("")) };
    ($($t:tt)*) => { $crate::out::line(false, format_args!($($t)*)) };
}

/// `eprintln!`, to this thread's supervisor log if it has one.
macro_rules! say_err {
    ($($t:tt)*) => { $crate::out::line(true, format_args!($($t)*)) };
}
