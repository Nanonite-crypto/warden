//! Standard output and standard error that can go away.
//!
//! `warden scan … | head` closes the pipe while Warden is still writing, and
//! `println!` panics when a write fails. So everything Warden prints goes
//! through the macros of this module instead.
//!
//! - `out!` and `outln!` write to standard output and hand back a
//!   `Result`. A failed write is an error like any other: the command
//!   stops, what it holds is released in the ordinary way, and `main` ends
//!   the program with the exit code for "could not be carried out". When
//!   the reason is that the reader has left, it does so without a word: the
//!   one who could have read it is gone.
//! - `errln!` writes a remark to standard error and ignores a failure.
//!   There is nowhere left to report it.

use std::fmt;
use std::io::{self, Write};

/// Writing to standard output failed.
#[derive(Debug)]
pub struct OutputError(io::Error);

impl OutputError {
    /// Whether the reader has closed its end: `warden … | head`.
    pub fn reader_has_left(&self) -> bool {
        self.0.kind() == io::ErrorKind::BrokenPipe
    }
}

impl fmt::Display for OutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot write to standard output: {}", self.0)
    }
}

impl std::error::Error for OutputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Writes to standard output. Use `out!` and `outln!`.
pub fn write(text: fmt::Arguments<'_>) -> Result<(), OutputError> {
    write_to(&mut io::stdout().lock(), text)
}

/// Writes to standard error and ignores a failure. Use `errln!`.
pub fn remark(text: fmt::Arguments<'_>) {
    let _ = io::stderr().lock().write_fmt(text);
}

fn write_to(target: &mut dyn Write, text: fmt::Arguments<'_>) -> Result<(), OutputError> {
    target.write_fmt(text).map_err(OutputError)
}

/// `print!` that reports a failed write instead of panicking.
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::out::write(format_args!($($arg)*))
    };
}

/// `println!` that reports a failed write instead of panicking.
macro_rules! outln {
    () => {
        $crate::out::write(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::out::write(format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// `eprintln!` that ignores a failed write instead of panicking.
macro_rules! errln {
    ($($arg:tt)*) => {
        $crate::out::remark(format_args!("{}\n", format_args!($($arg)*)))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader that has left: every write fails the way a closed pipe does.
    struct Closed;

    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A disk that is full.
    struct Full;

    impl Write for Full {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::StorageFull.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_write_that_fails_is_an_error_and_not_a_panic() {
        let error = write_to(&mut Closed, format_args!("a line\n"));
        assert!(error.is_err_and(|error| error.reader_has_left()));
    }

    #[test]
    fn only_a_closed_pipe_counts_as_a_reader_that_left() {
        let Err(error) = write_to(&mut Full, format_args!("a line\n")) else {
            panic!("the write should have failed");
        };
        assert!(!error.reader_has_left());
        assert!(
            error
                .to_string()
                .starts_with("cannot write to standard output")
        );
    }

    #[test]
    fn what_is_written_arrives_as_it_was_given() {
        let mut target = Vec::new();
        let written = write_to(&mut target, format_args!("{} of {}\n", 1, 2));
        assert!(written.is_ok());
        assert_eq!(target, b"1 of 2\n");
    }
}
