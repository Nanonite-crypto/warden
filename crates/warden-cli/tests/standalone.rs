//! The built program, looked at as a file: what it needs from the machine
//! it is started on.

#![allow(clippy::unwrap_used)]

/// Warden has to start on a Windows that nobody has prepared. The program
/// is read with Warden's own reader for executables, and may not ask for a
/// library that only comes with Microsoft's Visual C++ runtime. The build
/// setting that sees to it is in `.cargo/config.toml`.
#[cfg(windows)]
#[test]
fn the_program_needs_no_library_that_a_fresh_windows_lacks() {
    let bytes = std::fs::read(env!("CARGO_BIN_EXE_warden")).unwrap();
    let facts = warden_pe::read(&bytes).unwrap();
    let libraries: Vec<String> = facts
        .imports
        .iter()
        .map(|library| library.name.to_ascii_lowercase())
        .collect();
    assert!(
        libraries.iter().any(|name| name == "kernel32.dll"),
        "the import table was not read: {libraries:?}"
    );
    // The families of the Visual C++ runtime: the compiler's support
    // library, the C++ standard library, and the C runtime in its old and
    // its debug form.
    let not_part_of_windows = [
        "vcruntime",
        "msvcp",
        "msvcr",
        "vccorlib",
        "concrt",
        "ucrtbased",
    ];
    let missing_on_a_fresh_windows: Vec<&String> = libraries
        .iter()
        .filter(|name| {
            not_part_of_windows
                .iter()
                .any(|family| name.starts_with(family))
        })
        .collect();
    assert!(
        missing_on_a_fresh_windows.is_empty(),
        "warden.exe loads {missing_on_a_fresh_windows:?}, which a fresh Windows does not have; \
         is RUSTFLAGS set, so that .cargo/config.toml is ignored?"
    );
}

/// Everywhere else the program is an ordinary one: it is found and it is an
/// executable of the system's own kind, which is all there is to check.
#[cfg(not(windows))]
#[test]
fn the_program_is_where_the_tests_expect_it() {
    let bytes = std::fs::read(env!("CARGO_BIN_EXE_warden")).unwrap();
    assert!(bytes.len() > 1024);
    assert!(!warden_pe::looks_like_pe(&bytes));
}
