//! The autostart entries that the tests on a real Windows work with.
//!
//! They are made with Windows' own tools: `reg`, `schtasks`, `sc`, and
//! the shell's object for shortcuts. What those tools show of an entry is
//! what the tests compare: before the file goes into the quarantine and
//! after it is back, to the letter.
//!
//! A scene registers a service, two tasks, three Run values and a
//! Startup shortcut on the machine it runs on. All of them name one file
//! in a temporary folder, which nothing here ever starts, and all are
//! removed again when the scene goes, whatever happened in between. Even
//! so a scene is only made where the environment says in as many words
//! that the machine may be changed: on the hosted runner of the CI, which
//! is deleted after the job, and in the virtual machine, from the kit. A
//! developer's `cargo test` makes none.
//!
//! This file is shared. The tests of `warden-autostart` use it, and those
//! of the command line include it by its path, so that both work with the
//! same entries.

// Each of the tests that share this file uses a part of it.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// The variable that allows a scene, and what it has to say.
pub const ALLOW: &str = "WARDEN_AUTOSTART_TESTS";
/// See [`ALLOW`].
pub const ALLOWED: &str = "this-machine-may-be-changed";

/// The key whose values Windows runs at logon, below a hive.
pub const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
/// The Run value of the user the test runs as.
pub const USER_VALUE: &str = "WardenTestThreat";
/// The Run value of the machine.
pub const MACHINE_VALUE: &str = "WardenTestThreatForAll";
/// The Run value of the machine in the view that 32-bit programs see.
pub const OLD_VIEW_VALUE: &str = "WardenTestThreat32";
/// The task that runs when the user logs on.
pub const TASK: &str = r"\Warden Test\Threat at logon";
/// The task that runs as the system when Windows starts.
pub const BOOT_TASK: &str = r"\Warden Test\Threat at boot";
/// The service.
pub const SERVICE: &str = "WardenTestThreat";
/// The file name of the shortcut in the user's Startup folder.
pub const SHORTCUT: &str = "WardenTestThreat.lnk";
/// How many entries a scene makes.
pub const ENTRIES: usize = 7;

/// What one of Windows' tools shows of each entry, by a name for the
/// view. An entry that is not there shows as `None`.
pub type Views = Vec<(&'static str, Option<String>)>;

/// Whether this machine may be changed. Says why not, if not.
pub fn may_change_the_machine() -> bool {
    if std::env::var(ALLOW).as_deref() == Ok(ALLOWED) {
        return true;
    }
    eprintln!(
        "skipped: this test registers a service, tasks, Run values and a shortcut. It runs where {ALLOW} is set to {ALLOWED}."
    );
    false
}

/// Runs one of Windows' tools. Returns whether it succeeded, and what it
/// printed on both streams. It gets no input, so a tool that asks a
/// question fails and does not wait.
pub fn tool(program: &str, arguments: &[&str]) -> (bool, String) {
    let output = Process::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error| panic!("{program} cannot be started: {error}"));
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), text)
}

/// Runs a tool that has to succeed.
pub fn must(program: &str, arguments: &[&str]) -> String {
    let (ok, text) = tool(program, arguments);
    assert!(ok, "{program} {arguments:?} failed:\n{text}");
    text
}

/// Runs a script in the PowerShell that every Windows has.
pub fn powershell(script: &str) -> (bool, String) {
    tool(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", script],
    )
}

/// The names by which the entries of a scene are told apart in what
/// Warden prints, one for each.
pub fn names() -> Vec<String> {
    vec![
        format!("\"{USER_VALUE}\""),
        format!("\"{MACHINE_VALUE}\""),
        format!("\"{OLD_VIEW_VALUE}\""),
        format!("the scheduled task {TASK}"),
        format!("the scheduled task {BOOT_TASK}"),
        format!("the service {SERVICE}"),
        SHORTCUT.to_owned(),
    ]
}

/// The entries, and the file they start. One scene at a time: the names
/// are the same for all.
pub struct Scene {
    dir: tempfile::TempDir,
    shortcut: PathBuf,
    short_path: String,
    _alone: MutexGuard<'static, ()>,
}

impl Scene {
    /// Makes the file and the entries that start it.
    pub fn set_up() -> Self {
        static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
        let alone = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);

        // A folder with blanks in its name, as a user's folder can have.
        let dir = tempfile::Builder::new()
            .prefix("Warden test scene ")
            .tempdir()
            .expect("a temporary folder");
        // A real program that nothing here starts: a copy of this test.
        let threat = dir.path().join("threat.exe");
        fs::copy(std::env::current_exe().expect("this test's file"), &threat)
            .expect("a copy of this test");
        let threat = threat.display().to_string();
        assert!(!threat.contains('\''), "{threat} cannot be quoted");

        // Two things only Windows knows: how it shortens the path for
        // programs of old, and where this user's Startup folder is.
        let (ok, answers) = powershell(&format!(
            "(New-Object -ComObject Scripting.FileSystemObject).GetFile('{threat}').ShortPath; \
             $startup = [Environment]::GetFolderPath('Startup'); \
             New-Item -ItemType Directory -Force -Path $startup | Out-Null; $startup"
        ));
        assert!(ok, "PowerShell failed:\n{answers}");
        let mut answers = answers
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty());
        let short_path = answers.next().expect("the short path").to_owned();
        let startup = answers.next().expect("the Startup folder").to_owned();

        let scene = Self {
            shortcut: Path::new(&startup).join(SHORTCUT),
            short_path,
            dir,
            _alone: alone,
        };
        scene.clear();
        scene.make(&threat);
        scene
    }

    fn make(&self, threat: &str) {
        // As most programs write it: quoted, with what is passed to it.
        must(
            "reg",
            &[
                "add",
                &format!(r"HKCU\{RUN_KEY}"),
                "/v",
                USER_VALUE,
                "/t",
                "REG_SZ",
                "/d",
                &format!("\"{threat}\" --from-run"),
                "/f",
            ],
        );
        // For everybody, as something passed to a program of Windows, and
        // with a variable for Windows to fill in where the path allows.
        let drive = std::env::var("SystemDrive").unwrap_or_default();
        let with_variable = match threat.get(..drive.len()) {
            Some(start) if !drive.is_empty() && start.eq_ignore_ascii_case(&drive) => {
                format!("%SystemDrive%{}", &threat[drive.len()..])
            }
            _ => threat.to_owned(),
        };
        must(
            "reg",
            &[
                "add",
                &format!(r"HKLM\{RUN_KEY}"),
                "/v",
                MACHINE_VALUE,
                "/t",
                "REG_EXPAND_SZ",
                "/d",
                &format!("rundll32.exe \"{with_variable}\",Start"),
                "/f",
            ],
        );
        // In the view that 32-bit programs see: bare, and in the short
        // form of the path.
        must(
            "reg",
            &[
                "add",
                &format!(r"HKLM\{RUN_KEY}"),
                "/v",
                OLD_VIEW_VALUE,
                "/t",
                "REG_SZ",
                "/d",
                &self.short_path,
                "/f",
                "/reg:32",
            ],
        );
        // As the user who is logged on, at logon.
        must(
            "schtasks",
            &[
                "/create",
                "/tn",
                TASK,
                "/tr",
                &format!("\"{threat}\" --from-task"),
                "/sc",
                "onlogon",
                "/f",
            ],
        );
        // As the system, when Windows starts.
        must(
            "schtasks",
            &[
                "/create",
                "/tn",
                BOOT_TASK,
                "/tr",
                &format!("\"{threat}\" --from-boot-task"),
                "/sc",
                "onstart",
                "/ru",
                "SYSTEM",
                "/f",
            ],
        );
        // A service that starts with Windows, with every setting that
        // `sc` can give one beyond the basic ones, and with a key of its
        // own below its key, as services keep their parameters.
        must(
            "sc",
            &[
                "create",
                SERVICE,
                "binPath=",
                &format!("\"{threat}\" --service"),
                "start=",
                "delayed-auto",
                "DisplayName=",
                "Warden test threat",
            ],
        );
        must(
            "sc",
            &[
                "description",
                SERVICE,
                "A harmless stand-in for a threat, made by a test of Warden.",
            ],
        );
        must(
            "sc",
            &[
                "failure",
                SERVICE,
                "reset=",
                "86400",
                "actions=",
                "restart/60000",
            ],
        );
        must("sc", &["sidtype", SERVICE, "unrestricted"]);
        must(
            "sc",
            &[
                "privs",
                SERVICE,
                "SeChangeNotifyPrivilege/SeImpersonatePrivilege",
            ],
        );
        // Three events that start it by itself: one that needs no more
        // words, one narrowed down by a text and one by bytes. The last
        // two wait for a provider of events that does not exist.
        must(
            "sc",
            &[
                "triggerinfo",
                SERVICE,
                "start/networkon",
                "start/strcustom/6f1c5b2e-9d1a-4c1e-8a57-1c0d7f3a2b11/warden-test",
                "start/custom/6f1c5b2e-9d1a-4c1e-8a57-1c0d7f3a2b12/ABCD0102",
            ],
        );
        let parameters = format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{SERVICE}\Parameters");
        for (key, name, kind, data) in [
            (
                parameters.clone(),
                "Setting",
                "REG_SZ",
                "kept with the service",
            ),
            (parameters.clone(), "Several", "REG_MULTI_SZ", r"one\0two"),
            (format!(r"{parameters}\Deeper"), "Count", "REG_DWORD", "7"),
            (
                format!(r"{parameters}\Deeper"),
                "Bytes",
                "REG_BINARY",
                "00ff10",
            ),
        ] {
            must(
                "reg",
                &["add", &key, "/v", name, "/t", kind, "/d", data, "/f"],
            );
        }
        // A shortcut in the folder whose shortcuts Windows opens at logon.
        let shortcut = self.shortcut.display().to_string();
        assert!(!shortcut.contains('\''), "{shortcut} cannot be quoted");
        let (ok, text) = powershell(&format!(
            "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{shortcut}'); \
             $s.TargetPath = '{threat}'; $s.Arguments = '--from-shortcut'; $s.Save()"
        ));
        assert!(
            ok && self.shortcut.is_file(),
            "no shortcut was made:\n{text}"
        );
    }

    /// The file that the entries start.
    pub fn threat(&self) -> PathBuf {
        self.dir.path().join("threat.exe")
    }

    /// The path of the file in the short form, as one of the entries
    /// writes it. The same as the usual form where Windows keeps no
    /// short names.
    pub fn short_path(&self) -> &str {
        &self.short_path
    }

    /// A folder of the scene's own, gone with it.
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// The shortcut in the Startup folder.
    pub fn shortcut(&self) -> &Path {
        &self.shortcut
    }

    /// Removes everything a scene makes, whether it is there or not.
    pub fn clear(&self) {
        let _ = tool(
            "reg",
            &[
                "delete",
                &format!(r"HKCU\{RUN_KEY}"),
                "/v",
                USER_VALUE,
                "/f",
            ],
        );
        let _ = tool(
            "reg",
            &[
                "delete",
                &format!(r"HKLM\{RUN_KEY}"),
                "/v",
                MACHINE_VALUE,
                "/f",
            ],
        );
        let _ = tool(
            "reg",
            &[
                "delete",
                &format!(r"HKLM\{RUN_KEY}"),
                "/v",
                OLD_VIEW_VALUE,
                "/f",
                "/reg:32",
            ],
        );
        let _ = tool("schtasks", &["/delete", "/tn", TASK, "/f"]);
        let _ = tool("schtasks", &["/delete", "/tn", BOOT_TASK, "/f"]);
        let _ = tool("sc", &["delete", SERVICE]);
        let _ = fs::remove_file(&self.shortcut);
    }

    /// What Windows' own tools show of each entry.
    pub fn shown_by_windows(&self) -> Views {
        let shown = |program: &str, arguments: &[&str]| {
            let (ok, text) = tool(program, arguments);
            ok.then_some(text)
        };
        let service_key = format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{SERVICE}");
        // Who may do what with each task: nothing that comes with Windows
        // prints it, so the Task Scheduler is asked through its own
        // interface for scripts. One line for each task, empty if the
        // task is not there.
        let (_, rights) = powershell(&format!(
            "$s = New-Object -ComObject Schedule.Service; $s.Connect(); \
             foreach ($path in @('{TASK}', '{BOOT_TASK}')) {{ \
               try {{ $s.GetFolder('\\').GetTask($path).GetSecurityDescriptor(7) }} \
               catch {{ 'none' }} }}"
        ));
        let mut rights = rights
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(|line| (line != "none").then(|| line.to_owned()));
        let task_rights = rights.next().flatten();
        let boot_task_rights = rights.next().flatten();
        vec![
            (
                "the user's Run value",
                shown(
                    "reg",
                    &["query", &format!(r"HKCU\{RUN_KEY}"), "/v", USER_VALUE],
                ),
            ),
            (
                "the machine's Run value",
                shown(
                    "reg",
                    &["query", &format!(r"HKLM\{RUN_KEY}"), "/v", MACHINE_VALUE],
                ),
            ),
            (
                "the Run value in the 32-bit view",
                shown(
                    "reg",
                    &[
                        "query",
                        &format!(r"HKLM\{RUN_KEY}"),
                        "/v",
                        OLD_VIEW_VALUE,
                        "/reg:32",
                    ],
                ),
            ),
            (
                "the logon task's definition",
                shown("schtasks", &["/query", "/tn", TASK, "/xml"]),
            ),
            ("who may do what with the logon task", task_rights),
            (
                "the boot task's definition",
                shown("schtasks", &["/query", "/tn", BOOT_TASK, "/xml"]),
            ),
            ("who may do what with the boot task", boot_task_rights),
            ("the service's settings", shown("sc", &["qc", SERVICE])),
            (
                "the service's description",
                shown("sc", &["qdescription", SERVICE]),
            ),
            (
                "what happens when the service fails",
                shown("sc", &["qfailure", SERVICE]),
            ),
            (
                "the service's own identity",
                shown("sc", &["qsidtype", SERVICE]),
            ),
            (
                "the privileges the service asks for",
                shown("sc", &["qprivs", SERVICE]),
            ),
            (
                "what starts the service by itself",
                shown("sc", &["qtriggerinfo", SERVICE]),
            ),
            (
                "who may do what with the service",
                shown("sc", &["sdshow", SERVICE]),
            ),
            (
                // A key lists its values in the order they were made in,
                // which means nothing to Windows. The lines are put in
                // order so that only what the key holds is compared.
                "the service's key in the registry, its lines in order",
                shown("reg", &["query", &service_key, "/s"]).map(|text| {
                    let mut lines: Vec<&str> = text
                        .lines()
                        .map(str::trim_end)
                        .filter(|line| !line.is_empty())
                        .collect();
                    lines.sort_unstable();
                    lines.join("\n")
                }),
            ),
            (
                "the shortcut, byte for byte",
                fs::read(&self.shortcut).ok().map(|bytes| {
                    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
                    format!("{} bytes: {hex}", bytes.len())
                }),
            ),
        ]
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        self.clear();
        // The folder the two tasks were in. It goes only if it is empty.
        let _ = powershell(
            "$s = New-Object -ComObject Schedule.Service; $s.Connect(); \
             try { $s.GetFolder('\\').DeleteFolder('Warden Test', 0) } catch { }",
        );
    }
}

/// What a test found wrong. Collected, so that one run says everything
/// there is to say: a round trip through CI is slow.
#[derive(Debug, Default)]
pub struct Report {
    wrong: Vec<String>,
}

impl Report {
    /// Notes something that is wrong.
    pub fn wrong(&mut self, what: impl Into<String>) {
        let what = what.into();
        eprintln!("WRONG: {what}\n");
        self.wrong.push(what);
    }

    /// Notes `what` as wrong unless `holds`.
    pub fn check(&mut self, holds: bool, what: impl FnOnce() -> String) {
        if !holds {
            self.wrong(what());
        }
    }

    /// Windows' tools have to show every entry.
    pub fn all_there(&mut self, views: &Views) {
        for (what, shown) in views {
            self.check(shown.is_some(), || {
                format!("{what}: Windows does not show it")
            });
        }
    }

    /// Windows' tools have to show none of the entries.
    pub fn all_gone(&mut self, views: &Views) {
        for (what, shown) in views {
            if let Some(shown) = shown {
                self.wrong(format!("{what}: it is still there:\n{shown}"));
            }
        }
    }

    /// Windows' tools have to show every entry as they showed it before.
    pub fn same_as_before(&mut self, before: &Views, now: &Views) {
        for ((what, then), (_, now)) in before.iter().zip(now) {
            if then != now {
                self.wrong(format!(
                    "{what}: it is not what it was.\n--- before ---\n{}\n--- now ---\n{}",
                    then.as_deref().unwrap_or("(not there)"),
                    now.as_deref().unwrap_or("(not there)")
                ));
            }
        }
    }

    /// Fails the test if anything was noted, with all of it.
    pub fn finish(self) {
        assert!(
            self.wrong.is_empty(),
            "{} things are wrong:\n\n{}",
            self.wrong.len(),
            self.wrong.join("\n\n")
        );
    }
}

/// Prints what Windows' tools show, for the log of a run.
pub fn print_views(heading: &str, views: &Views) {
    println!("==== {heading} ====");
    for (what, shown) in views {
        println!("---- {what} ----");
        println!("{}", shown.as_deref().unwrap_or("(not there)").trim_end());
    }
    println!();
}
