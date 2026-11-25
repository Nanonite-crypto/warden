//! What an entry starts: its command lines, with the variables filled in.
//!
//! Windows keeps a command line in a different form in each of the four
//! places, and this module turns each into plain text that
//! [`stands_in`](crate::starts::stands_in) can look through. Nothing here
//! talks to Windows: the variables come from whoever asks, so that the
//! same code can be tried on any system.

use crate::entry::{Entry, RunValue, Service, Shortcut, Task};
use crate::task;

/// A registry value that is a string.
pub const REG_SZ: u32 = 1;
/// A registry value that is a string with variables to fill in.
pub const REG_EXPAND_SZ: u32 = 2;

/// Variables to fill in, such as `SystemRoot`. Names are compared without
/// regard to case, as Windows compares them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Variables(Vec<(String, String)>);

impl Variables {
    /// Variables from pairs of name and value. If a name comes twice, the
    /// first one counts.
    #[must_use]
    pub fn new(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        Self(pairs.into_iter().collect())
    }

    /// The value of a variable, if it is known.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(known, _)| known.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The variables among these that are the same for everybody on the
    /// machine. An entry that does not belong to the user who is asking
    /// is read with these alone: that user's own folders are not the ones
    /// the entry means, and a wrong guess could make an entry look as if
    /// it started a file that it has nothing to do with.
    #[must_use]
    pub fn of_the_machine(&self) -> Self {
        const SAME_FOR_EVERYBODY: [&str; 13] = [
            "SystemRoot",
            "windir",
            "SystemDrive",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "ProgramW6432",
            "CommonProgramFiles",
            "CommonProgramFiles(x86)",
            "CommonProgramW6432",
            "ProgramData",
            "ALLUSERSPROFILE",
            "PUBLIC",
            "ComSpec",
        ];
        Self(
            self.0
                .iter()
                .filter(|(name, _)| {
                    SAME_FOR_EVERYBODY
                        .iter()
                        .any(|same| same.eq_ignore_ascii_case(name))
                })
                .cloned()
                .collect(),
        )
    }
}

/// Fills in the variables of a text, the way Windows does: `%NAME%`
/// becomes the value of `NAME`, and a name that is not known stays as it
/// is written.
#[must_use]
pub fn expand(text: &str, variables: &Variables) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('%') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('%') else {
            // A percent sign with no partner is just that.
            out.push_str(&rest[open..]);
            return out;
        };
        if let Some(value) = variables.get(&after[..close]) {
            out.push_str(value);
            rest = &after[close + 1..];
        } else {
            // Not a variable. The second percent sign may open one.
            out.push('%');
            out.push_str(&after[..close]);
            rest = &after[close..];
        }
    }
    out.push_str(rest);
    out
}

/// The text of a registry value that is a string. The registry stores
/// such text in UTF-16 with a zero at its end, and guarantees neither.
#[must_use]
pub fn reg_string(value_type: u32, data: &[u8]) -> Option<String> {
    if value_type != REG_SZ && value_type != REG_EXPAND_SZ {
        return None;
    }
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|unit| *unit != 0)
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// The bytes the registry stores for a string: UTF-16 with a zero at its
/// end.
#[must_use]
pub fn reg_string_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// The command lines an entry stands for, with variables filled in. An
/// entry that Warden cannot read a command line from, such as a task
/// that sends a message, has none.
#[must_use]
pub fn commands(entry: &Entry, variables: &Variables) -> Vec<String> {
    match entry {
        Entry::RunValue(value) => run_value(value, variables),
        Entry::Task(task) => scheduled_task(task, variables),
        Entry::Service(service) => self::service(service, variables),
        Entry::Shortcut(shortcut) => self::shortcut(shortcut, variables),
    }
}

fn run_value(value: &RunValue, variables: &Variables) -> Vec<String> {
    reg_string(value.value_type, &value.data)
        .map(|text| with_expansion(text, variables))
        .unwrap_or_default()
}

fn scheduled_task(task: &Task, variables: &Variables) -> Vec<String> {
    let Ok(definition) = task::read(&task.xml) else {
        return Vec::new();
    };
    definition
        .actions
        .into_iter()
        .flat_map(|action| {
            let line = if action.arguments.is_empty() {
                action.command
            } else {
                format!("{} {}", action.command, action.arguments)
            };
            with_expansion(line, variables)
        })
        .collect()
}

fn service(service: &Service, variables: &Variables) -> Vec<String> {
    let mut lines = with_expansion(dos_form(&service.image_path), variables);
    // A service that lives in a shared host names its library in the
    // registry, usually below "Parameters".
    for key in [service.key.subkey("Parameters"), Some(&service.key)]
        .into_iter()
        .flatten()
    {
        if let Some(library) = key
            .value("ServiceDll")
            .and_then(|value| reg_string(value.value_type, &value.data))
        {
            lines.extend(with_expansion(library, variables));
        }
    }
    lines
}

fn shortcut(shortcut: &Shortcut, variables: &Variables) -> Vec<String> {
    let mut lines = with_expansion(shortcut.target.clone(), variables);
    if !shortcut.arguments.is_empty() {
        lines.extend(with_expansion(shortcut.arguments.clone(), variables));
    }
    lines
}

/// A line as written, and with its variables filled in if that changes
/// it.
fn with_expansion(line: String, variables: &Variables) -> Vec<String> {
    let expanded = expand(&line, variables);
    if expanded == line {
        vec![line]
    } else {
        vec![line, expanded]
    }
}

/// The program of a service as a path of the kind people write. The
/// service manager also accepts the forms the kernel uses: `\??\C:\x`,
/// `\SystemRoot\x`, and for a driver a path that starts at the Windows
/// folder.
fn dos_form(image: &str) -> String {
    let (quote, inner) = match image.strip_prefix('"') {
        Some(inner) => ("\"", inner),
        None => ("", image),
    };
    if let Some(rest) = strip_prefix_ignoring_case(inner, r"\??\") {
        format!("{quote}{rest}")
    } else if let Some(rest) = strip_prefix_ignoring_case(inner, r"\SystemRoot\") {
        format!(r"{quote}%SystemRoot%\{rest}")
    } else if strip_prefix_ignoring_case(inner, r"System32\").is_some()
        || strip_prefix_ignoring_case(inner, r"SysWOW64\").is_some()
    {
        format!(r"{quote}%SystemRoot%\{inner}")
    } else {
        image.to_owned()
    }
}

fn strip_prefix_ignoring_case<'text>(text: &'text str, prefix: &str) -> Option<&'text str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &text[prefix.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Hive, RegKey, RegValue, SubKey, View};

    fn variables() -> Variables {
        Variables::new([
            ("SystemRoot".to_owned(), r"C:\Windows".to_owned()),
            (
                "APPDATA".to_owned(),
                r"C:\Users\u\AppData\Roaming".to_owned(),
            ),
            ("ProgramFiles".to_owned(), r"C:\Program Files".to_owned()),
        ])
    }

    #[test]
    fn variables_are_filled_in_the_way_windows_does() {
        let variables = variables();
        assert_eq!(
            expand(r"%SystemRoot%\system32\x.exe", &variables),
            r"C:\Windows\system32\x.exe"
        );
        assert_eq!(
            expand(r"%systemroot%\a %APPDATA%\b", &variables),
            r"C:\Windows\a C:\Users\u\AppData\Roaming\b"
        );
        // What is not known stays as written.
        assert_eq!(expand(r"%NoSuchThing%\x", &variables), r"%NoSuchThing%\x");
        // A lone percent sign is one, and the second of two may open a name.
        assert_eq!(expand("100% sure", &variables), "100% sure");
        assert_eq!(expand(r"%%SystemRoot%", &variables), r"%C:\Windows");
        assert_eq!(expand("", &variables), "");
        assert_eq!(expand("%", &variables), "%");
        assert_eq!(expand("%%", &variables), "%%");
        // Text of several bytes a character is left in one piece.
        assert_eq!(expand(r"é%SystemRoot%é", &variables), r"éC:\Windowsé");
    }

    #[test]
    fn only_what_is_the_same_for_everybody_is_kept_for_others() {
        let machine = variables().of_the_machine();
        assert_eq!(machine.get("systemroot"), Some(r"C:\Windows"));
        assert_eq!(machine.get("ProgramFiles"), Some(r"C:\Program Files"));
        assert_eq!(machine.get("APPDATA"), None);
    }

    #[test]
    fn a_registry_string_is_read_with_and_without_its_end() {
        let stored = reg_string_bytes(r"C:\x\a.exe");
        assert_eq!(reg_string(REG_SZ, &stored).as_deref(), Some(r"C:\x\a.exe"));
        // No zero at the end, and a byte too many.
        let mut ragged = stored[..stored.len() - 2].to_vec();
        ragged.push(0x41);
        assert_eq!(
            reg_string(REG_EXPAND_SZ, &ragged).as_deref(),
            Some(r"C:\x\a.exe")
        );
        // What follows the first zero is not part of the string.
        let mut two = stored.clone();
        two.extend(reg_string_bytes("more"));
        assert_eq!(reg_string(REG_SZ, &two).as_deref(), Some(r"C:\x\a.exe"));
        // A number is not a string.
        assert_eq!(reg_string(4, &[1, 0, 0, 0]), None);
        assert_eq!(reg_string(REG_SZ, &[]).as_deref(), Some(""));
    }

    #[test]
    fn a_run_value_gives_its_text_as_written_and_filled_in() {
        let entry = Entry::RunValue(RunValue {
            hive: Hive::Machine,
            view: View::Native,
            key: "Run".to_owned(),
            name: "x".to_owned(),
            value_type: REG_EXPAND_SZ,
            data: reg_string_bytes(r#""%ProgramFiles%\x\a.exe" /min"#),
        });
        assert_eq!(
            commands(&entry, &variables()),
            [
                r#""%ProgramFiles%\x\a.exe" /min"#,
                r#""C:\Program Files\x\a.exe" /min"#
            ]
        );
        let number = Entry::RunValue(RunValue {
            hive: Hive::Machine,
            view: View::Native,
            key: "Run".to_owned(),
            name: "x".to_owned(),
            value_type: 4,
            data: vec![1, 0, 0, 0],
        });
        assert!(commands(&number, &variables()).is_empty());
    }

    fn service_with(image: &str, key: RegKey) -> Entry {
        Entry::Service(Service {
            name: "svc".to_owned(),
            display_name: "svc".to_owned(),
            service_type: 0x20,
            start_type: 2,
            error_control: 1,
            image_path: image.to_owned(),
            load_order_group: String::new(),
            dependencies: Vec::new(),
            account: "LocalSystem".to_owned(),
            security: None,
            key,
        })
    }

    #[test]
    fn a_service_gives_its_program_in_the_form_people_write() {
        let variables = variables();
        let cases = [
            (r"\??\C:\drivers\f.sys", vec![r"C:\drivers\f.sys"]),
            (
                r"\SystemRoot\System32\drivers\f.sys",
                vec![
                    r"%SystemRoot%\System32\drivers\f.sys",
                    r"C:\Windows\System32\drivers\f.sys",
                ],
            ),
            (
                r"system32\DRIVERS\f.sys",
                vec![
                    r"%SystemRoot%\system32\DRIVERS\f.sys",
                    r"C:\Windows\system32\DRIVERS\f.sys",
                ],
            ),
            (
                r#""\??\C:\Program Files\x\s.exe" -k"#,
                vec![r#""C:\Program Files\x\s.exe" -k"#],
            ),
            (
                r#""C:\Program Files\x\s.exe" --run"#,
                vec![r#""C:\Program Files\x\s.exe" --run"#],
            ),
            // Too short to be any of the special forms.
            (r"\?", vec![r"\?"]),
        ];
        for (image, expected) in cases {
            assert_eq!(
                commands(&service_with(image, RegKey::default()), &variables),
                expected,
                "{image}"
            );
        }
    }

    #[test]
    fn a_service_in_a_shared_host_gives_its_library_too() {
        let library = RegValue {
            name: "ServiceDll".to_owned(),
            value_type: REG_EXPAND_SZ,
            data: reg_string_bytes(r"%SystemRoot%\System32\thing.dll"),
        };
        let key = RegKey {
            values: Vec::new(),
            subkeys: vec![SubKey {
                name: "Parameters".to_owned(),
                key: RegKey {
                    values: vec![library],
                    subkeys: Vec::new(),
                },
            }],
        };
        let lines = commands(
            &service_with(r"%SystemRoot%\system32\svchost.exe -k netsvcs", key),
            &variables(),
        );
        assert_eq!(
            lines,
            [
                r"%SystemRoot%\system32\svchost.exe -k netsvcs",
                r"C:\Windows\system32\svchost.exe -k netsvcs",
                r"%SystemRoot%\System32\thing.dll",
                r"C:\Windows\System32\thing.dll",
            ]
        );
    }

    #[test]
    fn a_shortcut_gives_its_target_and_what_it_passes() {
        let entry = Entry::Shortcut(Shortcut {
            path: r"C:\Startup\x.lnk".to_owned(),
            target: r"C:\Windows\System32\rundll32.exe".to_owned(),
            arguments: r"C:\x\a.dll,Start".to_owned(),
        });
        assert_eq!(
            commands(&entry, &variables()),
            [r"C:\Windows\System32\rundll32.exe", r"C:\x\a.dll,Start"]
        );
    }

    #[test]
    fn a_task_gives_a_line_for_each_program_it_runs() {
        let xml = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions Context="Author">
    <Exec>
      <Command>"%ProgramFiles%\x\a.exe"</Command>
      <Arguments>--tray &amp; more</Arguments>
    </Exec>
    <Exec>
      <Command>C:\y\b.exe</Command>
    </Exec>
  </Actions>
</Task>"#;
        let entry = Entry::Task(Task {
            path: r"\x".to_owned(),
            xml: xml.to_owned(),
            security: None,
        });
        assert_eq!(
            commands(&entry, &variables()),
            [
                r#""%ProgramFiles%\x\a.exe" --tray & more"#,
                r#""C:\Program Files\x\a.exe" --tray & more"#,
                r"C:\y\b.exe",
            ]
        );
        let broken = Entry::Task(Task {
            path: r"\x".to_owned(),
            xml: "<Task".to_owned(),
            security: None,
        });
        assert!(commands(&broken, &variables()).is_empty());
    }
}
