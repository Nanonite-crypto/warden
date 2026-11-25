//! What an autostart entry is, in the four forms Warden looks at.
//!
//! An [`Entry`] holds everything that is needed to put the entry back as
//! it was, in the form Windows itself has it: a registry value with its
//! type and its bytes, a task as the definition the Task Scheduler gives
//! out, a service as the service manager describes it together with its
//! registry key. Nothing in it is an interpretation. What an entry
//! *starts* is worked out from it separately, see [`commands`](crate::commands).

use std::fmt;

use serde::{Deserialize, Serialize};

/// One thing that makes Windows start a program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Entry {
    /// A value under a `Run` or `RunOnce` key of the registry.
    RunValue(RunValue),
    /// A scheduled task.
    Task(Task),
    /// A service or a driver.
    Service(Service),
    /// A shortcut in a Startup folder.
    Shortcut(Shortcut),
}

impl Entry {
    /// Whether `other` sits at the same place as this entry: the same
    /// value name under the same key, the same task path, the same service
    /// name, the same file. What the two hold may differ.
    #[must_use]
    pub fn same_place(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::RunValue(mine), Self::RunValue(theirs)) => {
                mine.hive == theirs.hive
                    && mine.view == theirs.view
                    && same_name(&mine.key, &theirs.key)
                    && same_name(&mine.name, &theirs.name)
            }
            (Self::Task(mine), Self::Task(theirs)) => same_name(&mine.path, &theirs.path),
            (Self::Service(mine), Self::Service(theirs)) => same_name(&mine.name, &theirs.name),
            (Self::Shortcut(mine), Self::Shortcut(theirs)) => same_name(&mine.path, &theirs.path),
            _ => false,
        }
    }

    /// The kind of entry in a word, for a table.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::RunValue(_) => "run value",
            Self::Task(_) => "task",
            Self::Service(_) => "service",
            Self::Shortcut(_) => "shortcut",
        }
    }
}

/// Names of registry values, tasks, services and files are compared
/// without regard to case, as Windows compares them.
fn same_name(one: &str, other: &str) -> bool {
    one.chars()
        .flat_map(char::to_uppercase)
        .eq(other.chars().flat_map(char::to_uppercase))
}

impl fmt::Display for Entry {
    /// Where the entry is, in words a person can find it by.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunValue(value) => write!(
                formatter,
                "the value \"{}\" under {}\\{}{}",
                value.name,
                value.hive,
                value.key,
                match value.view {
                    View::Native => "",
                    View::Wow32 => " (as 32-bit programs see it)",
                }
            ),
            Self::Task(task) => write!(formatter, "the scheduled task {}", task.path),
            Self::Service(service) => write!(
                formatter,
                "the {} {}",
                if service.is_driver() {
                    "driver"
                } else {
                    "service"
                },
                service.name
            ),
            Self::Shortcut(shortcut) => write!(formatter, "the shortcut {}", shortcut.path),
        }
    }
}

/// Which part of the registry a value is in.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hive {
    /// The machine's settings, `HKEY_LOCAL_MACHINE`.
    Machine,
    /// The settings of one user, `HKEY_USERS\<sid>`.
    User {
        /// The user's security identifier, as the key is named.
        sid: String,
    },
}

impl fmt::Display for Hive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Machine => formatter.write_str("HKEY_LOCAL_MACHINE"),
            Self::User { sid } => write!(formatter, "HKEY_USERS\\{sid}"),
        }
    }
}

/// Which of the two views of the machine's software settings a value is
/// in. A 64-bit Windows keeps a second set for 32-bit programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum View {
    /// The one 64-bit programs see.
    #[default]
    Native,
    /// The one 32-bit programs see.
    Wow32,
}

/// A value under a `Run` or `RunOnce` key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunValue {
    /// Which part of the registry.
    pub hive: Hive,
    /// Which view of it.
    #[serde(default)]
    pub view: View,
    /// The key, below the hive.
    pub key: String,
    /// The name of the value.
    pub name: String,
    /// The type of the value, as the registry numbers them: 1 is a
    /// string, 2 a string with variables to fill in.
    pub value_type: u32,
    /// The bytes of the value, exactly as stored.
    #[serde(with = "crate::hex::serde_bytes")]
    pub data: Vec<u8>,
}

/// A scheduled task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    /// The task's path in the Task Scheduler, such as `\Folder\Name`.
    pub path: String,
    /// The task's definition, as the Task Scheduler gives it out.
    pub xml: String,
    /// Who may do what with the task, in the notation Windows writes
    /// security descriptors in. Missing if it could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
}

/// A service or a driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    /// The name the service manager knows it by.
    pub name: String,
    /// The name shown to people.
    pub display_name: String,
    /// What kind of service it is, as the service manager numbers them.
    pub service_type: u32,
    /// When it is started.
    pub start_type: u32,
    /// What Windows does if it fails to start.
    pub error_control: u32,
    /// The program, as the service manager gives it out.
    pub image_path: String,
    /// The group it is started with.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub load_order_group: String,
    /// The services it needs, with a `+` before the name of a group.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
    /// The account it runs as. Empty for a driver.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub account: String,
    /// Who may do what with the service, in the notation Windows writes
    /// security descriptors in. Missing if it could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    /// The service's key in the registry, whole. It holds what the
    /// fields above are taken from and everything else that belongs to
    /// the service: its description, what to do when it fails, the
    /// library a shared host loads for it.
    pub key: RegKey,
}

impl Service {
    /// Whether this is a driver: something the kernel loads, not a
    /// program of its own.
    #[must_use]
    pub fn is_driver(&self) -> bool {
        const KERNEL_DRIVER: u32 = 0x1;
        const FILE_SYSTEM_DRIVER: u32 = 0x2;
        self.service_type & (KERNEL_DRIVER | FILE_SYSTEM_DRIVER) != 0
    }
}

/// A registry key with everything below it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegKey {
    /// The values of the key, in the order of their names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<RegValue>,
    /// The keys below it, in the order of their names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subkeys: Vec<SubKey>,
}

impl RegKey {
    /// The value of a name, if the key has it.
    #[must_use]
    pub fn value(&self, name: &str) -> Option<&RegValue> {
        self.values
            .iter()
            .find(|value| same_name(&value.name, name))
    }

    /// The key of a name below this one, if there is one.
    #[must_use]
    pub fn subkey(&self, name: &str) -> Option<&RegKey> {
        self.subkeys
            .iter()
            .find(|subkey| same_name(&subkey.name, name))
            .map(|subkey| &subkey.key)
    }

    /// Puts values and keys in the order of their names, all the way
    /// down, so that two keys with the same content compare equal
    /// whatever order Windows listed them in.
    pub fn sort(&mut self) {
        self.values.sort_by_key(|value| fold(&value.name));
        self.subkeys.sort_by_key(|subkey| fold(&subkey.name));
        for subkey in &mut self.subkeys {
            subkey.key.sort();
        }
    }
}

fn fold(name: &str) -> String {
    name.chars().flat_map(char::to_uppercase).collect()
}

/// A key below another one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubKey {
    /// The name of the key.
    pub name: String,
    /// What it holds.
    pub key: RegKey,
}

/// One value of a registry key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegValue {
    /// The name of the value. Empty for the unnamed value of a key.
    pub name: String,
    /// The type of the value, as the registry numbers them.
    pub value_type: u32,
    /// The bytes of the value, exactly as stored.
    #[serde(with = "crate::hex::serde_bytes")]
    pub data: Vec<u8>,
}

/// A shortcut in a Startup folder. The shortcut is a file, and it is the
/// file that is taken away and put back; what is kept here is where it
/// was and what it pointed at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Shortcut {
    /// The shortcut file.
    pub path: String,
    /// The program it starts.
    pub target: String,
    /// What it passes to the program.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub arguments: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_value(name: &str, data: &[u8]) -> Entry {
        Entry::RunValue(RunValue {
            hive: Hive::Machine,
            view: View::Native,
            key: r"Software\Microsoft\Windows\CurrentVersion\Run".to_owned(),
            name: name.to_owned(),
            value_type: 1,
            data: data.to_vec(),
        })
    }

    #[test]
    fn a_place_is_the_same_whatever_the_case_and_whatever_is_in_it() {
        let one = run_value("Updater", b"a");
        assert!(one.same_place(&run_value("UPDATER", b"b")));
        assert!(!one.same_place(&run_value("Updater2", b"a")));

        let other_view = match one.clone() {
            Entry::RunValue(value) => Entry::RunValue(RunValue {
                view: View::Wow32,
                ..value
            }),
            _ => unreachable!(),
        };
        assert!(!one.same_place(&other_view));

        let task = Entry::Task(Task {
            path: r"\Vendor\Update".to_owned(),
            xml: String::new(),
            security: None,
        });
        assert!(!one.same_place(&task));
        assert!(task.same_place(&Entry::Task(Task {
            path: r"\vendor\update".to_owned(),
            xml: "<Task/>".to_owned(),
            security: Some("D:".to_owned()),
        })));
    }

    #[test]
    fn an_entry_says_where_it_is() {
        assert_eq!(
            run_value("Updater", b"").to_string(),
            r#"the value "Updater" under HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"#
        );
        let user = Entry::RunValue(RunValue {
            hive: Hive::User {
                sid: "S-1-5-21-1-2-3-1001".to_owned(),
            },
            view: View::Native,
            key: r"Software\Microsoft\Windows\CurrentVersion\RunOnce".to_owned(),
            name: "Once".to_owned(),
            value_type: 1,
            data: Vec::new(),
        });
        assert_eq!(
            user.to_string(),
            r#"the value "Once" under HKEY_USERS\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\RunOnce"#
        );
        let driver = Entry::Service(Service {
            name: "filter".to_owned(),
            display_name: "Filter".to_owned(),
            service_type: 0x1,
            start_type: 0,
            error_control: 1,
            image_path: r"System32\drivers\filter.sys".to_owned(),
            load_order_group: String::new(),
            dependencies: Vec::new(),
            account: String::new(),
            security: None,
            key: RegKey::default(),
        });
        assert_eq!(driver.to_string(), "the driver filter");
    }

    #[test]
    fn an_entry_survives_being_written_down() {
        let entries = [
            run_value("Updater", &[0x41, 0x00, 0x00, 0x00]),
            Entry::Task(Task {
                path: r"\Vendor\Update".to_owned(),
                xml: "<Task><Actions/></Task>".to_owned(),
                security: Some("O:BAG:SYD:(A;;FA;;;BA)".to_owned()),
            }),
            Entry::Service(Service {
                name: "svc".to_owned(),
                display_name: "A service".to_owned(),
                service_type: 0x10,
                start_type: 2,
                error_control: 1,
                image_path: r#""C:\Program Files\x\svc.exe" --run"#.to_owned(),
                load_order_group: String::new(),
                dependencies: vec!["RpcSs".to_owned(), "+Network".to_owned()],
                account: "LocalSystem".to_owned(),
                security: None,
                key: RegKey {
                    values: vec![RegValue {
                        name: "Description".to_owned(),
                        value_type: 1,
                        data: vec![0x41, 0x00, 0x00, 0x00],
                    }],
                    subkeys: vec![SubKey {
                        name: "Parameters".to_owned(),
                        key: RegKey::default(),
                    }],
                },
            }),
            Entry::Shortcut(Shortcut {
                path: r"C:\Users\u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk"
                    .to_owned(),
                target: r"C:\x\x.exe".to_owned(),
                arguments: String::new(),
            }),
        ];
        for entry in entries {
            let text = serde_json::to_string(&entry).unwrap();
            assert_eq!(
                serde_json::from_str::<Entry>(&text).unwrap(),
                entry,
                "{text}"
            );
        }
    }

    #[test]
    fn a_field_nobody_knows_is_refused() {
        let text = r#"{"kind":"task","path":"\\A","xml":"","made_up":1}"#;
        assert!(serde_json::from_str::<Entry>(text).is_err());
    }

    #[test]
    fn a_key_is_looked_into_and_sorted_by_name() {
        let mut key = RegKey {
            values: vec![
                RegValue {
                    name: "b".to_owned(),
                    value_type: 4,
                    data: vec![1, 0, 0, 0],
                },
                RegValue {
                    name: "A".to_owned(),
                    value_type: 4,
                    data: vec![2, 0, 0, 0],
                },
            ],
            subkeys: vec![
                SubKey {
                    name: "zeta".to_owned(),
                    key: RegKey::default(),
                },
                SubKey {
                    name: "Alpha".to_owned(),
                    key: RegKey::default(),
                },
            ],
        };
        assert_eq!(key.value("B").map(|value| value.data[0]), Some(1));
        assert!(key.value("c").is_none());
        assert!(key.subkey("ZETA").is_some());
        key.sort();
        assert_eq!(key.values[0].name, "A");
        assert_eq!(key.subkeys[0].name, "Alpha");
    }
}
