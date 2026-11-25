//! Reading the definition of a scheduled task.
//!
//! The Task Scheduler gives out a task as an XML document. Warden keeps
//! that document as it is and hands it back to the Task Scheduler on a
//! restore; it never writes one. What it reads from it is which programs
//! the task runs and whose rights it runs with, the latter because a task
//! that runs with a stored password cannot be put back by anyone who does
//! not know the password.

/// What Warden reads from a task's definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    /// The programs the task runs, in order.
    pub actions: Vec<Action>,
    /// How the task gets the rights it runs with.
    pub logon: Logon,
}

/// A program a task runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    /// The program.
    pub command: String,
    /// What is passed to it.
    pub arguments: String,
}

/// How a task gets the rights it runs with, as the Task Scheduler
/// numbers the ways.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Logon {
    /// Not said.
    None,
    /// With a password that the Task Scheduler keeps.
    Password,
    /// As a user who need not be logged on, without a password.
    S4u,
    /// As a user who is logged on.
    InteractiveToken,
    /// As whoever of a group is logged on.
    Group,
    /// As the system or one of its service accounts.
    ServiceAccount,
    /// As a user who is logged on, or else with a stored password.
    InteractiveTokenOrPassword,
}

impl Logon {
    /// The number the Task Scheduler has for it.
    #[must_use]
    pub fn number(self) -> i32 {
        match self {
            Self::None => 0,
            Self::Password => 1,
            Self::S4u => 2,
            Self::InteractiveToken => 3,
            Self::Group => 4,
            Self::ServiceAccount => 5,
            Self::InteractiveTokenOrPassword => 6,
        }
    }

    /// Whether registering such a task takes a password. The Task
    /// Scheduler never gives a stored password back, so a task like that
    /// cannot be put back, and Warden does not remove it.
    #[must_use]
    pub fn needs_password(self) -> bool {
        matches!(self, Self::Password | Self::InteractiveTokenOrPassword)
    }
}

/// The largest definition that is read. Real ones are a few kilobytes.
const MAX_XML_BYTES: usize = 4 * 1024 * 1024;
/// The most elements, attributes and pieces of text a definition may have.
const MAX_XML_NODES: u32 = 100_000;

/// Reads a task's definition.
///
/// # Errors
///
/// Fails with a sentence if the text is not a task definition: too large,
/// not XML, or with another outermost element than `Task`.
pub fn read(xml: &str) -> Result<Definition, String> {
    if xml.len() > MAX_XML_BYTES {
        return Err(format!(
            "the definition has {} bytes, more than a task's ever has",
            xml.len()
        ));
    }
    let text = xml.strip_prefix('\u{feff}').unwrap_or(xml);
    let options = roxmltree::ParsingOptions {
        allow_dtd: false,
        nodes_limit: MAX_XML_NODES,
        ..roxmltree::ParsingOptions::default()
    };
    let document = roxmltree::Document::parse_with_options(text, options)
        .map_err(|error| format!("the definition cannot be read ({error})"))?;
    let root = document.root_element();
    if root.tag_name().name() != "Task" {
        return Err("the outermost element of the definition is not Task".to_owned());
    }

    let mut actions = Vec::new();
    for list in children(root, "Actions") {
        for exec in children(list, "Exec") {
            let text_of = |name| {
                children(exec, name)
                    .next()
                    .and_then(|node| node.text())
                    .unwrap_or_default()
                    .trim()
                    .to_owned()
            };
            let command = text_of("Command");
            if !command.is_empty() {
                actions.push(Action {
                    command,
                    arguments: text_of("Arguments"),
                });
            }
        }
    }

    let principal = children(root, "Principals")
        .flat_map(|list| children(list, "Principal"))
        .next();
    let logon = principal.map_or(Logon::None, |principal| {
        let text_of = |name| {
            children(principal, name)
                .next()
                .and_then(|node| node.text())
                .map(str::trim)
        };
        match text_of("LogonType") {
            Some("Password") => Logon::Password,
            Some("S4U") => Logon::S4u,
            Some("InteractiveToken") => Logon::InteractiveToken,
            Some("Group") => Logon::Group,
            Some("ServiceAccount") => Logon::ServiceAccount,
            Some("InteractiveTokenOrPassword") => Logon::InteractiveTokenOrPassword,
            Some("None") => Logon::None,
            // Not said in so many words: the Task Scheduler leaves the
            // way out where the account says it.
            _ => {
                if text_of("GroupId").is_some() {
                    Logon::Group
                } else if text_of("UserId").is_some_and(is_service_account) {
                    Logon::ServiceAccount
                } else {
                    Logon::InteractiveToken
                }
            }
        }
    });

    Ok(Definition { actions, logon })
}

fn children<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
    name: &'static str,
) -> impl Iterator<Item = roxmltree::Node<'a, 'input>> {
    node.children()
        .filter(move |child| child.is_element() && child.tag_name().name() == name)
}

/// Whether an account, by name or by identifier, is the system or one of
/// the two service accounts that need no password.
fn is_service_account(user: &str) -> bool {
    const ACCOUNTS: [&str; 10] = [
        "S-1-5-18",
        "S-1-5-19",
        "S-1-5-20",
        "SYSTEM",
        "LocalSystem",
        "LOCAL SERVICE",
        "NETWORK SERVICE",
        r"NT AUTHORITY\SYSTEM",
        r"NT AUTHORITY\LOCAL SERVICE",
        r"NT AUTHORITY\NETWORK SERVICE",
    ];
    ACCOUNTS
        .iter()
        .any(|account| account.eq_ignore_ascii_case(user))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(principal: &str, actions: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\x</URI></RegistrationInfo>
  <Principals>{principal}</Principals>
  <Actions Context="Author">{actions}</Actions>
</Task>"#
        )
    }

    #[test]
    fn the_programs_of_a_task_are_read_in_order() {
        let xml = task(
            r#"<Principal id="Author"><UserId>S-1-5-21-1-2-3-1001</UserId><LogonType>InteractiveToken</LogonType></Principal>"#,
            r"<Exec><Command>C:\x\a.exe</Command><Arguments>--one</Arguments><WorkingDirectory>C:\x</WorkingDirectory></Exec>
              <ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId></ComHandler>
              <Exec><Command> C:\y\b.exe </Command></Exec>
              <Exec><Arguments>nothing to run</Arguments></Exec>",
        );
        let definition = read(&xml).unwrap();
        assert_eq!(
            definition.actions,
            [
                Action {
                    command: r"C:\x\a.exe".to_owned(),
                    arguments: "--one".to_owned()
                },
                Action {
                    command: r"C:\y\b.exe".to_owned(),
                    arguments: String::new()
                },
            ]
        );
        assert_eq!(definition.logon, Logon::InteractiveToken);
    }

    #[test]
    fn whose_rights_a_task_runs_with_is_read_or_worked_out() {
        let cases = [
            (
                "<Principal><UserId>S-1-5-18</UserId><RunLevel>LeastPrivilege</RunLevel></Principal>",
                Logon::ServiceAccount,
            ),
            (
                r"<Principal><UserId>NT AUTHORITY\LOCAL SERVICE</UserId></Principal>",
                Logon::ServiceAccount,
            ),
            (
                "<Principal><GroupId>S-1-5-32-545</GroupId></Principal>",
                Logon::Group,
            ),
            (
                "<Principal><UserId>S-1-5-21-1-2-3-1001</UserId></Principal>",
                Logon::InteractiveToken,
            ),
            (
                "<Principal><UserId>u</UserId><LogonType>Password</LogonType></Principal>",
                Logon::Password,
            ),
            (
                "<Principal><UserId>u</UserId><LogonType>S4U</LogonType></Principal>",
                Logon::S4u,
            ),
            (
                "<Principal><UserId>u</UserId><LogonType>InteractiveTokenOrPassword</LogonType></Principal>",
                Logon::InteractiveTokenOrPassword,
            ),
            ("", Logon::None),
        ];
        for (principal, expected) in cases {
            assert_eq!(
                read(&task(principal, "")).unwrap().logon,
                expected,
                "{principal}"
            );
        }
        assert!(Logon::Password.needs_password());
        assert!(Logon::InteractiveTokenOrPassword.needs_password());
        assert!(!Logon::S4u.needs_password());
        assert!(!Logon::ServiceAccount.needs_password());
        assert_eq!(Logon::ServiceAccount.number(), 5);
    }

    #[test]
    fn what_is_no_task_definition_is_turned_down() {
        assert!(read("").is_err());
        assert!(read("<Task").is_err());
        assert!(read("<Other/>").unwrap_err().contains("not Task"));
        // A document type could make a small text very large.
        let with_doctype = r#"<!DOCTYPE Task [<!ENTITY a "aaaa">]><Task>&a;</Task>"#;
        assert!(read(with_doctype).is_err());
        let huge = format!("<Task>{}</Task>", " ".repeat(MAX_XML_BYTES));
        assert!(
            read(&huge)
                .unwrap_err()
                .contains("more than a task's ever has")
        );
    }

    #[test]
    fn a_mark_at_the_start_of_the_text_is_no_obstacle() {
        let xml = format!("\u{feff}{}", task("", ""));
        assert!(read(&xml).is_ok());
    }
}
