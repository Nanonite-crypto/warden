//! Taking away what starts a file, and putting it back.
//!
//! The machine here is a stand-in that holds its entries in memory; the
//! quarantine and the files are real. What is tried is the logic: that
//! exactly the entries that start the file are found, that all of them
//! go and come back as they were, and that an operation that is cut off
//! at any point leaves every entry in its place or in the record.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use warden_autostart::stand_in::Machine;
use warden_autostart::{
    AutostartError, Entry, Hive, KIND, Outcome, REG_EXPAND_SZ, REG_SZ, RegKey, Remedy, RunValue,
    Service, Shortcut, State, Step, Task, Variables, View, find, reg_string_bytes,
};
use warden_quarantine::{Quarantine, Reason, RestoreOptions};

/// How the stand-in machine writes the path of the file under test.
const THREAT: &str = r"C:\scene\threat.exe";
const SHORTCUT_BYTES: &[u8] = b"what a shortcut file holds";

struct Scene {
    dir: tempfile::TempDir,
    machine: Machine,
    quarantine: Quarantine,
}

fn run_value(hive: Hive, name: &str, value_type: u32, text: &str) -> Entry {
    Entry::RunValue(RunValue {
        hive,
        view: View::Native,
        key: r"Software\Microsoft\Windows\CurrentVersion\Run".to_owned(),
        name: name.to_owned(),
        value_type,
        data: reg_string_bytes(text),
    })
}

fn user() -> Hive {
    Hive::User {
        sid: "S-1-5-21-1-2-3-1001".to_owned(),
    }
}

fn task(path: &str, command: &str, logon: &str) -> Entry {
    Entry::Task(Task {
        path: path.to_owned(),
        xml: format!(
            r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="Author"><UserId>S-1-5-21-1-2-3-1001</UserId><LogonType>{logon}</LogonType></Principal></Principals>
  <Actions Context="Author"><Exec><Command>{command}</Command><Arguments>--from-task</Arguments></Exec></Actions>
</Task>"#
        ),
        security: Some("O:BAG:SYD:(A;;FA;;;BA)".to_owned()),
    })
}

fn service(name: &str, image: &str) -> Entry {
    Entry::Service(Service {
        name: name.to_owned(),
        display_name: format!("The {name} service"),
        service_type: 0x10,
        start_type: 2,
        error_control: 1,
        image_path: image.to_owned(),
        load_order_group: String::new(),
        dependencies: vec!["RpcSs".to_owned()],
        account: "LocalSystem".to_owned(),
        security: Some("D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)".to_owned()),
        key: RegKey::default(),
    })
}

impl Scene {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (quarantine, recovered) = Quarantine::open(dir.path().join("quarantine")).unwrap();
        assert!(recovered.is_empty());
        let scene = Self {
            dir,
            machine: Machine::new(),
            quarantine,
        };
        fs::write(scene.threat(), b"a harmless stand-in for a threat").unwrap();
        fs::create_dir(scene.dir.path().join("startup")).unwrap();
        fs::write(scene.shortcut_path(), SHORTCUT_BYTES).unwrap();
        scene.machine.spell(&scene.threat(), THREAT);
        scene.machine.set_variables(Variables::new([(
            "SCENE".to_owned(),
            r"C:\scene".to_owned(),
        )]));
        for entry in scene.starting().into_iter().chain(scene.unrelated()) {
            scene.machine.add(entry);
        }
        scene
    }

    fn threat(&self) -> PathBuf {
        self.dir.path().join("threat.exe")
    }

    fn shortcut_path(&self) -> PathBuf {
        self.dir.path().join("startup").join("threat.lnk")
    }

    fn shortcut(&self) -> Entry {
        Entry::Shortcut(Shortcut {
            path: self.shortcut_path().display().to_string(),
            target: THREAT.to_owned(),
            arguments: String::new(),
        })
    }

    /// The five entries that start the file, one of each kind and a
    /// second Run value that names the file through a variable.
    fn starting(&self) -> Vec<Entry> {
        vec![
            run_value(user(), "Threat", REG_SZ, &format!(r#""{THREAT}" --tray"#)),
            run_value(
                Hive::Machine,
                "ThreatForAll",
                REG_EXPAND_SZ,
                r"%SCENE%\threat.exe",
            ),
            task(r"\Scene\Threat", THREAT, "InteractiveToken"),
            service("threatsvc", &format!(r#""{THREAT}" --service"#)),
            self.shortcut(),
        ]
    }

    /// Entries that have nothing to do with the file, however much their
    /// command lines look like it.
    fn unrelated(&self) -> Vec<Entry> {
        vec![
            run_value(user(), "Other", REG_SZ, r"C:\other\thing.exe"),
            run_value(user(), "Backup", REG_SZ, &format!("{THREAT}.bak")),
            run_value(user(), "ByName", REG_SZ, "threat.exe"),
            task(r"\Scene\Other", r"C:\scene\threat2.exe", "InteractiveToken"),
            service("othersvc", r"C:\scene\other\threat.exe"),
        ]
    }

    fn remedy(&self) -> Remedy<'_> {
        Remedy::new(&self.machine, &self.quarantine)
    }

    /// Finds what starts the file and quarantines the file. Returns the
    /// entry's identifier and what was found.
    fn quarantine_the_file(&self) -> (String, Vec<warden_autostart::Seen>) {
        let found = find(&self.machine, &self.threat());
        assert!(found.problems.is_empty());
        let entry = self
            .quarantine
            .add(&self.threat(), Reason::note("under test"))
            .unwrap();
        (entry.info.id, found.starting)
    }

    fn remove_everything(&self) -> String {
        let (id, starting) = self.quarantine_the_file();
        let removal = self
            .remedy()
            .remove(&id, &self.threat().display().to_string(), starting)
            .unwrap();
        assert_eq!(removal.removed.len(), 5);
        assert!(removal.left.is_empty());
        id
    }

    fn restore_the_file(&self, id: &str) {
        self.quarantine
            .restore(id, &RestoreOptions::default())
            .unwrap();
    }

    fn on_the_machine(&self, entry: &Entry) -> bool {
        self.machine.entries().contains(entry)
    }

    fn assert_everything_is_as_it_was(&self) {
        let mut now = self.machine.entries();
        let mut then: Vec<Entry> = self
            .starting()
            .into_iter()
            .chain(self.unrelated())
            .collect();
        let key = |entry: &Entry| serde_json::to_string(entry).unwrap();
        now.sort_by_key(key);
        then.sort_by_key(key);
        assert_eq!(now, then);
        assert_eq!(fs::read(self.shortcut_path()).unwrap(), SHORTCUT_BYTES);
        assert!(self.threat().exists());
        assert!(self.quarantine.list().unwrap().entries.is_empty());
        assert!(self.quarantine.attached_ids(KIND).unwrap().is_empty());
    }

    /// The rule that has to hold whenever anything is cut off: each entry
    /// that started the file is in its place or in the record, whole.
    fn assert_nothing_is_lost(&self, id: &str) {
        let record = self.remedy().record(id).unwrap();
        for entry in self.starting() {
            let in_place = self.on_the_machine(&entry);
            let in_record = record
                .as_ref()
                .is_some_and(|record| record.items.iter().any(|item| item.what == entry));
            assert!(
                in_place || in_record,
                "{entry} is neither in its place nor in the record"
            );
            if let Entry::Shortcut(shortcut) = &entry {
                let file_in_place = Path::new(&shortcut.path).exists();
                let file_in_quarantine = self
                    .quarantine
                    .list()
                    .unwrap()
                    .entries
                    .iter()
                    .any(|entry| entry.info.original_path == shortcut.path);
                assert!(
                    file_in_place != file_in_quarantine,
                    "the shortcut file is in {} places",
                    usize::from(file_in_place) + usize::from(file_in_quarantine)
                );
            }
        }
        for entry in self.unrelated() {
            assert!(self.on_the_machine(&entry), "{entry} was touched");
        }
    }
}

#[test]
fn what_starts_a_file_is_found_and_nothing_else() {
    let scene = Scene::new();
    scene
        .machine
        .report_problem("the tasks of other users could not be read");
    let found = find(&scene.machine, &scene.threat());
    let entries: Vec<Entry> = found.starting.into_iter().map(|seen| seen.entry).collect();
    assert_eq!(entries, scene.starting());
    assert_eq!(
        found.problems,
        ["the tasks of other users could not be read"]
    );

    // A file nothing starts.
    let other = scene.dir.path().join("lonely.exe");
    fs::write(&other, b"x").unwrap();
    scene.machine.spell(&other, r"C:\scene\lonely.exe");
    assert!(find(&scene.machine, &other).starting.is_empty());

    // A file the machine has no full path for is not looked for by a
    // part of its name.
    let nameless = scene.dir.path().join("threat2.exe");
    fs::write(&nameless, b"x").unwrap();
    assert!(find(&scene.machine, &nameless).starting.is_empty());
}

#[test]
fn everything_that_starts_a_file_goes_with_it_and_comes_back_with_it() {
    let scene = Scene::new();
    let id = scene.remove_everything();

    // Gone from the machine, all five, and nothing else.
    let mut left = scene.machine.entries();
    let mut unrelated = scene.unrelated();
    let key = |entry: &Entry| serde_json::to_string(entry).unwrap();
    left.sort_by_key(key);
    unrelated.sort_by_key(key);
    assert_eq!(left, unrelated);
    assert!(!scene.shortcut_path().exists());

    // And in the record, whole.
    let record = scene.remedy().record(&id).unwrap().unwrap();
    assert_eq!(record.entry, id);
    assert_eq!(record.file, scene.threat().display().to_string());
    let recorded: Vec<Entry> = record.items.iter().map(|item| item.what.clone()).collect();
    assert_eq!(recorded, scene.starting());
    assert!(record.items.iter().all(|item| item.state == State::Removed));
    let shortcut_item = record.items.last().unwrap();
    let child = shortcut_item.quarantined_as.clone().unwrap();
    let child_entry = scene.quarantine.find(&child).unwrap();
    assert!(
        child_entry
            .info
            .reason
            .note
            .as_deref()
            .unwrap()
            .contains(&id)
    );
    assert_eq!(scene.remedy().records().unwrap(), [(record, true)]);

    scene.restore_the_file(&id);
    let back = scene.remedy().put_back(&id).unwrap().unwrap();
    assert_eq!(back.entries.len(), 5);
    for (entry, outcome) in &back.entries {
        assert!(
            matches!(outcome, Outcome::Back(notes) if notes.is_empty()),
            "{entry}: {outcome:?}"
        );
    }
    assert!(!back.is_owing());
    scene.assert_everything_is_as_it_was();

    // There is nothing left to put back.
    assert!(scene.remedy().put_back(&id).unwrap().is_none());
}

#[test]
fn a_file_that_nothing_starts_leaves_no_record() {
    let scene = Scene::new();
    let entry = scene
        .quarantine
        .add(&scene.threat(), Reason::note("under test"))
        .unwrap();
    let removal = scene
        .remedy()
        .remove(&entry.info.id, "anywhere", Vec::new())
        .unwrap();
    assert!(removal.removed.is_empty() && removal.left.is_empty());
    assert!(scene.quarantine.attached_ids(KIND).unwrap().is_empty());
    assert!(scene.remedy().put_back(&entry.info.id).unwrap().is_none());
}

#[test]
fn cut_off_while_removing_every_entry_is_in_its_place_or_in_the_record() {
    let steps = [
        Step::Recorded,
        Step::Removed(0),
        Step::Removed(1),
        Step::Removed(2),
        Step::Removed(3),
        Step::Removed(4),
    ];
    for step in steps {
        let scene = Scene::new();
        let (id, starting) = scene.quarantine_the_file();
        let mut remedy = scene.remedy();
        remedy.interrupt_after(step);
        let cut = remedy.remove(&id, &scene.threat().display().to_string(), starting);
        assert!(
            matches!(cut, Err(AutostartError::Interrupted(at)) if at == step),
            "{step:?}: {cut:?}"
        );
        scene.assert_nothing_is_lost(&id);

        // Putting back right away, without finishing the removal, brings
        // everything back that had gone.
        scene.restore_the_file(&id);
        let back = scene.remedy().put_back(&id).unwrap().unwrap();
        assert!(!back.is_owing(), "{step:?}: {back:?}");
        scene.assert_everything_is_as_it_was();
    }
}

#[test]
fn a_removal_that_was_cut_off_can_be_finished() {
    for step in [Step::Recorded, Step::Removed(1), Step::Removed(4)] {
        let scene = Scene::new();
        let (id, starting) = scene.quarantine_the_file();
        let mut remedy = scene.remedy();
        remedy.interrupt_after(step);
        remedy
            .remove(&id, &scene.threat().display().to_string(), starting)
            .unwrap_err();

        let removal = scene.remedy().finish_removing(&id).unwrap();
        assert_eq!(removal.removed.len(), 5, "{step:?}");
        assert!(removal.left.is_empty());
        for entry in scene.starting() {
            assert!(!scene.on_the_machine(&entry), "{step:?}: {entry}");
        }
        // The shortcut is in the quarantine once, not twice.
        assert_eq!(
            scene.quarantine.list().unwrap().entries.len(),
            2,
            "{step:?}"
        );
        scene.assert_nothing_is_lost(&id);

        scene.restore_the_file(&id);
        assert!(!scene.remedy().put_back(&id).unwrap().unwrap().is_owing());
        scene.assert_everything_is_as_it_was();
    }
}

#[test]
fn cut_off_while_putting_back_it_can_be_done_again() {
    for index in 0..5 {
        let scene = Scene::new();
        let id = scene.remove_everything();
        scene.restore_the_file(&id);

        let mut remedy = scene.remedy();
        remedy.interrupt_after(Step::PutBack(index));
        let cut = remedy.put_back(&id);
        assert!(matches!(
            cut,
            Err(AutostartError::Interrupted(Step::PutBack(at))) if at == index
        ));
        scene.assert_nothing_is_lost(&id);

        let back = scene.remedy().put_back(&id).unwrap().unwrap();
        assert!(!back.is_owing());
        // What was back before the cut is found in its place this time.
        let in_place = back
            .entries
            .iter()
            .filter(|(_, outcome)| *outcome == Outcome::InPlace)
            .count();
        assert_eq!(in_place, index + 1, "cut after entry {index}");
        scene.assert_everything_is_as_it_was();
    }
}

#[test]
fn without_rights_what_belongs_to_the_user_goes_and_the_rest_is_named() {
    let scene = Scene::new();
    let starting = scene.starting();
    let (for_all, the_service) = (&starting[1], &starting[3]);
    scene.machine.protect(for_all);
    scene.machine.protect(the_service);

    let (id, found) = scene.quarantine_the_file();
    let removal = scene
        .remedy()
        .remove(&id, &scene.threat().display().to_string(), found)
        .unwrap();
    assert_eq!(removal.removed.len(), 3);
    let left: Vec<&Entry> = removal.left.iter().map(|left| &left.entry).collect();
    assert_eq!(left, [for_all, the_service]);
    assert!(removal.left.iter().all(|left| left.needs_rights));
    assert!(removal.left[0].why.contains("administrator"));
    assert!(scene.on_the_machine(for_all) && scene.on_the_machine(the_service));
    scene.assert_nothing_is_lost(&id);

    // Somebody with the rights goes on where this stopped.
    scene.machine.grant_rights();
    let finished = scene.remedy().finish_removing(&id).unwrap();
    assert_eq!(finished.removed.len(), 5);
    assert!(finished.left.is_empty());
    assert!(!scene.on_the_machine(for_all) && !scene.on_the_machine(the_service));

    scene.restore_the_file(&id);
    assert!(!scene.remedy().put_back(&id).unwrap().unwrap().is_owing());
    scene.assert_everything_is_as_it_was();
}

#[test]
fn what_was_left_for_want_of_rights_is_not_owed_on_a_restore() {
    let scene = Scene::new();
    let starting = scene.starting();
    scene.machine.protect(&starting[1]);
    let (id, found) = scene.quarantine_the_file();
    scene
        .remedy()
        .remove(&id, &scene.threat().display().to_string(), found)
        .unwrap();

    scene.restore_the_file(&id);
    let back = scene.remedy().put_back(&id).unwrap().unwrap();
    assert!(!back.is_owing());
    assert!(
        matches!(&back.entries[1].1, Outcome::NeverRemoved(why) if why.contains("administrator"))
    );
    scene.assert_everything_is_as_it_was();
}

#[test]
fn when_only_what_needs_rights_starts_the_file_the_record_waits_for_them() {
    let scene = Scene::new();
    let for_all = scene.starting().swap_remove(1);
    scene.machine.protect(&for_all);
    let found = find(&scene.machine, &scene.threat());
    let only: Vec<_> = found
        .starting
        .into_iter()
        .filter(|seen| seen.entry == for_all)
        .collect();
    let entry = scene
        .quarantine
        .add(&scene.threat(), Reason::note("under test"))
        .unwrap();
    let removal = scene.remedy().remove(&entry.info.id, "x", only).unwrap();
    assert!(removal.removed.is_empty());
    assert_eq!(removal.left.len(), 1);
    assert_eq!(
        scene.quarantine.attached_ids(KIND).unwrap(),
        std::slice::from_ref(&entry.info.id)
    );

    scene.machine.grant_rights();
    let finished = scene.remedy().finish_removing(&entry.info.id).unwrap();
    assert_eq!(finished.removed, std::slice::from_ref(&for_all));
    assert!(!scene.on_the_machine(&for_all));
}

#[test]
fn an_entry_that_could_not_be_put_back_is_not_removed() {
    let scene = Scene::new();
    let with_password = task(r"\Scene\WithPassword", THREAT, "Password");
    scene.machine.add(with_password.clone());

    let (id, found) = scene.quarantine_the_file();
    assert_eq!(found.len(), 6);
    let removal = scene
        .remedy()
        .remove(&id, &scene.threat().display().to_string(), found)
        .unwrap();
    assert_eq!(removal.removed.len(), 5);
    assert_eq!(removal.left.len(), 1);
    assert_eq!(removal.left[0].entry, with_password);
    assert!(removal.left[0].why.contains("stored password"));
    assert!(!removal.left[0].needs_rights);
    assert!(scene.on_the_machine(&with_password));

    // More rights do not change that.
    scene.machine.grant_rights();
    let again = scene.remedy().finish_removing(&id).unwrap();
    assert_eq!(again.left.len(), 1);
    assert!(scene.on_the_machine(&with_password));
}

#[test]
fn putting_back_looks_before_it_writes() {
    let scene = Scene::new();
    let starting = scene.starting();
    let id = scene.remove_everything();
    scene.restore_the_file(&id);

    // Somebody made the first entry again, the same as it was.
    scene.machine.add(starting[0].clone());
    // Something else sits where the second one was.
    let squatter = run_value(Hive::Machine, "ThreatForAll", REG_SZ, r"C:\elsewhere\b.exe");
    scene.machine.add(squatter.clone());
    // And the machine will not take the service back just yet.
    scene.machine.refuse_to_create(&starting[3]);

    let back = scene.remedy().put_back(&id).unwrap().unwrap();
    assert_eq!(back.entries[0].1, Outcome::InPlace);
    assert_eq!(back.entries[1].1, Outcome::Occupied);
    assert!(matches!(&back.entries[2].1, Outcome::Back(_)));
    assert!(matches!(&back.entries[3].1, Outcome::Failed(why) if why.contains("not finished")));
    assert!(matches!(&back.entries[4].1, Outcome::Back(_)));
    assert!(back.is_owing());

    // Nothing was replaced, and the record holds what is owed, whole.
    assert!(scene.on_the_machine(&squatter));
    assert!(!scene.on_the_machine(&starting[1]));
    let records = scene.remedy().records().unwrap();
    assert_eq!(records.len(), 1);
    let (record, file_in_quarantine) = &records[0];
    assert!(!file_in_quarantine);
    let owed: Vec<&Entry> = record.items.iter().map(|item| &item.what).collect();
    assert_eq!(owed, [&starting[1], &starting[3]]);
    assert!(
        record.items[0]
            .note
            .as_deref()
            .unwrap()
            .contains("something else")
    );
    assert!(
        record.items[1]
            .note
            .as_deref()
            .unwrap()
            .contains("not finished")
    );

    // Later the machine takes the service, and the squatter is gone.
    scene.machine.allow_to_create();
    warden_autostart::System::remove(&scene.machine, &squatter).unwrap();
    let again = scene.remedy().put_back(&id).unwrap().unwrap();
    assert_eq!(again.entries.len(), 2);
    assert!(!again.is_owing());
    scene.assert_everything_is_as_it_was();
}

#[test]
fn a_shortcut_whose_place_is_taken_stays_in_the_quarantine() {
    let scene = Scene::new();
    let id = scene.remove_everything();
    scene.restore_the_file(&id);
    fs::write(scene.shortcut_path(), b"another shortcut altogether").unwrap();

    let back = scene.remedy().put_back(&id).unwrap().unwrap();
    assert_eq!(back.entries[4].1, Outcome::Occupied);
    assert_eq!(
        fs::read(scene.shortcut_path()).unwrap(),
        b"another shortcut altogether"
    );
    assert_eq!(scene.quarantine.list().unwrap().entries.len(), 1);

    fs::remove_file(scene.shortcut_path()).unwrap();
    let again = scene.remedy().put_back(&id).unwrap().unwrap();
    assert!(matches!(&again.entries[0].1, Outcome::Back(_)));
    scene.assert_everything_is_as_it_was();
}

#[test]
fn a_shortcut_that_went_without_the_record_saying_so_is_found_again() {
    let scene = Scene::new();
    let (id, starting) = scene.quarantine_the_file();
    let mut remedy = scene.remedy();
    // The shortcut is the fifth entry. It is in the quarantine, and the
    // record does not know under which identifier.
    remedy.interrupt_after(Step::Removed(4));
    remedy
        .remove(&id, &scene.threat().display().to_string(), starting)
        .unwrap_err();
    let record = scene.remedy().record(&id).unwrap().unwrap();
    assert_eq!(record.items[4].state, State::Recorded);
    assert!(record.items[4].quarantined_as.is_none());
    assert!(!scene.shortcut_path().exists());

    scene.restore_the_file(&id);
    let back = scene.remedy().put_back(&id).unwrap().unwrap();
    assert!(matches!(&back.entries[4].1, Outcome::Back(_)));
    scene.assert_everything_is_as_it_was();
}

#[test]
fn a_shortcut_that_somebody_else_removed_is_reported_as_lost() {
    let scene = Scene::new();
    let found = find(&scene.machine, &scene.threat());
    fs::remove_file(scene.shortcut_path()).unwrap();
    let entry = scene
        .quarantine
        .add(&scene.threat(), Reason::note("under test"))
        .unwrap();
    let removal = scene
        .remedy()
        .remove(&entry.info.id, "x", found.starting)
        .unwrap();
    // It counts as removed: it is not there any more.
    assert_eq!(removal.removed.len(), 5);

    scene.restore_the_file(&entry.info.id);
    let back = scene.remedy().put_back(&entry.info.id).unwrap().unwrap();
    assert_eq!(back.entries[4].1, Outcome::Lost);
    assert!(!back.is_owing());
    assert!(scene.quarantine.attached_ids(KIND).unwrap().is_empty());
}

#[test]
fn forgetting_lets_go_of_the_record_and_of_the_shortcuts() {
    let scene = Scene::new();
    let id = scene.remove_everything();
    assert_eq!(scene.quarantine.list().unwrap().entries.len(), 2);

    scene.remedy().forget(&id).unwrap();
    assert!(scene.quarantine.attached_ids(KIND).unwrap().is_empty());
    let entries = scene.quarantine.list().unwrap().entries;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].info.id, id);
    // Forgetting twice, or what was never there, is no error.
    scene.remedy().forget(&id).unwrap();
    scene.remedy().forget("0000000000000000").unwrap();

    // What was removed stays removed.
    scene.restore_the_file(&id);
    assert!(scene.remedy().put_back(&id).unwrap().is_none());
    for entry in scene.starting() {
        assert!(!scene.on_the_machine(&entry));
    }
}

#[test]
fn deleting_the_file_for_good_takes_the_record_with_it() {
    let scene = Scene::new();
    let id = scene.remove_everything();
    scene.remedy().forget(&id).unwrap();
    scene.quarantine.delete(&id).unwrap();
    assert!(scene.quarantine.list().unwrap().entries.is_empty());
    assert!(scene.remedy().records().unwrap().is_empty());
}

#[test]
fn a_record_that_cannot_be_read_is_said_to_be_so() {
    let scene = Scene::new();
    let id = scene.remove_everything();
    scene.quarantine.attach(&id, KIND, b"not a record").unwrap();
    let error = scene.remedy().put_back(&id).unwrap_err();
    assert!(
        matches!(&error, AutostartError::BadRecord { id: bad, .. } if *bad == id),
        "{error}"
    );
    assert!(error.to_string().contains(&id));
    // It is left out of the list and does not stop the others.
    assert!(scene.remedy().records().unwrap().is_empty());
}
