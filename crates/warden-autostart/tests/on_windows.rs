//! The Windows side, on a real Windows.
//!
//! Everything else in this crate is tried against a stand-in. Here the
//! part that talks to Windows is tried against Windows: that it finds
//! entries made with Windows' own tools, removes them so that those
//! tools no longer show them, and puts them back so that the tools show
//! what they showed before.
//!
//! The first test only reads and runs everywhere. The others change the
//! machine, and run only where the environment allows it in as many
//! words; see `scene/mod.rs`. The last of them is about a driver that
//! Windows loads while it starts, which the quarantine leaves alone.

#![cfg(windows)]
#![allow(clippy::unwrap_used)]

mod scene;

use std::time::Instant;

use scene::{BOOT_DRIVER, BootDriver, ENTRIES, Report, SERVICE, Scene, print_views};
use warden_autostart::{
    Entry, KIND, Outcome, REG_EXPAND_SZ, REG_SZ, Remedy, Spellings, find, find_in, this_system,
};
use warden_quarantine::{Quarantine, Reason, RestoreOptions};

fn as_json(entry: &Entry) -> String {
    serde_json::to_string_pretty(entry).unwrap()
}

#[test]
fn the_survey_reads_this_machine() {
    let system = this_system();
    let started = Instant::now();
    let survey = system.survey();
    let took = started.elapsed();
    let count = |kind: &str| {
        survey
            .seen
            .iter()
            .filter(|seen| seen.entry.kind() == kind)
            .count()
    };
    // Numbers only: what a machine starts says what is installed on it.
    println!(
        "survey: {} Run values, {} tasks, {} services and drivers, {} shortcuts, {} problems, in {took:?}",
        count("run value"),
        count("task"),
        count("service"),
        count("shortcut"),
        survey.problems.len()
    );
    // Every Windows has services, and each of those has a program.
    assert!(count("service") > 50);
    assert!(
        survey
            .seen
            .iter()
            .filter(|seen| seen.entry.kind() == "service")
            .all(|seen| !seen.lines.is_empty())
    );

    // Windows knows this test's own file by the path it was started as.
    let own = std::env::current_exe().unwrap();
    let spellings = system.spellings(&own);
    assert!(!spellings.is_empty());
    assert!(
        spellings
            .iter()
            .all(|spelling| spelling.to_lowercase().ends_with(".exe")),
        "{spellings:?}"
    );
}

#[test]
fn what_windows_tools_made_is_found_and_read_right() {
    if !scene::may_change_the_machine() {
        return;
    }
    let scene = Scene::set_up();
    let before = scene.shown_by_windows();
    print_views("what Windows' tools show of the scene", &before);
    let mut report = Report::default();
    report.all_there(&before);

    let system = this_system();
    let threat = scene.threat();
    println!("the file: {}", threat.display());
    println!("in short: {}", scene.short_path());
    println!("as Windows writes it: {:?}", system.spellings(&threat));
    let started = Instant::now();
    let found = find(system.as_ref(), &threat);
    println!("found in {:?}", started.elapsed());
    for seen in &found.starting {
        println!("  {}\n      {:?}", seen.entry, seen.lines);
    }
    println!("problems: {:#?}", found.problems);

    let places: Vec<String> = found
        .starting
        .iter()
        .map(|seen| seen.entry.to_string())
        .collect();
    report.check(found.starting.len() == ENTRIES, || {
        format!(
            "{} entries were found and not {ENTRIES}: {places:#?}",
            found.starting.len()
        )
    });
    for name in scene::names() {
        report.check(places.iter().any(|place| place.contains(&name)), || {
            format!("{name} was not found among {places:#?}")
        });
    }

    // The path of the file, in every way Windows writes it.
    let paths: Vec<String> = system
        .spellings(&threat)
        .into_iter()
        .chain([threat.display().to_string()])
        .map(|path| path.to_lowercase())
        .collect();
    for seen in &found.starting {
        let place = seen.entry.to_string();
        match &seen.entry {
            Entry::RunValue(value) => {
                let expected = if value.name == scene::MACHINE_VALUE {
                    REG_EXPAND_SZ
                } else {
                    REG_SZ
                };
                report.check(value.value_type == expected, || {
                    format!("{place}: the value has type {}", value.value_type)
                });
            }
            Entry::Task(task) => {
                report.check(task.xml.contains("<Exec>"), || {
                    format!("{place}: the definition has no program:\n{}", task.xml)
                });
                report.check(task.security.is_some(), || {
                    format!("{place}: who may do what with it was not read")
                });
            }
            Entry::Service(service) => {
                report.check(service.name == SERVICE, || format!("{place}: its name"));
                report.check(service.display_name == "Warden test threat", || {
                    format!("{place}: it is shown as {:?}", service.display_name)
                });
                report.check(service.start_type == 2, || {
                    format!("{place}: start type {}", service.start_type)
                });
                report.check(service.service_type == 0x10, || {
                    format!("{place}: type {:#x}", service.service_type)
                });
                report.check(service.account.eq_ignore_ascii_case("LocalSystem"), || {
                    format!("{place}: it runs as {:?}", service.account)
                });
                report.check(service.security.is_some(), || {
                    format!("{place}: who may do what with it was not read")
                });
                for name in [
                    "Description",
                    "FailureActions",
                    "ServiceSidType",
                    "RequiredPrivileges",
                    "DelayedAutostart",
                ] {
                    report.check(service.key.value(name).is_some(), || {
                        format!("{place}: its key was read without the value {name}")
                    });
                }
                let deeper = service
                    .key
                    .subkey("Parameters")
                    .and_then(|parameters| parameters.subkey("Deeper"));
                report.check(
                    deeper.is_some_and(|key| key.value("Count").is_some()),
                    || format!("{place}: the keys below its key were not read"),
                );
                report.check(service.key.subkey("TriggerInfo").is_some(), || {
                    format!("{place}: what starts it by itself was not read")
                });
                report.check(service.key.subkey("Security").is_none(), || {
                    format!("{place}: the access rights were read as part of the key")
                });
            }
            Entry::Shortcut(shortcut) => {
                report.check(paths.contains(&shortcut.target.to_lowercase()), || {
                    format!("{place}: it points at {:?}", shortcut.target)
                });
                report.check(shortcut.arguments == "--from-shortcut", || {
                    format!("{place}: it passes {:?}", shortcut.arguments)
                });
            }
        }
    }

    // A file that nothing starts, next to the one that everything starts.
    let lonely = scene.dir().join("lonely.exe");
    std::fs::write(&lonely, b"nothing starts this").unwrap();
    let nothing = find(system.as_ref(), &lonely);
    report.check(nothing.starting.is_empty(), || {
        format!(
            "{} entries start a file that nothing starts",
            nothing.starting.len()
        )
    });

    // Looking changes nothing.
    report.same_as_before(&before, &scene.shown_by_windows());
    report.finish();
}

#[test]
fn each_entry_goes_and_comes_back_as_windows_showed_it() {
    if !scene::may_change_the_machine() {
        return;
    }
    let scene = Scene::set_up();
    let before = scene.shown_by_windows();
    let mut report = Report::default();
    report.all_there(&before);

    let system = this_system();
    let found = find(system.as_ref(), &scene.threat());
    // A shortcut is a file, and files are the quarantine's business.
    let entries: Vec<&Entry> = found
        .starting
        .iter()
        .map(|seen| &seen.entry)
        .filter(|entry| !matches!(entry, Entry::Shortcut(_)))
        .collect();
    report.check(entries.len() == ENTRIES - 1, || {
        format!("{} entries were found to remove", entries.len())
    });

    for entry in &entries {
        // Read twice, an entry is the same: nothing in it moves by itself.
        match system.current(entry) {
            Ok(Some(again)) if again == **entry => {}
            other => report.wrong(format!("{entry}: read again it is not the same: {other:?}")),
        }
        if let Err(failure) = system.remove(entry) {
            report.wrong(format!(
                "{entry}: it could not be removed, because {failure}"
            ));
        }
        match system.current(entry) {
            Ok(None) => {}
            other => report.wrong(format!("{entry}: after its removal Warden reads {other:?}")),
        }
        // Removing what is gone is no failure.
        if let Err(failure) = system.remove(entry) {
            report.wrong(format!(
                "{entry}: removing it again failed, because {failure}"
            ));
        }
    }
    let gone = scene.shown_by_windows();
    // The shortcut was left alone.
    let (shortcut, rest): (Vec<_>, Vec<_>) = gone
        .into_iter()
        .partition(|(what, _)| what.starts_with("the shortcut"));
    report.all_gone(&rest);
    report.all_there(&shortcut);

    for entry in &entries {
        let started = Instant::now();
        match system.create(entry) {
            Ok(notes) => {
                println!("{entry}: put back in {:?}", started.elapsed());
                report.check(notes.is_empty(), || {
                    format!("{entry}: it was put back with reservations: {notes:?}")
                });
            }
            Err(failure) => {
                report.wrong(format!(
                    "{entry}: it could not be put back, because {failure}"
                ));
                continue;
            }
        }
        match system.current(entry) {
            Ok(Some(now)) if now == **entry => {}
            Ok(Some(now)) => report.wrong(format!(
                "{entry}: Warden reads it differently after putting it back.\n--- written down ---\n{}\n--- now ---\n{}",
                as_json(entry),
                as_json(&now)
            )),
            other => report.wrong(format!("{entry}: after putting it back Warden reads {other:?}")),
        }
        // A place that is taken is not written over.
        report.check(system.create(entry).is_err(), || {
            format!("{entry}: it was created a second time over itself")
        });
    }
    let after = scene.shown_by_windows();
    print_views(
        "what Windows' tools show after everything was put back",
        &after,
    );
    report.same_as_before(&before, &after);
    report.finish();
}

#[test]
fn a_file_goes_into_the_quarantine_with_what_starts_it_and_comes_back_with_it() {
    if !scene::may_change_the_machine() {
        return;
    }
    let scene = Scene::set_up();
    let before = scene.shown_by_windows();
    let mut report = Report::default();
    report.all_there(&before);

    let system = this_system();
    let (quarantine, recovered) = Quarantine::open(scene.dir().join("quarantine")).unwrap();
    assert!(recovered.is_empty());
    let remedy = Remedy::new(system.as_ref(), &quarantine);

    let found = find(system.as_ref(), &scene.threat());
    let entry = quarantine
        .add(&scene.threat(), Reason::note("a test of Warden"))
        .unwrap();
    let id = entry.info.id;
    let removal = remedy
        .remove(&id, &entry.info.original_path, found.starting)
        .unwrap();
    for left in &removal.left {
        report.wrong(format!("{} was left, because {}", left.entry, left.why));
    }
    report.check(removal.removed.len() == ENTRIES, || {
        format!(
            "{} entries were removed and not {ENTRIES}",
            removal.removed.len()
        )
    });
    report.check(!scene.threat().exists(), || {
        "the file is still at its place".to_owned()
    });
    report.all_gone(&scene.shown_by_windows());
    // The shortcut is in the quarantine, next to the file.
    report.check(quarantine.list().unwrap().entries.len() == 2, || {
        format!(
            "the quarantine holds {} entries and not the file and its shortcut",
            quarantine.list().unwrap().entries.len()
        )
    });

    quarantine.restore(&id, &RestoreOptions::default()).unwrap();
    let back = remedy.put_back(&id).unwrap().unwrap();
    for (entry, outcome) in &back.entries {
        report.check(
            matches!(outcome, Outcome::Back(notes) if notes.is_empty()),
            || format!("{entry}: {outcome:?}"),
        );
    }
    report.check(back.entries.len() == ENTRIES, || {
        format!("{} entries were dealt with", back.entries.len())
    });
    report.check(scene.threat().exists(), || {
        "the file is not back".to_owned()
    });
    report.same_as_before(&before, &scene.shown_by_windows());
    report.check(quarantine.list().unwrap().entries.is_empty(), || {
        "something is left in the quarantine".to_owned()
    });
    report.check(quarantine.attached_ids(KIND).unwrap().is_empty(), || {
        "a record is left in the quarantine".to_owned()
    });

    // Done a second time, putting back finds nothing to do.
    report.check(remedy.put_back(&id).unwrap().is_none(), || {
        "a second put-back found a record".to_owned()
    });
    report.finish();
}

/// A driver that Windows loads while it starts, on a real Windows: where
/// the file of one has to be, that a survey knows it for such a driver by
/// the path of its file, and that it goes and comes back like a service.
#[test]
fn a_driver_that_windows_loads_while_it_starts_is_known_and_goes_and_comes_back() {
    if !scene::may_change_the_machine() {
        return;
    }
    let mut report = Report::default();

    // Where the file of such a driver can be. In a folder of one's own
    // the service manager takes a driver that is loaded on demand, and
    // turns the same one down with the start "boot". The documents say
    // so, and this is where it shows.
    const ELSEWHERE: &str = "WardenTestDriverElsewhere";
    let dir = tempfile::Builder::new()
        .prefix("Warden driver elsewhere ")
        .tempdir()
        .unwrap();
    let elsewhere = dir.path().join("wardentest.sys");
    std::fs::copy(std::env::current_exe().unwrap(), &elsewhere).unwrap();
    let _ = scene::tool("sc", &["delete", ELSEWHERE]);
    for (start, expected) in [("boot", false), ("demand", true)] {
        let (taken, said) = scene::tool(
            "sc",
            &[
                "create",
                ELSEWHERE,
                "type=",
                "kernel",
                "start=",
                start,
                "error=",
                "ignore",
                "binPath=",
                &elsewhere.display().to_string(),
            ],
        );
        println!(
            "==== a driver with its file outside the Windows folder, start \"{start}\" ====\n{}",
            said.trim()
        );
        if taken {
            let (_, shown) = scene::tool("sc", &["qc", ELSEWHERE]);
            println!("{}", shown.trim());
        }
        let _ = scene::tool("sc", &["delete", ELSEWHERE]);
        report.check(taken == expected, || {
            format!(
                "the service manager {} a driver outside the Windows folder with the start \"{start}\":\n{said}",
                if taken { "took" } else { "turned down" }
            )
        });
    }
    println!();

    let driver = BootDriver::register();
    let before = driver.shown_by_windows();
    print_views("what Windows' tools show of the driver", &before);
    report.all_there(&before);

    let system = this_system();
    let file = driver.file();
    println!("the file: {}", file.display());
    println!("as Windows writes it: {:?}", system.spellings(file));

    // A survey knows the file for one that Windows loads while it
    // starts, by the path a person would write. The copy elsewhere, with
    // the same name, is no such file.
    let survey = system.survey();
    let spelled = |file: &std::path::Path| {
        let mut paths = vec![file.display().to_string()];
        paths.extend(system.spellings(file));
        Spellings::new(paths)
    };
    let drivers = survey.boot_drivers();
    let drivers_of = |file: &std::path::Path| -> Vec<String> {
        let file = spelled(file);
        drivers
            .iter()
            .filter(|driver| driver.is_file(&file))
            .map(|driver| driver.name.clone())
            .collect()
    };
    println!(
        "{} drivers are loaded while this Windows starts; the file is that of {:?}",
        drivers.len(),
        drivers_of(file)
    );
    report.check(drivers_of(file) == [BOOT_DRIVER], || {
        format!(
            "the file is taken for that of {:?}, and not of {BOOT_DRIVER} alone",
            drivers_of(file)
        )
    });
    report.check(drivers_of(&elsewhere).is_empty(), || {
        format!(
            "a file elsewhere is taken for that of {:?}",
            drivers_of(&elsewhere)
        )
    });

    // What starts the file is the driver, and nothing else.
    let found = find_in(system.as_ref(), &survey, file);
    for seen in &found.starting {
        println!("  {}\n      {:?}", seen.entry, seen.lines);
    }
    let places: Vec<String> = found
        .starting
        .iter()
        .map(|seen| seen.entry.to_string())
        .collect();
    report.check(places == [format!("the driver {BOOT_DRIVER}")], || {
        format!("what starts the file was found to be {places:?}")
    });
    let Some(seen) = found.starting.first() else {
        report.finish();
        return;
    };
    let entry = &seen.entry;
    println!("{}", as_json(entry));
    match entry {
        Entry::Service(service) => {
            report.check(service.is_loaded_at_boot(), || {
                format!(
                    "it was read with type {:#x} and start {}",
                    service.service_type, service.start_type
                )
            });
            report.check(service.error_control == 0, || {
                format!("it was read with error control {}", service.error_control)
            });
        }
        other => report.wrong(format!("it was read as {other}")),
    }

    // It goes and comes back as a service does. The file is not part of
    // that: files are the quarantine's business.
    if let Err(failure) = system.remove(entry) {
        report.wrong(format!("it could not be removed, because {failure}"));
    }
    match system.current(entry) {
        Ok(None) => {}
        other => report.wrong(format!("after its removal Warden reads {other:?}")),
    }
    report.all_gone(&driver.shown_by_windows());
    report.check(file.is_file(), || "the file went with the entry".to_owned());
    match system.create(entry) {
        Ok(notes) => report.check(notes.is_empty(), || {
            format!("it was put back with reservations: {notes:?}")
        }),
        Err(failure) => report.wrong(format!("it could not be put back, because {failure}")),
    }
    match system.current(entry) {
        Ok(Some(now)) if now == *entry => {}
        Ok(Some(now)) => report.wrong(format!(
            "Warden reads it differently after putting it back.\n--- written down ---\n{}\n--- now ---\n{}",
            as_json(entry),
            as_json(&now)
        )),
        other => report.wrong(format!("after putting it back Warden reads {other:?}")),
    }
    let after = driver.shown_by_windows();
    print_views(
        "what Windows' tools show after the driver was put back",
        &after,
    );
    report.same_as_before(&before, &after);
    report.finish();
}
