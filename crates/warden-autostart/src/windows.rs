//! What Warden asks of Windows about autostart entries.
//!
//! Four places, each through the part of Windows that owns it: Run values
//! through the registry, tasks through the Task Scheduler, services
//! through the service manager and the registry key that is a service's
//! definition, shortcuts through the shell. Nothing here decides
//! anything: which entry starts a file, what is removed and in which
//! order is for the rest of the crate, which runs against a stand-in on
//! every system.
//!
//! This is the only module of the crate with `unsafe` code. Each block is
//! one call of a Windows function, or reads memory that such a call
//! handed out, with what makes it sound written next to it.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::marker::PhantomData;
use std::path::Path;
use std::ptr;

use windows::Win32::Foundation::{
    E_ACCESSDENIED, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER,
    ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_PATH_NOT_FOUND, ERROR_SERVICE_DOES_NOT_EXIST,
    ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SUCCESS, HLOCAL, LocalFree, RPC_E_CHANGED_MODE,
    WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::{GetFullPathNameW, GetLongPathNameW, GetShortPathNameW};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoTaskMemFree, CoUninitialize, IPersistFile, STGM_READ,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, KEY_WRITE,
    REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW,
    RegDeleteValueW, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, CreateServiceW, DeleteService, ENUM_SERVICE_TYPE,
    OpenSCManagerW, OpenServiceW, QueryServiceObjectSecurity, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_MANAGER_CREATE_SERVICE, SERVICE_CHANGE_CONFIG, SERVICE_CONFIG,
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
    SERVICE_CONFIG_PRESHUTDOWN_INFO, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
    SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_CONFIG_TRIGGER_INFO, SERVICE_DELAYED_AUTO_START_INFO,
    SERVICE_ERROR, SERVICE_FAILURE_ACTIONS_FLAG, SERVICE_PRESHUTDOWN_INFO,
    SERVICE_REQUIRED_PRIVILEGES_INFOW, SERVICE_SID_INFO, SERVICE_START_TYPE, SERVICE_TRIGGER,
    SERVICE_TRIGGER_ACTION, SERVICE_TRIGGER_INFO, SERVICE_TRIGGER_SPECIFIC_DATA_ITEM,
    SERVICE_TRIGGER_SPECIFIC_DATA_ITEM_DATA_TYPE, SERVICE_TRIGGER_TYPE, SetServiceObjectSecurity,
};
use windows::Win32::System::TaskScheduler::{
    IRegisteredTask, ITaskFolder, ITaskService, TASK_CREATE, TASK_DONT_ADD_PRINCIPAL_ACE,
    TASK_ENUM_HIDDEN, TASK_LOGON_TYPE, TaskScheduler,
};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::UI::Shell::{
    FOLDERID_CommonStartup, FOLDERID_Startup, IShellLinkW, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    SLGP_RAWPATH, ShellLink,
};
use windows::core::{BSTR, GUID, HSTRING, Interface, PCWSTR, PWSTR};

use crate::command::{REG_EXPAND_SZ, REG_SZ, Variables, commands, expand, reg_string};
use crate::entry::{
    Entry, Hive, RegKey, RegValue, RunValue, Service, Shortcut, SubKey, Task, View,
};
use crate::system::{Failure, Seen, Survey, System};
use crate::task;

/// The keys whose values Windows runs at logon, below a hive.
const RUN_KEYS: [&str; 2] = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
];
/// Where the service manager keeps its services.
const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";
/// Keys below a service's key that are not part of what is recorded: the
/// access rights, which the service manager is asked for and told
/// directly, and what Windows writes there while a driver is loaded.
const NOT_RECORDED: [&str; 2] = ["Security", "Enum"];

/// The most bytes of registry values that are read for one service.
const MAX_KEY_BYTES: usize = 4 * 1024 * 1024;
/// The most values and keys that are read for one service.
const MAX_KEY_ITEMS: usize = 20_000;
/// How deep the keys below a service's key are followed.
const MAX_KEY_DEPTH: usize = 32;
/// How deep task folders are followed.
const MAX_TASK_DEPTH: usize = 32;
/// The longest path Windows has, in UTF-16 units.
const LONG_PATH: usize = 32_768;

const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;
const READ_CONTROL: u32 = 0x0002_0000;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
/// What a service that Windows has not finished removing says about
/// itself, to whoever wants to put one of the same name in its place.
const STILL_BEING_REMOVED: &str = "Windows has not finished removing the old one; it can be tried \
                                   again once every window that shows services is closed, or \
                                   after a restart";
/// "The file is not there", as the Task Scheduler says it.
const TASK_NOT_FOUND: i32 = 0x8007_0002_u32 as i32;
/// "The path is not there".
const TASK_PATH_NOT_FOUND: i32 = 0x8007_0003_u32 as i32;

/// Windows, as far as autostart entries go.
#[derive(Debug)]
pub struct Windows {
    com: Com,
}

impl Windows {
    /// Gets ready to talk to the Task Scheduler and the shell from this
    /// thread.
    #[must_use]
    pub fn new() -> Self {
        Self { com: Com::start() }
    }
}

impl Default for Windows {
    fn default() -> Self {
        Self::new()
    }
}

/// The component model that the Task Scheduler and the shell speak, set
/// up for this thread and taken down again when the value goes. It
/// belongs to the thread, so it must not move to another.
#[derive(Debug)]
struct Com {
    to_take_down: bool,
    _this_thread: PhantomData<*const ()>,
}

impl Com {
    fn start() -> Self {
        // As an apartment of this thread's own: that is the mode every
        // object of the shell works in, and the Task Scheduler works in
        // either. Everything here is called from this thread and answers
        // before the call returns, so nothing has to be waited for.
        //
        // SAFETY: no pointer is passed. The call is paired with
        // CoUninitialize in `drop` whenever it succeeded, as it must be.
        let result = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        Self {
            // If the thread was set up differently by somebody else, the
            // call fails, the component model still works, and taking it
            // down is not ours to do.
            to_take_down: result.is_ok() && result != RPC_E_CHANGED_MODE,
            _this_thread: PhantomData,
        }
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if self.to_take_down {
            // SAFETY: pairs with the successful CoInitializeEx of this
            // thread in `start`.
            unsafe { CoUninitialize() };
        }
    }
}

impl System for Windows {
    fn survey(&self) -> Survey {
        let mut survey = Survey::default();
        let machine = process_variables().of_the_machine();
        let users = user_hives(&machine);
        run_values(&machine, &users, &mut survey);
        self.tasks(&machine, &users, &mut survey);
        services(&machine, &mut survey);
        self.shortcuts(&machine, &mut survey);
        survey
    }

    fn spellings(&self, file: &Path) -> Vec<String> {
        let given = HSTRING::from(file.as_os_str());
        let mut spellings = Vec::new();
        let Some(full) = path_from(|buffer| {
            // SAFETY: `given` is a zero-terminated string that lives
            // through the call, and the buffer is a slice of our own.
            unsafe { GetFullPathNameW(&given, Some(buffer), None) }
        }) else {
            return spellings;
        };
        let full_wide = HSTRING::from(full.as_str());
        for other in [
            path_from(|buffer| {
                // SAFETY: as above.
                unsafe { GetLongPathNameW(&full_wide, Some(buffer)) }
            }),
            path_from(|buffer| {
                // SAFETY: as above.
                unsafe { GetShortPathNameW(&full_wide, Some(buffer)) }
            }),
        ]
        .into_iter()
        .flatten()
        {
            spellings.push(other);
        }
        spellings.insert(0, full);
        spellings
    }

    fn current(&self, entry: &Entry) -> Result<Option<Entry>, Failure> {
        match entry {
            Entry::RunValue(value) => {
                let Some(key) = open_run_key(value, KEY_READ)
                    .map_err(|error| registry_failure("the key cannot be opened", error))?
                else {
                    return Ok(None);
                };
                let found = key
                    .value(&value.name)
                    .map_err(|error| registry_failure("the value cannot be read", error))?;
                Ok(found.map(|(value_type, data)| {
                    Entry::RunValue(RunValue {
                        value_type,
                        data,
                        ..value.clone()
                    })
                }))
            }
            Entry::Task(wanted) => {
                let root = self.task_root()?;
                // SAFETY: a call through an interface pointer that
                // `task_root` handed out and that is alive.
                match unsafe { root.GetTask(&BSTR::from(wanted.path.as_str())) } {
                    Ok(found) => read_task(&found).map(|task| Some(Entry::Task(task))),
                    Err(error)
                        if error.code().0 == TASK_NOT_FOUND
                            || error.code().0 == TASK_PATH_NOT_FOUND =>
                    {
                        Ok(None)
                    }
                    Err(error) => Err(com_failure("the task cannot be looked up", &error)),
                }
            }
            Entry::Service(service) => read_service(&service.name, true),
            Entry::Shortcut(shortcut) => {
                if Path::new(&shortcut.path).is_file() {
                    self.read_shortcut(&shortcut.path)
                        .map(|read| Some(Entry::Shortcut(read)))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn remove(&self, entry: &Entry) -> Result<(), Failure> {
        match entry {
            Entry::RunValue(value) => {
                let Some(key) = open_run_key(value, KEY_WRITE)
                    .map_err(|error| registry_failure("the key cannot be opened", error))?
                else {
                    return Ok(());
                };
                key.delete_value(&value.name)
                    .map_err(|error| registry_failure("the value cannot be removed", error))
            }
            Entry::Task(task) => {
                let (folder, name) = split_task_path(&task.path);
                let root = self.task_root()?;
                // SAFETY: calls through interface pointers that are alive.
                let folder = match unsafe { root.GetFolder(&BSTR::from(folder)) } {
                    Ok(folder) => folder,
                    Err(error)
                        if error.code().0 == TASK_NOT_FOUND
                            || error.code().0 == TASK_PATH_NOT_FOUND =>
                    {
                        return Ok(());
                    }
                    Err(error) => {
                        return Err(com_failure("the task's folder cannot be opened", &error));
                    }
                };
                // SAFETY: as above.
                match unsafe { folder.DeleteTask(&BSTR::from(name), 0) } {
                    Ok(()) => Ok(()),
                    Err(error) if error.code().0 == TASK_NOT_FOUND => Ok(()),
                    Err(error) => Err(com_failure("the task cannot be removed", &error)),
                }
            }
            Entry::Service(service) => delete_service(&service.name),
            Entry::Shortcut(_) => Err(Failure::new(
                "a shortcut is a file, and files go to the quarantine",
            )),
        }
    }

    fn create(&self, entry: &Entry) -> Result<Vec<String>, Failure> {
        match entry {
            Entry::RunValue(value) => {
                let key = Key::create(root_of(&value.hive), &run_key_path(value), view_of(value))
                    .map_err(|error| registry_failure("the key cannot be opened", error))?;
                if key
                    .value(&value.name)
                    .map_err(|error| registry_failure("the value cannot be read", error))?
                    .is_some()
                {
                    return Err(Failure::new("there is one at its place already"));
                }
                key.set(&value.name, value.value_type, &value.data)
                    .map_err(|error| registry_failure("the value cannot be written", error))?;
                Ok(Vec::new())
            }
            Entry::Task(task) => self.register_task(task),
            Entry::Service(service) => create_service(service),
            Entry::Shortcut(_) => Err(Failure::new(
                "a shortcut is a file, and files come from the quarantine",
            )),
        }
    }
}

// ---------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------

fn registry_failure(what: &str, error: WIN32_ERROR) -> Failure {
    let reason = format!("{what} (Windows error {})", error.0);
    if error == ERROR_ACCESS_DENIED {
        Failure::denied(format!(
            "{reason}; it takes an administrator's rights, or the rights of the user it belongs to"
        ))
    } else {
        Failure::new(reason)
    }
}

fn com_failure(what: &str, error: &windows::core::Error) -> Failure {
    // The number is what can be looked up; the message comes in the
    // language of the system.
    let reason = format!(
        "{what} (Windows error {:#010x}: {})",
        error.code().0,
        error.message().trim()
    );
    if error.code() == E_ACCESSDENIED || error.code() == ERROR_ACCESS_DENIED.to_hresult() {
        Failure::denied(format!("{reason}; it takes an administrator's rights"))
    } else {
        Failure::new(reason)
    }
}

// ---------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------

/// An open registry key, closed when it goes.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle came from RegOpenKeyExW or RegCreateKeyExW
        // and is closed exactly once, here.
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

impl Key {
    /// Opens a key that is there. Nothing if it is not.
    fn open(root: HKEY, path: &str, access: REG_SAM_FLAGS) -> Result<Option<Self>, WIN32_ERROR> {
        let mut handle = HKEY::default();
        // SAFETY: the path is a zero-terminated string that lives through
        // the call, and `handle` is a place of our own to put the result.
        let result =
            unsafe { RegOpenKeyExW(root, &HSTRING::from(path), None, access, &raw mut handle) };
        if result == ERROR_SUCCESS {
            Ok(Some(Self(handle)))
        } else if result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND {
            Ok(None)
        } else {
            Err(result)
        }
    }

    /// Opens a key for reading and writing, and makes it if it is not
    /// there.
    fn create(root: HKEY, path: &str, view: REG_SAM_FLAGS) -> Result<Self, WIN32_ERROR> {
        let mut handle = HKEY::default();
        // SAFETY: as for `open`; the class and the security attributes
        // are left out, which the function allows.
        let result = unsafe {
            RegCreateKeyExW(
                root,
                &HSTRING::from(path),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE | view,
                None,
                &raw mut handle,
                None,
            )
        };
        if result == ERROR_SUCCESS {
            Ok(Self(handle))
        } else {
            Err(result)
        }
    }

    /// The type and the bytes of a value. Nothing if the key has no
    /// value of that name.
    fn value(&self, name: &str) -> Result<Option<(u32, Vec<u8>)>, WIN32_ERROR> {
        let name = HSTRING::from(name);
        let mut data = vec![0u8; 512];
        loop {
            let mut value_type = REG_VALUE_TYPE::default();
            let mut size = u32::try_from(data.len()).unwrap_or(u32::MAX);
            // SAFETY: the name is a zero-terminated string, the buffer is
            // ours and `size` says how long it is, as the function asks.
            let result = unsafe {
                RegQueryValueExW(
                    self.0,
                    &name,
                    None,
                    Some(&raw mut value_type),
                    Some(data.as_mut_ptr()),
                    Some(&raw mut size),
                )
            };
            if result == ERROR_SUCCESS {
                data.truncate(size as usize);
                return Ok(Some((value_type.0, data)));
            } else if result == ERROR_MORE_DATA {
                // `size` now says what is needed. It may have grown since.
                data.resize((size as usize).max(data.len() * 2), 0);
            } else if result == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            } else {
                return Err(result);
            }
        }
    }

    fn set(&self, name: &str, value_type: u32, data: &[u8]) -> Result<(), WIN32_ERROR> {
        // SAFETY: the name is a zero-terminated string and the data a
        // slice, both alive through the call.
        let result = unsafe {
            RegSetValueExW(
                self.0,
                &HSTRING::from(name),
                None,
                REG_VALUE_TYPE(value_type),
                Some(data),
            )
        };
        if result == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(result)
        }
    }

    /// Removes a value. That there is none is fine.
    fn delete_value(&self, name: &str) -> Result<(), WIN32_ERROR> {
        // SAFETY: the name is a zero-terminated string that lives through
        // the call.
        let result = unsafe { RegDeleteValueW(self.0, &HSTRING::from(name)) };
        if result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND {
            Ok(())
        } else {
            Err(result)
        }
    }

    /// Every value of the key.
    fn values(&self) -> Result<Vec<RegValue>, WIN32_ERROR> {
        let mut values = Vec::new();
        // The longest name a value can have, and its end.
        let mut name = vec![0u16; 16_384];
        let mut data = vec![0u8; 4096];
        let mut index = 0;
        loop {
            let mut name_length = u32::try_from(name.len()).unwrap_or(u32::MAX);
            let mut size = u32::try_from(data.len()).unwrap_or(u32::MAX);
            let mut value_type = 0u32;
            // SAFETY: both buffers are ours, and the two lengths say how
            // long they are, in the units the function asks for.
            let result = unsafe {
                RegEnumValueW(
                    self.0,
                    index,
                    Some(PWSTR(name.as_mut_ptr())),
                    &raw mut name_length,
                    None,
                    Some(&raw mut value_type),
                    Some(data.as_mut_ptr()),
                    Some(&raw mut size),
                )
            };
            if result == ERROR_SUCCESS {
                values.push(RegValue {
                    name: String::from_utf16_lossy(&name[..name_length as usize]),
                    value_type,
                    data: data[..size as usize].to_vec(),
                });
                index += 1;
            } else if result == ERROR_MORE_DATA {
                data.resize((size as usize).max(data.len() * 2), 0);
            } else if result == ERROR_NO_MORE_ITEMS {
                return Ok(values);
            } else {
                return Err(result);
            }
        }
    }

    /// The names of the keys directly below this one.
    fn subkey_names(&self) -> Result<Vec<String>, WIN32_ERROR> {
        let mut names = Vec::new();
        // A key's name has at most 255 characters.
        let mut name = [0u16; 256];
        let mut index = 0;
        loop {
            let mut length = u32::try_from(name.len()).unwrap_or(u32::MAX);
            // SAFETY: the buffer is ours and `length` says how long it is.
            let result = unsafe {
                RegEnumKeyExW(
                    self.0,
                    index,
                    Some(PWSTR(name.as_mut_ptr())),
                    &raw mut length,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if result == ERROR_SUCCESS {
                names.push(String::from_utf16_lossy(&name[..length as usize]));
                index += 1;
            } else if result == ERROR_NO_MORE_ITEMS {
                return Ok(names);
            } else {
                return Err(result);
            }
        }
    }

    fn subkey(&self, name: &str, access: REG_SAM_FLAGS) -> Result<Option<Self>, WIN32_ERROR> {
        Self::open(self.0, name, access)
    }

    fn string(&self, name: &str) -> Option<String> {
        let (value_type, data) = self.value(name).ok()??;
        reg_string(value_type, &data)
    }

    fn number(&self, name: &str) -> Option<u32> {
        let (value_type, data) = self.value(name).ok()??;
        (value_type == REG_DWORD)
            .then(|| {
                data.get(..4)
                    .map(|four| u32::from_le_bytes([four[0], four[1], four[2], four[3]]))
            })
            .flatten()
    }

    /// The strings of a value that holds several.
    fn strings(&self, name: &str) -> Vec<String> {
        let Some((value_type, data)) = self.value(name).ok().flatten() else {
            return Vec::new();
        };
        if value_type != REG_MULTI_SZ {
            return Vec::new();
        }
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        units
            .split(|unit| *unit == 0)
            .filter(|part| !part.is_empty())
            .map(String::from_utf16_lossy)
            .collect()
    }
}

/// What is left of the room for one service's registry key.
struct Room {
    bytes: usize,
    items: usize,
}

/// Reads a key with everything below it, within limits.
fn read_tree(key: &Key, depth: usize, top: bool, room: &mut Room) -> Result<RegKey, Failure> {
    let too_much =
        || Failure::new("its key in the registry holds more than Warden writes down for a service");
    let cannot = |error| registry_failure("its key in the registry cannot be read", error);
    if depth > MAX_KEY_DEPTH {
        return Err(too_much());
    }
    let values = key.values().map_err(cannot)?;
    for value in &values {
        room.bytes = room
            .bytes
            .checked_sub(value.data.len() + value.name.len())
            .ok_or_else(too_much)?;
        room.items = room.items.checked_sub(1).ok_or_else(too_much)?;
    }
    let mut subkeys = Vec::new();
    for name in key.subkey_names().map_err(cannot)? {
        if top
            && NOT_RECORDED
                .iter()
                .any(|skipped| skipped.eq_ignore_ascii_case(&name))
        {
            continue;
        }
        room.items = room.items.checked_sub(1).ok_or_else(too_much)?;
        let Some(below) = key.subkey(&name, KEY_READ).map_err(cannot)? else {
            continue;
        };
        subkeys.push(SubKey {
            key: read_tree(&below, depth + 1, false, room)?,
            name,
        });
    }
    let mut tree = RegKey { values, subkeys };
    tree.sort();
    Ok(tree)
}

/// Writes back what a recorded key holds and the key that is there now
/// does not: values that are missing or differ, and keys that are
/// missing. Nothing is removed. Says whether everything could be
/// written.
fn write_back(key: &Key, recorded: &RegKey, top: bool) -> bool {
    let mut complete = true;
    for value in &recorded.values {
        let same = key
            .value(&value.name)
            .ok()
            .flatten()
            .is_some_and(|(value_type, data)| value_type == value.value_type && data == value.data);
        if !same && key.set(&value.name, value.value_type, &value.data).is_err() {
            complete = false;
        }
    }
    for subkey in &recorded.subkeys {
        if top
            && NOT_RECORDED
                .iter()
                .any(|skipped| skipped.eq_ignore_ascii_case(&subkey.name))
        {
            continue;
        }
        match Key::create(key.0, &subkey.name, REG_SAM_FLAGS(0)) {
            Ok(below) => complete &= write_back(&below, &subkey.key, false),
            Err(_) => complete = false,
        }
    }
    complete
}

// ---------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------

fn process_variables() -> Variables {
    Variables::new(std::env::vars_os().map(|(name, value)| {
        (
            name.to_string_lossy().into_owned(),
            value.to_string_lossy().into_owned(),
        )
    }))
}

/// A user whose settings are loaded: the name of the hive, which is the
/// user's security identifier, and the variables that user's programs
/// see.
struct UserHive {
    sid: String,
    variables: Variables,
}

/// Where Windows keeps the folder of each user's profile.
const PROFILES: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
/// Where a user's settings say in which folders programs keep their data.
const SHELL_FOLDERS: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";

fn user_hives(machine: &Variables) -> Vec<UserHive> {
    let Ok(Some(users)) = Key::open(HKEY_USERS, "", KEY_READ) else {
        return Vec::new();
    };
    let own_profile = std::env::var("USERPROFILE").ok();
    let mut hives = Vec::new();
    for sid in users.subkey_names().unwrap_or_default() {
        // The settings of a user's file types are a hive of their own,
        // and `.DEFAULT` is the system account's hive under a second name.
        if sid.ends_with("_Classes") || sid.eq_ignore_ascii_case(".DEFAULT") {
            continue;
        }
        let profile = profile_folder(&sid, machine);
        // The process is told its own user's folder. The hive whose
        // profile is that folder is the hive of the user it runs as.
        let is_own = match (&profile, &own_profile) {
            (Some(theirs), Some(own)) => same_folder(theirs, own),
            _ => false,
        };
        hives.push(UserHive {
            variables: if is_own {
                // The process's own variables are the truth for its user.
                process_variables()
            } else if is_a_persons(&sid) {
                user_variables(&users, &sid, profile, machine)
            } else {
                // The accounts of the system and of services get their
                // variables in ways of their own. What is the same for
                // everybody is the part of them that is certain.
                machine.clone()
            },
            sid,
        });
    }
    hives
}

/// Whether a security identifier is that of a person's account, local,
/// of a domain or of a cloud directory, and not of the system or of a
/// service.
fn is_a_persons(sid: &str) -> bool {
    sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-")
}

/// The folder of a user's profile, from the list that Windows keeps.
fn profile_folder(sid: &str, machine: &Variables) -> Option<String> {
    let key = Key::open(
        HKEY_LOCAL_MACHINE,
        &format!(r"{PROFILES}\{sid}"),
        KEY_READ | KEY_WOW64_64KEY,
    )
    .ok()??;
    let (value_type, data) = key.value("ProfileImagePath").ok()??;
    let folder = reg_string(value_type, &data)?;
    Some(expand(&folder, machine))
}

fn same_folder(one: &str, other: &str) -> bool {
    one.trim_end_matches('\\')
        .eq_ignore_ascii_case(other.trim_end_matches('\\'))
}

/// The variables that a user's programs see, as far as the registry
/// tells them: what Windows set at logon if the user is logged on, the
/// folder of the profile, the two folders for programs' data, and what
/// the user has set. Each on top of what is the same for everybody.
///
/// This is for people's accounts that the process does not run as. It is
/// not a guess: these are the places Windows fills the variables from.
fn user_variables(
    users: &Key,
    sid: &str,
    profile: Option<String>,
    machine: &Variables,
) -> Variables {
    let mut pairs: Vec<(String, String)> = Vec::new();
    let as_it_is = |name: &str| Some(name.to_owned());
    add_strings(
        users,
        &format!(r"{sid}\Volatile Environment"),
        machine,
        &mut pairs,
        as_it_is,
    );
    if let Some(profile) = profile {
        pairs.push(("USERPROFILE".to_owned(), profile));
    }
    add_strings(
        users,
        &format!(r"{sid}\{SHELL_FOLDERS}"),
        machine,
        &mut pairs,
        |name| {
            if name.eq_ignore_ascii_case("AppData") {
                Some("APPDATA".to_owned())
            } else if name.eq_ignore_ascii_case("Local AppData") {
                Some("LOCALAPPDATA".to_owned())
            } else {
                None
            }
        },
    );
    add_strings(
        users,
        &format!(r"{sid}\Environment"),
        machine,
        &mut pairs,
        as_it_is,
    );
    Variables::new(pairs).and_then(machine)
}

/// Adds the string values of a key as variables, under the names that
/// `variable_for` gives them. A value with variables in it is filled in
/// from what is known so far.
fn add_strings(
    root: &Key,
    path: &str,
    machine: &Variables,
    pairs: &mut Vec<(String, String)>,
    variable_for: impl Fn(&str) -> Option<String>,
) {
    let Ok(Some(key)) = Key::open(root.0, path, KEY_READ) else {
        return;
    };
    for value in key.values().unwrap_or_default() {
        let (Some(name), Some(text)) = (
            variable_for(&value.name),
            reg_string(value.value_type, &value.data),
        ) else {
            continue;
        };
        let text = if value.value_type == REG_EXPAND_SZ {
            expand(&text, &Variables::new(pairs.clone()).and_then(machine))
        } else {
            text
        };
        pairs.push((name, text));
    }
}

// ---------------------------------------------------------------------
// Run values
// ---------------------------------------------------------------------

fn root_of(hive: &Hive) -> HKEY {
    match hive {
        Hive::Machine => HKEY_LOCAL_MACHINE,
        Hive::User { .. } => HKEY_USERS,
    }
}

fn run_key_path(value: &RunValue) -> String {
    match &value.hive {
        Hive::Machine => value.key.clone(),
        Hive::User { sid } => format!(r"{sid}\{}", value.key),
    }
}

fn view_of(value: &RunValue) -> REG_SAM_FLAGS {
    match value.view {
        View::Native => KEY_WOW64_64KEY,
        View::Wow32 => KEY_WOW64_32KEY,
    }
}

fn open_run_key(value: &RunValue, access: REG_SAM_FLAGS) -> Result<Option<Key>, WIN32_ERROR> {
    Key::open(
        root_of(&value.hive),
        &run_key_path(value),
        access | view_of(value),
    )
}

fn run_values(machine: &Variables, users: &[UserHive], survey: &mut Survey) {
    let mut places: Vec<(Hive, View, &Variables)> = vec![
        (Hive::Machine, View::Native, machine),
        (Hive::Machine, View::Wow32, machine),
    ];
    for user in users {
        places.push((
            Hive::User {
                sid: user.sid.clone(),
            },
            View::Native,
            &user.variables,
        ));
    }
    for (hive, view, variables) in places {
        for key_path in RUN_KEYS {
            let place = RunValue {
                hive: hive.clone(),
                view,
                key: key_path.to_owned(),
                name: String::new(),
                value_type: REG_SZ,
                data: Vec::new(),
            };
            let values = match open_run_key(&place, KEY_READ) {
                Ok(Some(key)) => key.values(),
                Ok(None) => continue,
                Err(error) => Err(error),
            };
            match values {
                Ok(values) => {
                    for value in values {
                        let entry = Entry::RunValue(RunValue {
                            name: value.name,
                            value_type: value.value_type,
                            data: value.data,
                            ..place.clone()
                        });
                        let lines = commands(&entry, variables);
                        if !lines.is_empty() {
                            survey.seen.push(Seen { entry, lines });
                        }
                    }
                }
                Err(error) => survey.problems.push(format!(
                    "{hive}\\{key_path} could not be read (Windows error {})",
                    error.0
                )),
            }
        }
    }
}

// ---------------------------------------------------------------------
// Scheduled tasks
// ---------------------------------------------------------------------

impl Windows {
    /// The topmost folder of the Task Scheduler.
    fn task_root(&self) -> Result<ITaskFolder, Failure> {
        let _ = &self.com;
        let cannot = |error: windows::core::Error| {
            com_failure("the Task Scheduler cannot be reached", &error)
        };
        // SAFETY: the class identifier is a constant of the bindings, and
        // the component model is set up for this thread for as long as
        // `self` lives.
        let service: ITaskService =
            unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
                .map_err(cannot)?;
        let nothing = VARIANT::default();
        // SAFETY: calls through an interface pointer that is alive; four
        // empty values mean "this machine, as the caller".
        unsafe {
            service
                .Connect(&nothing, &nothing, &nothing, &nothing)
                .map_err(cannot)?;
            service.GetFolder(&BSTR::from("\\")).map_err(cannot)
        }
    }

    fn tasks(&self, machine: &Variables, users: &[UserHive], survey: &mut Survey) {
        let root = match self.task_root() {
            Ok(root) => root,
            Err(failure) => {
                survey
                    .problems
                    .push(format!("the scheduled tasks could not be read: {failure}"));
                return;
            }
        };
        let mut unreadable = 0usize;
        let mut found = Vec::new();
        walk_tasks(&root, 0, &mut found, &mut unreadable);
        if unreadable > 0 {
            survey.problems.push(format!(
                "{unreadable} scheduled tasks or task folders could not be read"
            ));
        }
        for task in found {
            // A task is filled in with the variables of the user it runs
            // as. For a user whose settings are not loaded, and for the
            // accounts of the system, that is what is the same for all.
            let variables = task::read(&task.xml)
                .ok()
                .and_then(|definition| definition.user)
                .and_then(|user| {
                    users
                        .iter()
                        .find(|known| known.sid.eq_ignore_ascii_case(&user))
                })
                .map_or(machine, |known| &known.variables);
            let entry = Entry::Task(task);
            let lines = commands(&entry, variables);
            survey.seen.push(Seen { entry, lines });
        }
    }

    fn register_task(&self, task: &Task) -> Result<Vec<String>, Failure> {
        let definition = task::read(&task.xml).map_err(Failure::new)?;
        let (folder_path, name) = split_task_path(&task.path);
        let root = self.task_root()?;
        let nothing = VARIANT::default();
        // SAFETY: calls through interface pointers that are alive, with
        // strings that live through each call.
        let folder = match unsafe { root.GetFolder(&BSTR::from(folder_path)) } {
            Ok(folder) => folder,
            Err(_) => unsafe {
                root.CreateFolder(&BSTR::from(folder_path.trim_start_matches('\\')), &nothing)
            }
            .map_err(|error| com_failure("the task's folder cannot be made", &error))?,
        };
        // The definition and nothing else is handed over. A task takes
        // its access rights from its folder, with a right to read for the
        // account it runs as, unless its definition names rights of its
        // own; registered again in the same folder it gets the same
        // rights. Rights handed over next to the definition would be
        // written into the definition, and it would no longer be the one
        // that was recorded.
        //
        // SAFETY: as above. No account and no password are given: the
        // definition names the account, and a task that needs a password
        // was never removed.
        let registered = unsafe {
            folder.RegisterTask(
                &BSTR::from(name),
                &BSTR::from(task.xml.as_str()),
                TASK_CREATE.0,
                &nothing,
                &nothing,
                TASK_LOGON_TYPE(definition.logon.number()),
                &nothing,
            )
        }
        .map_err(|error| com_failure("the Task Scheduler does not take it", &error))?;

        let mut notes = Vec::new();
        if let Some(recorded) = &task.security {
            // SAFETY: a call through an interface pointer that is alive;
            // the result is an owned string.
            let now = unsafe { registered.GetSecurityDescriptor(TASK_RIGHTS) }
                .ok()
                .map(|sddl| sddl.to_string());
            // Other rights than these: somebody had given the task rights
            // after it was registered. They are set as they were, without
            // a second right to read for the account it runs as.
            //
            // SAFETY: as above, with a string that lives through the call.
            if now.as_deref() != Some(recorded.as_str())
                && unsafe {
                    registered.SetSecurityDescriptor(
                        &BSTR::from(recorded.as_str()),
                        TASK_DONT_ADD_PRINCIPAL_ACE.0,
                    )
                }
                .is_err()
            {
                notes.push("its access rights could not be put back as they were".to_owned());
            }
        }
        Ok(notes)
    }
}

/// The parts of a task's access rights that are read and set: who owns
/// it, its group, and who may do what with it.
const TASK_RIGHTS: i32 = (OWNER_SECURITY_INFORMATION.0
    | GROUP_SECURITY_INFORMATION.0
    | DACL_SECURITY_INFORMATION.0) as i32;

fn split_task_path(path: &str) -> (&str, &str) {
    match path.rfind('\\') {
        Some(0) | None => ("\\", path.trim_start_matches('\\')),
        Some(at) => (&path[..at], &path[at + 1..]),
    }
}

fn walk_tasks(folder: &ITaskFolder, depth: usize, found: &mut Vec<Task>, unreadable: &mut usize) {
    // SAFETY: every call goes through an interface pointer that is alive,
    // and each result is an owned value. Collections count from one.
    unsafe {
        match folder.GetTasks(TASK_ENUM_HIDDEN.0) {
            Ok(tasks) => {
                for index in 1..=tasks.Count().unwrap_or(0) {
                    match tasks
                        .get_Item(&VARIANT::from(index))
                        .map_err(|error| com_failure("", &error))
                        .and_then(|task| read_task(&task))
                    {
                        Ok(task) => found.push(task),
                        Err(_) => *unreadable += 1,
                    }
                }
            }
            Err(_) => *unreadable += 1,
        }
        if depth >= MAX_TASK_DEPTH {
            return;
        }
        match folder.GetFolders(0) {
            Ok(folders) => {
                for index in 1..=folders.Count().unwrap_or(0) {
                    match folders.get_Item(&VARIANT::from(index)) {
                        Ok(below) => walk_tasks(&below, depth + 1, found, unreadable),
                        Err(_) => *unreadable += 1,
                    }
                }
            }
            Err(_) => *unreadable += 1,
        }
    }
}

fn read_task(task: &IRegisteredTask) -> Result<Task, Failure> {
    let cannot = |error: windows::core::Error| com_failure("the task cannot be read", &error);
    // SAFETY: calls through an interface pointer that is alive; each
    // result is an owned string.
    unsafe {
        Ok(Task {
            path: task.Path().map_err(cannot)?.to_string(),
            xml: task.Xml().map_err(cannot)?.to_string(),
            security: task
                .GetSecurityDescriptor(TASK_RIGHTS)
                .ok()
                .map(|sddl| sddl.to_string()),
        })
    }
}

// ---------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------

fn services(machine: &Variables, survey: &mut Survey) {
    let names = match Key::open(HKEY_LOCAL_MACHINE, SERVICES, KEY_READ) {
        Ok(Some(key)) => key.subkey_names(),
        Ok(None) => return,
        Err(error) => Err(error),
    };
    let names = match names {
        Ok(names) => names,
        Err(error) => {
            survey.problems.push(format!(
                "the services could not be read (Windows error {})",
                error.0
            ));
            return;
        }
    };
    let mut unreadable = 0usize;
    for name in names {
        match read_service(&name, false) {
            Ok(Some(entry)) => {
                let lines = commands(&entry, machine);
                survey.seen.push(Seen { entry, lines });
            }
            Ok(None) => {}
            Err(_) => unreadable += 1,
        }
    }
    if unreadable > 0 {
        survey
            .problems
            .push(format!("{unreadable} services could not be read"));
    }
}

/// Reads a service from its key in the registry. In full, with the whole
/// key and the access rights, or just enough to tell what it starts.
/// Nothing if there is no such key, or if the key is not a service's: a
/// few drivers keep settings there without being one.
fn read_service(name: &str, in_full: bool) -> Result<Option<Entry>, Failure> {
    let cannot = |error| registry_failure("its key in the registry cannot be read", error);
    let Some(key) =
        Key::open(HKEY_LOCAL_MACHINE, &format!(r"{SERVICES}\{name}"), KEY_READ).map_err(cannot)?
    else {
        return Ok(None);
    };
    let Some(service_type) = key.number("Type") else {
        return Ok(None);
    };
    if is_being_removed(&key) {
        // It starts nothing any more, and it goes when the last program
        // that has it open lets go of it.
        return Ok(None);
    }
    let Some(image_path) = key
        .string("ImagePath")
        .filter(|path| !path.trim().is_empty())
    else {
        // A service without a program starts nothing by itself.
        return Ok(None);
    };
    let tree = if in_full {
        let mut room = Room {
            bytes: MAX_KEY_BYTES,
            items: MAX_KEY_ITEMS,
        };
        read_tree(&key, 0, true, &mut room)?
    } else {
        // What it takes to tell which library a shared host loads.
        let mut tree = RegKey::default();
        let library = |key: &Key| {
            key.value("ServiceDll")
                .ok()
                .flatten()
                .map(|(value_type, data)| RegValue {
                    name: "ServiceDll".to_owned(),
                    value_type,
                    data,
                })
        };
        tree.values.extend(library(&key));
        if let Ok(Some(parameters)) = key.subkey("Parameters", KEY_READ) {
            tree.subkeys.push(SubKey {
                name: "Parameters".to_owned(),
                key: RegKey {
                    values: library(&parameters).into_iter().collect(),
                    subkeys: Vec::new(),
                },
            });
        }
        tree
    };
    let mut dependencies = key.strings("DependOnService");
    dependencies.extend(
        key.strings("DependOnGroup")
            .into_iter()
            .map(|group| format!("+{group}")),
    );
    Ok(Some(Entry::Service(Service {
        name: name.to_owned(),
        display_name: key.string("DisplayName").unwrap_or_default(),
        service_type,
        start_type: key.number("Start").unwrap_or(3),
        error_control: key.number("ErrorControl").unwrap_or(1),
        image_path,
        load_order_group: key.string("Group").unwrap_or_default(),
        dependencies,
        account: key.string("ObjectName").unwrap_or_default(),
        security: if in_full {
            service_security(name)
        } else {
            None
        },
        key: tree,
    })))
}

/// Whether the service manager has marked the service of this key for
/// removal. It does that when a service is deleted while a program still
/// has it open, or while it runs; the key stays until then.
fn is_being_removed(key: &Key) -> bool {
    key.number("DeleteFlag").is_some_and(|flag| flag != 0)
}

/// An open handle of the service manager, closed when it goes.
struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenSCManagerW, OpenServiceW or
        // CreateServiceW and is closed exactly once, here.
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

fn service_manager(access: u32) -> windows::core::Result<ServiceHandle> {
    // SAFETY: two null strings mean "this machine" and "the database of
    // active services", as the function documents.
    unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access) }.map(ServiceHandle)
}

fn open_service(
    manager: &ServiceHandle,
    name: &str,
    access: u32,
) -> windows::core::Result<ServiceHandle> {
    // SAFETY: the manager's handle is open, and the name is a
    // zero-terminated string that lives through the call.
    unsafe { OpenServiceW(manager.0, &HSTRING::from(name), access) }.map(ServiceHandle)
}

fn everything_about_access() -> OBJECT_SECURITY_INFORMATION {
    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
}

/// Who may do what with a service, in the notation `sc sdshow` prints.
fn service_security(name: &str) -> Option<String> {
    let manager = service_manager(SC_MANAGER_CONNECT).ok()?;
    let service = open_service(&manager, name, READ_CONTROL).ok()?;
    let mut needed = 0u32;
    // SAFETY: a call with no buffer, to learn how large one has to be.
    let first = unsafe {
        QueryServiceObjectSecurity(
            service.0,
            everything_about_access().0,
            None,
            0,
            &raw mut needed,
        )
    };
    match first {
        Err(error) if error.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() && needed > 0 => {}
        _ => return None,
    }
    // Aligned for the structures a security descriptor is made of.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    let descriptor = PSECURITY_DESCRIPTOR(buffer.as_mut_ptr().cast::<c_void>());
    let mut text = PWSTR::null();
    // SAFETY: the buffer is ours and at least `needed` bytes long, which
    // is what the first call asked for. The text that the conversion
    // hands out is read while it is alive and freed with LocalFree, as
    // its documentation says.
    unsafe {
        QueryServiceObjectSecurity(
            service.0,
            everything_about_access().0,
            Some(descriptor),
            needed,
            &raw mut needed,
        )
        .ok()?;
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            everything_about_access(),
            &raw mut text,
            None,
        )
        .ok()?;
        let sddl = String::from_utf16_lossy(text.as_wide());
        let _ = LocalFree(Some(HLOCAL(text.0.cast::<c_void>())));
        Some(sddl)
    }
}

fn service_failure(what: &str, error: &windows::core::Error) -> Failure {
    if error.code() == ERROR_SERVICE_MARKED_FOR_DELETE.to_hresult() {
        Failure::new(STILL_BEING_REMOVED)
    } else {
        com_failure(what, error)
    }
}

fn delete_service(name: &str) -> Result<(), Failure> {
    let gone = |error: &windows::core::Error| {
        error.code() == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult()
            || error.code() == ERROR_SERVICE_MARKED_FOR_DELETE.to_hresult()
    };
    let manager = service_manager(SC_MANAGER_CONNECT)
        .map_err(|error| com_failure("the service manager cannot be reached", &error))?;
    let service = match open_service(&manager, name, DELETE) {
        Ok(service) => service,
        Err(error) if gone(&error) => return Ok(()),
        Err(error) => return Err(com_failure("the service cannot be opened", &error)),
    };
    // SAFETY: the handle is open and was opened with the right to delete.
    match unsafe { DeleteService(service.0) } {
        Ok(()) => Ok(()),
        Err(error) if gone(&error) => Ok(()),
        Err(error) => Err(com_failure("the service cannot be removed", &error)),
    }
}

fn create_service(service: &Service) -> Result<Vec<String>, Failure> {
    if service.is_user_instance() {
        return Err(Failure::new(
            "it is one that Windows makes for each user who logs on, and nobody else can make it",
        ));
    }
    let path = format!(r"{SERVICES}\{}", service.name);
    if let Some(key) = Key::open(HKEY_LOCAL_MACHINE, &path, KEY_READ)
        .map_err(|error| registry_failure("its key in the registry cannot be looked at", error))?
    {
        return Err(Failure::new(if is_being_removed(&key) {
            STILL_BEING_REMOVED
        } else {
            "there is one at its place already"
        }));
    }

    let manager = service_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)
        .map_err(|error| com_failure("the service manager cannot be reached", &error))?;
    let name = HSTRING::from(service.name.as_str());
    let display_name = HSTRING::from(service.display_name.as_str());
    let image_path = HSTRING::from(service.image_path.as_str());
    let group = HSTRING::from(service.load_order_group.as_str());
    let account = HSTRING::from(service.account.as_str());
    // The names one after the other, each with a zero at its end, and a
    // zero more at the end of all.
    let dependencies: Vec<u16> = service
        .dependencies
        .iter()
        .flat_map(|dependency| dependency.encode_utf16().chain(std::iter::once(0)))
        .chain(std::iter::once(0))
        .collect();
    let or_nothing = |text: &HSTRING, wanted: bool| {
        if wanted {
            PCWSTR(text.as_ptr())
        } else {
            PCWSTR::null()
        }
    };
    // SAFETY: every string is zero-terminated and lives through the
    // call; a null string means "none" or "the default" for each of the
    // parameters it is passed for. No password is given: a service that
    // needs one was never removed.
    let created = unsafe {
        CreateServiceW(
            manager.0,
            &name,
            or_nothing(&display_name, !service.display_name.is_empty()),
            READ_CONTROL | WRITE_DAC | WRITE_OWNER | SERVICE_CHANGE_CONFIG,
            ENUM_SERVICE_TYPE(service.service_type),
            SERVICE_START_TYPE(service.start_type),
            SERVICE_ERROR(service.error_control),
            &image_path,
            or_nothing(&group, !service.load_order_group.is_empty()),
            None,
            if service.dependencies.is_empty() {
                PCWSTR::null()
            } else {
                PCWSTR(dependencies.as_ptr())
            },
            or_nothing(
                &account,
                !service.account.is_empty() && !service.is_driver(),
            ),
            PCWSTR::null(),
        )
    }
    .map(ServiceHandle)
    .map_err(|error| service_failure("the service manager does not take it", &error))?;

    let mut notes = Vec::new();
    // First what the service manager keeps in its own memory. Then the
    // rest: what it has no parameter for is in the service's key, and
    // goes back there as recorded. The second step also writes whatever
    // the first could not hand over, so the registry is whole either way.
    let told = tell_the_service_manager(&created, &service.key);
    let written = Key::create(HKEY_LOCAL_MACHINE, &path, KEY_WOW64_64KEY)
        .is_ok_and(|key| write_back(&key, &service.key, true));
    if !written {
        notes
            .push("part of its key in the registry could not be written back as it was".to_owned());
    } else if !told {
        notes.push(
            "some of its settings are back in the registry only, and hold from the next start of \
             Windows"
                .to_owned(),
        );
    }

    // A new service gets the access rights Windows gives every service.
    // Mostly those are the rights it had, and then nothing is written.
    if let Some(sddl) = &service.security
        && service_security(&service.name).as_deref() != Some(sddl.as_str())
        && !set_service_security(&created, sddl)
    {
        notes.push("its access rights could not be put back as they were".to_owned());
    }
    Ok(notes)
}

/// A number that a recorded key holds under a name.
fn recorded_number(key: &RegKey, name: &str) -> Option<u32> {
    const REG_DWORD: u32 = 4;
    let value = key.value(name)?;
    let bytes: [u8; 4] = value.data.as_slice().try_into().ok()?;
    (value.value_type == REG_DWORD).then(|| u32::from_le_bytes(bytes))
}

/// Hands one setting to the service manager.
///
/// # Safety
///
/// `info` has to be the structure that the service manager expects for
/// `level`, and every pointer in it has to be good for the length of the
/// call.
unsafe fn tell<T>(service: &ServiceHandle, level: SERVICE_CONFIG, info: &T) -> bool {
    // SAFETY: the caller's promise; the pointer is to a value that lives
    // through the call.
    unsafe { ChangeServiceConfig2W(service.0, level, Some(ptr::from_ref(info).cast())) }.is_ok()
}

/// Tells the service manager the settings that it keeps in its own
/// memory besides the registry: a delayed start, the service's own
/// identity for access checks, the privileges it asks for, whether a
/// failure without a crash counts as one, how long it gets before a
/// shutdown, and what starts it by itself.
///
/// Written into the registry alone, they hold from the next start of
/// Windows. That was tried: asked right afterwards, the service manager
/// knew of no delayed start and of no identity. Told through its own
/// calls it knows them at once, and writes them into the registry
/// itself.
///
/// The settings are read from the recorded key, where Windows had put
/// them. Returns whether everything that was there could be handed over.
fn tell_the_service_manager(service: &ServiceHandle, key: &RegKey) -> bool {
    let mut told = true;
    // SAFETY, for each call of `tell` below: the structure is the one the
    // documentation gives for the level it is passed with.
    if recorded_number(key, "DelayedAutostart").is_some_and(|delayed| delayed != 0) {
        let info = SERVICE_DELAYED_AUTO_START_INFO {
            fDelayedAutostart: true.into(),
        };
        told &= unsafe { tell(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &info) };
    }
    if let Some(kind) = recorded_number(key, "ServiceSidType").filter(|&kind| kind != 0) {
        let info = SERVICE_SID_INFO {
            dwServiceSidType: kind,
        };
        told &= unsafe { tell(service, SERVICE_CONFIG_SERVICE_SID_INFO, &info) };
    }
    if recorded_number(key, "FailureActionsOnNonCrashFailures").is_some_and(|flag| flag != 0) {
        let info = SERVICE_FAILURE_ACTIONS_FLAG {
            fFailureActionsOnNonCrashFailures: true.into(),
        };
        told &= unsafe { tell(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &info) };
    }
    if let Some(timeout) = recorded_number(key, "PreshutdownTimeout") {
        let info = SERVICE_PRESHUTDOWN_INFO {
            dwPreshutdownTimeout: timeout,
        };
        told &= unsafe { tell(service, SERVICE_CONFIG_PRESHUTDOWN_INFO, &info) };
    }
    if let Some(privileges) = key.value("RequiredPrivileges") {
        // Names one after the other, each with a zero at its end, and a
        // zero more at the end of all. The two zeros are made sure of.
        let mut names: Vec<u16> = privileges
            .data
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        while names.last() == Some(&0) {
            names.pop();
        }
        if !names.is_empty() {
            names.extend([0, 0]);
            let info = SERVICE_REQUIRED_PRIVILEGES_INFOW {
                pmszRequiredPrivileges: PWSTR(names.as_mut_ptr()),
            };
            // SAFETY: as above; the names live until after the call.
            told &= unsafe { tell(service, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &info) };
        }
    }
    if let Some(recorded) = key.subkey("TriggerInfo") {
        told &= match triggers_of(recorded) {
            Some(triggers) => tell_triggers(service, triggers),
            None => false,
        };
    }
    told
}

/// One of the events that start or stop a service by itself.
struct Trigger {
    kind: u32,
    action: u32,
    subtype: GUID,
    /// What narrows the event down: each a kind and its bytes.
    data: Vec<(u32, Vec<u8>)>,
}

/// Reads a service's triggers from the key Windows keeps them in: a key
/// for each, named by its number, with the kind of event, what to do,
/// the event's identifier in the layout of memory, and numbered pairs of
/// data and the data's kind. `None` if a key does not read that way.
fn triggers_of(recorded: &RegKey) -> Option<Vec<Trigger>> {
    let mut numbered: Vec<(u32, &RegKey)> = recorded
        .subkeys
        .iter()
        .map(|subkey| Some((subkey.name.parse().ok()?, &subkey.key)))
        .collect::<Option<_>>()?;
    numbered.sort_by_key(|(number, _)| *number);
    let mut triggers = Vec::new();
    for (_, key) in numbered {
        let id: [u8; 16] = key.value("GUID")?.data.as_slice().try_into().ok()?;
        let mut data = Vec::new();
        while let Some(bytes) = key.value(&format!("Data{}", data.len())) {
            let kind = recorded_number(key, &format!("DataType{}", data.len()))?;
            data.push((kind, bytes.data.clone()));
        }
        triggers.push(Trigger {
            kind: recorded_number(key, "Type")?,
            action: recorded_number(key, "Action")?,
            subtype: GUID::from_values(
                u32::from_le_bytes([id[0], id[1], id[2], id[3]]),
                u16::from_le_bytes([id[4], id[5]]),
                u16::from_le_bytes([id[6], id[7]]),
                [id[8], id[9], id[10], id[11], id[12], id[13], id[14], id[15]],
            ),
            data,
        });
    }
    Some(triggers)
}

fn tell_triggers(service: &ServiceHandle, mut triggers: Vec<Trigger>) -> bool {
    // The structures point into `triggers` and into `items`. Both stay
    // where they are, and unchanged, until after the call.
    let mut items: Vec<Vec<SERVICE_TRIGGER_SPECIFIC_DATA_ITEM>> = triggers
        .iter_mut()
        .map(|trigger| {
            trigger
                .data
                .iter_mut()
                .map(|(kind, bytes)| SERVICE_TRIGGER_SPECIFIC_DATA_ITEM {
                    dwDataType: SERVICE_TRIGGER_SPECIFIC_DATA_ITEM_DATA_TYPE(*kind),
                    cbData: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
                    pData: bytes.as_mut_ptr(),
                })
                .collect()
        })
        .collect();
    let mut raw: Vec<SERVICE_TRIGGER> = triggers
        .iter_mut()
        .zip(&mut items)
        .map(|(trigger, items)| SERVICE_TRIGGER {
            dwTriggerType: SERVICE_TRIGGER_TYPE(trigger.kind),
            dwAction: SERVICE_TRIGGER_ACTION(trigger.action),
            pTriggerSubtype: &raw mut trigger.subtype,
            cDataItems: u32::try_from(items.len()).unwrap_or(u32::MAX),
            pDataItems: if items.is_empty() {
                ptr::null_mut()
            } else {
                items.as_mut_ptr()
            },
        })
        .collect();
    let info = SERVICE_TRIGGER_INFO {
        cTriggers: u32::try_from(raw.len()).unwrap_or(u32::MAX),
        pTriggers: raw.as_mut_ptr(),
        pReserved: ptr::null_mut(),
    };
    // SAFETY: the structure for this level, with as many triggers and
    // data items as it says, each pointer into a vector that is alive
    // and is not touched until the call has returned.
    unsafe { tell(service, SERVICE_CONFIG_TRIGGER_INFO, &info) }
}

fn set_service_security(service: &ServiceHandle, sddl: &str) -> bool {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the text is a zero-terminated string that lives through
    // the call; the descriptor that comes back is used while it is alive
    // and freed with LocalFree, as the documentation says.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(sddl),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
        .is_err()
        {
            return false;
        }
        // With the owner if the caller may set it, and without if not.
        let set = SetServiceObjectSecurity(service.0, everything_about_access(), descriptor)
            .or_else(|_| SetServiceObjectSecurity(service.0, DACL_SECURITY_INFORMATION, descriptor))
            .is_ok();
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        set
    }
}

// ---------------------------------------------------------------------
// Shortcuts
// ---------------------------------------------------------------------

impl Windows {
    fn shortcuts(&self, machine: &Variables, survey: &mut Survey) {
        let own = process_variables();
        for (folder, variables) in [
            (known_folder(&FOLDERID_Startup), &own),
            (known_folder(&FOLDERID_CommonStartup), machine),
        ] {
            let Some(folder) = folder else {
                continue;
            };
            let Ok(listing) = std::fs::read_dir(&folder) else {
                // A Startup folder that is not there holds nothing.
                continue;
            };
            for item in listing.flatten() {
                let path = item.path();
                let is_shortcut = path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("lnk"));
                if !is_shortcut {
                    continue;
                }
                let shown = path.display().to_string();
                match self.read_shortcut(&shown) {
                    Ok(shortcut) => {
                        let entry = Entry::Shortcut(shortcut);
                        let lines = commands(&entry, variables);
                        survey.seen.push(Seen { entry, lines });
                    }
                    Err(failure) => survey
                        .problems
                        .push(format!("the shortcut {shown} could not be read: {failure}")),
                }
            }
        }
    }

    /// What a shortcut file points at, as the shell reads it.
    fn read_shortcut(&self, path: &str) -> Result<Shortcut, Failure> {
        let _ = &self.com;
        let cannot = |error: windows::core::Error| com_failure("the shell cannot read it", &error);
        // SAFETY: the class identifier is a constant of the bindings, and
        // the component model is set up for this thread for as long as
        // `self` lives. The buffers are ours, and the functions are told
        // their lengths through the slices.
        unsafe {
            let link: IShellLinkW =
                CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).map_err(cannot)?;
            let file: IPersistFile = link.cast().map_err(cannot)?;
            file.Load(&HSTRING::from(path), STGM_READ).map_err(cannot)?;
            let mut buffer = vec![0u16; LONG_PATH];
            // As it is written in the shortcut, variables and all.
            link.GetPath(&mut buffer, std::ptr::null_mut(), SLGP_RAWPATH.0 as u32)
                .map_err(cannot)?;
            let target = until_zero(&buffer);
            buffer.fill(0);
            link.GetArguments(&mut buffer).map_err(cannot)?;
            Ok(Shortcut {
                path: path.to_owned(),
                target,
                arguments: until_zero(&buffer),
            })
        }
    }
}

fn known_folder(id: &GUID) -> Option<String> {
    // SAFETY: the identifier is a constant of the bindings. The string
    // that comes back is read while it is alive and freed with
    // CoTaskMemFree, as the documentation says.
    unsafe {
        let path = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).ok()?;
        let text = String::from_utf16_lossy(path.as_wide());
        CoTaskMemFree(Some(path.0.cast::<c_void>().cast_const()));
        Some(text)
    }
}

// ---------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------

fn until_zero(units: &[u16]) -> String {
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

/// Calls a function that writes a path into a buffer and returns how many
/// units it wrote, or how many it would need, or zero if it failed.
fn path_from(call: impl Fn(&mut [u16]) -> u32) -> Option<String> {
    let mut buffer = vec![0u16; 512];
    loop {
        let written = call(&mut buffer) as usize;
        if written == 0 {
            return None;
        }
        if written < buffer.len() {
            return Some(String::from_utf16_lossy(&buffer[..written]));
        }
        if buffer.len() >= LONG_PATH {
            return None;
        }
        buffer.resize((written + 1).min(LONG_PATH), 0);
    }
}
