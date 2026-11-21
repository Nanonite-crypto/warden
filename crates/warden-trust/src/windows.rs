//! What Warden asks of Windows about a signature.
//!
//! Three questions, one for each route: does the signature inside this
//! executable hold, is this file listed in a catalogue whose signature
//! holds, and does the signature of this package hold. Each goes to
//! `WinVerifyTrust`, the function Windows itself uses, and each answer
//! comes back with the chain of certificates Windows built, from which
//! this module reads who signed, whether the chain ends in a root of
//! Microsoft's, and whether revocation was checked.
//!
//! Nothing here decides anything. Which signers count is for the trust
//! list, and which route may be tried for which file is for the caller.
//!
//! This is the only module of the crate with `unsafe` code. Each block is
//! one call of a Windows function, or reads memory that such a call handed
//! out, with what makes it sound written next to it.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    CERT_E_CHAINING, CERT_E_EXPIRED, CERT_E_PURPOSE, CERT_E_REVOCATION_FAILURE, CERT_E_REVOKED,
    CERT_E_UNTRUSTEDCA, CERT_E_UNTRUSTEDROOT, CERT_E_WRONG_USAGE, CRYPT_E_NO_REVOCATION_CHECK,
    CRYPT_E_REVOCATION_OFFLINE, HANDLE, INVALID_HANDLE_VALUE, NTE_BAD_ALGID, TRUST_E_BAD_DIGEST,
    TRUST_E_CERT_SIGNATURE, TRUST_E_COUNTER_SIGNER, TRUST_E_EXPLICIT_DISTRUST, TRUST_E_NOSIGNATURE,
    TRUST_E_PROVIDER_UNKNOWN, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_SUBJECT_NOT_TRUSTED,
};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA256_ALGORITHM, CERT_CHAIN_CONTEXT,
    CERT_CHAIN_POLICY_MICROSOFT_ROOT, CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS,
    CERT_CONTEXT, CERT_NAME_ATTR_TYPE, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    CERT_TRUST_IS_OFFLINE_REVOCATION, CERT_TRUST_REVOCATION_STATUS_UNKNOWN, CertGetNameStringW,
    CertVerifyCertificateChainPolicy, MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG,
    szOID_COMMON_NAME, szOID_ORGANIZATION_NAME,
};
use windows_sys::Win32::Security::WinTrust::{
    DRIVER_ACTION_VERIFY, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_BLOB_INFO,
    WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_BLOB, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
    WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTD_UICONTEXT_EXECUTE,
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows_sys::core::{GUID, PCWSTR};

use crate::signature::{Certificate, Found, Revocation, Signer, hex};
use crate::verify::{Options, Os};

/// What tells Windows that the bytes it is handed are the signature file
/// of an app package. Microsoft's own reader of packages passes the same
/// value.
const PACKAGE_SIGNATURE_SUBJECT: GUID = GUID::from_u128(0x5598cff1_68db_4340_b57f_1cacf88c9a51);
/// Most catalogues that are looked at for one file. A file is in one, or
/// in a few when updates replaced each other.
const MAX_CATALOGS: usize = 16;
/// Most certificates a chain is read for.
const MAX_CHAIN: usize = 32;
/// Room for the longest hash a catalogue uses.
const MAX_HASH_BYTES: usize = 64;

/// Windows, asked through `WinVerifyTrust`.
pub(crate) struct Windows {
    options: Options,
}

impl Windows {
    pub(crate) fn new(options: Options) -> Self {
        Self { options }
    }

    /// Has Windows check one signature, and reads who made it.
    fn verify(&self, subject: Subject<'_>) -> Checked {
        let mut file_info;
        let mut catalog_info;
        let mut blob_info;
        let (choice, target) = match subject {
            Subject::File { path, handle } => {
                file_info = WINTRUST_FILE_INFO {
                    cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
                    pcwszFilePath: path.as_ptr(),
                    hFile: handle,
                    pgKnownSubject: ptr::null_mut(),
                };
                (
                    WTD_CHOICE_FILE,
                    WINTRUST_DATA_0 {
                        pFile: &raw mut file_info,
                    },
                )
            }
            Subject::Member {
                catalog,
                tag,
                path,
                handle,
                hash,
                admin,
            } => {
                catalog_info = WINTRUST_CATALOG_INFO {
                    cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
                    dwCatalogVersion: 0,
                    pcwszCatalogFilePath: catalog.as_ptr(),
                    pcwszMemberTag: tag.as_ptr(),
                    pcwszMemberFilePath: path.as_ptr(),
                    hMemberFile: handle,
                    pbCalculatedFileHash: hash.as_mut_ptr(),
                    cbCalculatedFileHash: hash.len() as u32,
                    pcCatalogContext: ptr::null_mut(),
                    hCatAdmin: admin,
                };
                (
                    WTD_CHOICE_CATALOG,
                    WINTRUST_DATA_0 {
                        pCatalog: &raw mut catalog_info,
                    },
                )
            }
            Subject::PackageSignature { bytes, name } => {
                blob_info = WINTRUST_BLOB_INFO {
                    cbStruct: size_of::<WINTRUST_BLOB_INFO>() as u32,
                    gSubject: PACKAGE_SIGNATURE_SUBJECT,
                    pcwszDisplayName: name.as_ptr(),
                    cbMemObject: bytes.len() as u32,
                    // Windows only reads the bytes; the type of the field
                    // is what asks for a pointer that could be written to.
                    pbMemObject: bytes.as_ptr().cast_mut(),
                    cbMemSignedMsg: 0,
                    pbMemSignedMsg: ptr::null_mut(),
                };
                (
                    WTD_CHOICE_BLOB,
                    WINTRUST_DATA_0 {
                        pBlob: &raw mut blob_info,
                    },
                )
            }
        };

        let mut flags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_DISABLE_MD2_MD4;
        if !self.options.network {
            flags |= WTD_CACHE_ONLY_URL_RETRIEVAL;
        }
        let mut data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: ptr::null_mut(),
            pSIPClientData: ptr::null_mut(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice: choice,
            Anonymous: target,
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: ptr::null_mut(),
            pwszURLReference: ptr::null_mut(),
            dwProvFlags: flags,
            dwUIContext: WTD_UICONTEXT_EXECUTE,
            pSignatureSettings: ptr::null_mut(),
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // SAFETY: `action` and `data` are valid for the call. `data` points
        // to the one of the three structures above that matches
        // `dwUnionChoice`, and that structure points to strings that end
        // in a zero, to a handle that is open, or to bytes with their
        // length, all of which the caller borrowed to this function for
        // longer than the call. The first argument asks for no window.
        let status = unsafe {
            WinVerifyTrust(
                INVALID_HANDLE_VALUE,
                &raw mut action,
                (&raw mut data).cast::<c_void>(),
            )
        };
        let signer = if data.hWVTStateData.is_null() {
            None
        } else {
            // SAFETY: the call above stored a state handle, and it is
            // closed only below.
            unsafe { signer_of(data.hWVTStateData) }
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: as for the first call. This one frees the state that
        // the first one allocated, and nothing reads that state after it.
        unsafe {
            WinVerifyTrust(
                INVALID_HANDLE_VALUE,
                &raw mut action,
                (&raw mut data).cast::<c_void>(),
            );
        }
        Checked { status, signer }
    }
}

/// What `WinVerifyTrust` is asked about.
enum Subject<'a> {
    /// The signature inside a file.
    File { path: &'a [u16], handle: HANDLE },
    /// A file as a member of a catalogue.
    Member {
        catalog: &'a [u16],
        tag: &'a [u16],
        path: &'a [u16],
        handle: HANDLE,
        hash: &'a mut [u8],
        admin: isize,
    },
    /// The signature file of an app package, in memory.
    PackageSignature { bytes: &'a [u8], name: &'a [u16] },
}

/// What `WinVerifyTrust` said, and who signed if it got that far.
struct Checked {
    status: i32,
    signer: Option<Signer>,
}

impl Os for Windows {
    fn embedded(&self, path: &Path, file: &File) -> Found {
        let path = wide(path);
        rewind(file);
        let checked = self.verify(Subject::File {
            path: &path,
            handle: file.as_raw_handle(),
        });
        match found(checked, None) {
            // The caller asks only about a file that has a signature
            // table.
            Found::Nothing => Found::Invalid {
                why: "Windows finds no signature it can check in the file's signature table"
                    .to_owned(),
            },
            other => other,
        }
    }

    fn catalog(&self, path: &Path, file: &File) -> Found {
        let path = wide(path);
        let mut answer = Found::Nothing;
        // Newer catalogues list SHA-256 hashes, older ones SHA-1.
        for (algorithm, algorithm_name) in [
            (BCRYPT_SHA256_ALGORITHM, "SHA-256"),
            (BCRYPT_SHA1_ALGORITHM, "SHA-1"),
        ] {
            let Some(admin) = CatalogAdmin::acquire(algorithm) else {
                answer = more_telling(
                    answer,
                    Found::Failed {
                        why: "the catalogues of Windows could not be opened".to_owned(),
                    },
                );
                continue;
            };
            rewind(file);
            let Some(mut hash) = admin.hash_of(file) else {
                answer = more_telling(
                    answer,
                    Found::Failed {
                        why: "Windows could not work out the hash that its catalogues list the \
                              file by"
                            .to_owned(),
                    },
                );
                continue;
            };
            let tag: Vec<u16> = hex(&hash)
                .to_ascii_uppercase()
                .encode_utf16()
                .chain(Some(0))
                .collect();

            // The catalogue the last call returned. Zero starts the
            // enumeration.
            let mut previous: isize = 0;
            for looked_at in 1..=MAX_CATALOGS {
                // SAFETY: `admin` is open and the hash is passed with its
                // length. `previous` is zero, or the catalogue context the
                // last call returned; the function takes that one over and
                // releases it, whatever it returns.
                let current = unsafe {
                    CryptCATAdminEnumCatalogFromHash(
                        admin.0,
                        hash.as_ptr(),
                        hash.len() as u32,
                        0,
                        &raw mut previous,
                    )
                };
                if current == 0 {
                    break;
                }
                let mut info = CATALOG_INFO {
                    cbStruct: size_of::<CATALOG_INFO>() as u32,
                    wszCatalogFile: [0; 260],
                };
                // SAFETY: `current` is the context the call above returned,
                // and `info` is a structure of the size it states.
                let named = unsafe { CryptCATCatalogInfoFromContext(current, &raw mut info, 0) };
                if named != 0 && info.wszCatalogFile.contains(&0) {
                    rewind(file);
                    let checked = self.verify(Subject::Member {
                        catalog: &info.wszCatalogFile,
                        tag: &tag,
                        path: &path,
                        handle: file.as_raw_handle(),
                        hash: &mut hash,
                        admin: admin.0,
                    });
                    let place =
                        format!("{} (by {algorithm_name})", file_name(&info.wszCatalogFile));
                    let this = found(checked, Some(place));
                    if matches!(this, Found::Valid { .. }) {
                        admin.release(current);
                        return this;
                    }
                    answer = more_telling(answer, this);
                }
                if looked_at == MAX_CATALOGS {
                    // Nothing asks for the next one, so this one is still
                    // this function's to release.
                    admin.release(current);
                } else {
                    previous = current;
                }
            }
        }
        answer
    }

    fn package_signature(&self, signature_file: &[u8]) -> Found {
        if u32::try_from(signature_file.len()).is_err() {
            return Found::Invalid {
                why: "the signature file of the file's package is too large".to_owned(),
            };
        }
        let name: Vec<u16> = "AppxSignature.p7x".encode_utf16().chain(Some(0)).collect();
        let checked = self.verify(Subject::PackageSignature {
            bytes: signature_file,
            name: &name,
        });
        found(checked, None)
    }
}

/// An open handle to the catalogues of Windows, for one hash algorithm.
struct CatalogAdmin(isize);

impl CatalogAdmin {
    fn acquire(algorithm: PCWSTR) -> Option<Self> {
        let mut handle: isize = 0;
        let subsystem = DRIVER_ACTION_VERIFY;
        // SAFETY: `handle` is a place for the handle, `subsystem` is a
        // GUID that lives through the call, `algorithm` is one of the two
        // constant strings of the bindings, which end in a zero, and the
        // remaining arguments are the documented "none".
        let acquired = unsafe {
            CryptCATAdminAcquireContext2(
                &raw mut handle,
                &raw const subsystem,
                algorithm,
                ptr::null(),
                0,
            )
        };
        (acquired != 0 && handle != 0).then_some(Self(handle))
    }

    /// The hash by which catalogues list this file. For an executable
    /// that is the hash a signature would cover, not the hash of all its
    /// bytes.
    fn hash_of(&self, file: &File) -> Option<Vec<u8>> {
        let mut hash = vec![0u8; MAX_HASH_BYTES];
        let mut length = hash.len() as u32;
        // SAFETY: the context is open, the file handle belongs to `file`,
        // which is borrowed for the call, and the buffer is passed with
        // its length, which the function replaces by the length it used.
        let done = unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                self.0,
                file.as_raw_handle(),
                &raw mut length,
                hash.as_mut_ptr(),
                0,
            )
        };
        if done == 0 || length == 0 || length as usize > hash.len() {
            return None;
        }
        hash.truncate(length as usize);
        Some(hash)
    }

    fn release(&self, catalog: isize) {
        // SAFETY: `catalog` is a context that an enumeration with this
        // handle returned and that nothing has released yet.
        unsafe {
            CryptCATAdminReleaseCatalogContext(self.0, catalog, 0);
        }
    }
}

impl Drop for CatalogAdmin {
    fn drop(&mut self) {
        // SAFETY: the handle was acquired in `acquire` and is released
        // exactly once, here.
        unsafe {
            CryptCATAdminReleaseContext(self.0, 0);
        }
    }
}

/// Of two things that were found on the way to no valid signature, the
/// one that says more: a signature that does not hold before a failure to
/// ask, and either before nothing at all. Of two of a kind, the first.
fn more_telling(so_far: Found, new: Found) -> Found {
    fn weight(found: &Found) -> u8 {
        match found {
            Found::Valid { .. } => 3,
            Found::Invalid { .. } => 2,
            Found::Failed { .. } => 1,
            Found::Nothing | Found::NotApplicable { .. } => 0,
        }
    }
    if weight(&new) > weight(&so_far) {
        new
    } else {
        so_far
    }
}

/// Turns what `WinVerifyTrust` said into what a route found.
fn found(checked: Checked, place: Option<String>) -> Found {
    match checked.status {
        0 => match checked.signer {
            Some(signer) => Found::Valid { signer, place },
            None => Found::Failed {
                why: "Windows accepts the signature and does not say who made it".to_owned(),
            },
        },
        TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => {
            Found::Nothing
        }
        // The signature holds as far as Windows got; what it could not
        // find out is whether a certificate was revoked.
        CERT_E_REVOCATION_FAILURE | CRYPT_E_REVOCATION_OFFLINE | CRYPT_E_NO_REVOCATION_CHECK => {
            match checked.signer {
                Some(mut signer) => {
                    signer.revocation = Revocation::Unknown;
                    Found::Valid { signer, place }
                }
                None => Found::Invalid {
                    why: meaning(checked.status),
                },
            }
        }
        other => Found::Invalid {
            why: meaning(other),
        },
    }
}

/// What an error of `WinVerifyTrust` means, with its number.
fn meaning(status: i32) -> String {
    let text = match status {
        TRUST_E_BAD_DIGEST => "the file was changed after it was signed",
        CERT_E_REVOKED => "a certificate of the signer's chain has been revoked",
        CERT_E_EXPIRED => {
            "a certificate of the signer's chain was not valid at the time that counts"
        }
        CERT_E_UNTRUSTEDROOT => {
            "the signer's chain ends in a root that this machine does not trust"
        }
        CERT_E_CHAINING | CERT_E_UNTRUSTEDCA => {
            "the signer's chain of certificates does not lead to a root that this machine trusts"
        }
        TRUST_E_EXPLICIT_DISTRUST => {
            "the signer's certificate is marked as not trusted on this machine"
        }
        TRUST_E_SUBJECT_NOT_TRUSTED => "Windows does not trust the signature",
        TRUST_E_CERT_SIGNATURE => "the signature of a certificate in the chain does not check",
        TRUST_E_COUNTER_SIGNER => "the timestamp of the signature does not check",
        CERT_E_WRONG_USAGE | CERT_E_PURPOSE => {
            "the signer's certificate is not one for signing code"
        }
        NTE_BAD_ALGID => "the signature uses a hash that is no longer accepted",
        CERT_E_REVOCATION_FAILURE | CRYPT_E_REVOCATION_OFFLINE | CRYPT_E_NO_REVOCATION_CHECK => {
            "it could not be found out whether a certificate of the signer's chain was revoked"
        }
        _ => "Windows rejects the signature",
    };
    format!("{text} (Windows error 0x{:08X})", status as u32)
}

/// Reads who signed out of the state of a `WinVerifyTrust` call.
///
/// # Safety
///
/// `state` must be the state handle that a `WinVerifyTrust` call with
/// `WTD_STATEACTION_VERIFY` stored, and that call's state must not have
/// been closed yet.
unsafe fn signer_of(state: HANDLE) -> Option<Signer> {
    // SAFETY: `state` is a live state handle, as the caller promises. The
    // function returns a pointer into that state, or null.
    let provider = unsafe { WTHelperProvDataFromStateData(state) };
    if provider.is_null() {
        return None;
    }
    // SAFETY: `provider` came from the call above. Signer number 0 is the
    // first one, and the last two arguments say "not a countersigner".
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
    if signer.is_null() {
        return None;
    }
    // SAFETY: not null, and it points into the state, which lives until
    // the caller closes it after this function has returned.
    let chain = unsafe { (*signer).pChainContext };
    if chain.is_null() {
        return None;
    }
    // SAFETY: not null, and part of the same state. The fields read here
    // are the ones Windows documents: how many simple chains there are,
    // and the array of pointers to them.
    let (chains, first) = unsafe { ((*chain).cChain, (*chain).rgpChain) };
    if chains == 0 || first.is_null() {
        return None;
    }
    // SAFETY: the array has at least one entry, as just checked.
    let simple = unsafe { *first };
    if simple.is_null() {
        return None;
    }
    // SAFETY: not null; the count and the array of the chain's elements.
    let (count, elements) = unsafe { ((*simple).cElement as usize, (*simple).rgpElement) };
    if count == 0 || count > MAX_CHAIN || elements.is_null() {
        return None;
    }
    // SAFETY: `elements` points to `count` pointers, as the chain states.
    let elements = unsafe { std::slice::from_raw_parts(elements, count) };

    let mut certificates = Vec::with_capacity(count);
    let mut revocation = Revocation::Checked;
    let mut signer_certificate: *const CERT_CONTEXT = ptr::null();
    for (index, &element) in elements.iter().enumerate() {
        if element.is_null() {
            return None;
        }
        // SAFETY: not null, one element of the chain; the fields read are
        // its certificate, its status bits and what a revocation check
        // left behind.
        let (certificate, status, revocation_info) = unsafe {
            (
                (*element).pCertContext,
                (*element).TrustStatus.dwErrorStatus,
                (*element).pRevocationInfo,
            )
        };
        if certificate.is_null() {
            return None;
        }
        if index == 0 {
            signer_certificate = certificate;
        }
        // SAFETY: `certificate` is not null and belongs to the chain. Its
        // encoded form is a pointer and a length that go together.
        let encoded = unsafe {
            let (bytes, length) = (
                (*certificate).pbCertEncoded,
                (*certificate).cbCertEncoded as usize,
            );
            if bytes.is_null() {
                return None;
            }
            std::slice::from_raw_parts(bytes, length)
        };
        certificates.push(Certificate {
            // SAFETY: `certificate` is a live certificate of the chain.
            subject: unsafe { name(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, ptr::null()) },
            sha256: hex(&Sha256::digest(encoded)),
        });

        // Revocation is asked for every certificate below the root. The
        // root is the last element; nobody can revoke a root but its
        // owner, by taking it out of the store.
        if index + 1 < count {
            let unknown = status
                & (CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION)
                != 0;
            // SAFETY: when it is not null, it points to the result of the
            // revocation check for this element, inside the same chain.
            let checked =
                !revocation_info.is_null() && unsafe { (*revocation_info).dwRevocationResult } == 0;
            if unknown || !checked {
                revocation = Revocation::Unknown;
            }
        }
    }

    Some(Signer {
        // SAFETY: the first element's certificate, checked not to be null
        // in the loop, which ran at least once.
        common_name: unsafe {
            name(
                signer_certificate,
                CERT_NAME_ATTR_TYPE,
                szOID_COMMON_NAME.cast(),
            )
        },
        // SAFETY: as above.
        organization: unsafe {
            name(
                signer_certificate,
                CERT_NAME_ATTR_TYPE,
                szOID_ORGANIZATION_NAME.cast(),
            )
        },
        chain: certificates,
        // SAFETY: `chain` is the live chain context read above.
        microsoft_root: unsafe { ends_in_a_microsoft_root(chain) },
        revocation,
    })
}

/// Asks Windows whether a chain ends in one of Microsoft's own roots.
///
/// Windows compares the root's key with the keys it knows, so a root that
/// somebody installed under Microsoft's name does not pass. The check
/// knows two groups of roots and is asked for one at a time: the ones
/// Windows itself is signed under, and the one Microsoft's applications
/// are signed under.
///
/// # Safety
///
/// `chain` must point to a live certificate chain context.
unsafe fn ends_in_a_microsoft_root(chain: *const CERT_CHAIN_CONTEXT) -> bool {
    [
        0,
        MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG,
    ]
    .into_iter()
    .any(|flags| {
        let parameters = CERT_CHAIN_POLICY_PARA {
            cbSize: size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
            dwFlags: flags,
            pvExtraPolicyPara: ptr::null_mut(),
        };
        let mut status = CERT_CHAIN_POLICY_STATUS {
            cbSize: size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
            // Anything but "passed", in case the call leaves it alone.
            dwError: u32::MAX,
            lChainIndex: 0,
            lElementIndex: 0,
            pvExtraPolicyStatus: ptr::null_mut(),
        };
        // SAFETY: `chain` is live, as the caller promises, and the two
        // structures are of the sizes they state and live through the
        // call.
        let asked = unsafe {
            CertVerifyCertificateChainPolicy(
                CERT_CHAIN_POLICY_MICROSOFT_ROOT,
                chain,
                &raw const parameters,
                &raw mut status,
            )
        };
        asked != 0 && status.dwError == 0
    })
}

/// Reads one name out of a certificate: the display name, or one field of
/// the subject.
///
/// # Safety
///
/// `certificate` must point to a live certificate context, and `field`
/// must be null or the object identifier that goes with `kind`, as a
/// string that ends in a zero.
unsafe fn name(certificate: *const CERT_CONTEXT, kind: u32, field: *const c_void) -> String {
    let mut buffer = [0u16; 512];
    // SAFETY: the certificate and the field are what the caller promises,
    // and the buffer is passed with its length.
    let written = unsafe {
        CertGetNameStringW(
            certificate,
            kind,
            0,
            field,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    };
    // The count includes the zero at the end, and is 1 for "no such
    // field".
    let length = (written as usize).saturating_sub(1).min(buffer.len());
    String::from_utf16_lossy(&buffer[..length])
}

/// A path as Windows takes it: UTF-16 with a zero at the end.
fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// The last part of a path that is given as UTF-16 with a zero at the
/// end.
fn file_name(path: &[u16]) -> String {
    let end = path
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(path.len());
    let text = String::from_utf16_lossy(&path[..end]);
    match text.rsplit(['\\', '/']).next() {
        Some(name) if !name.is_empty() => name.to_owned(),
        _ => text,
    }
}

/// Puts the file's read position back to the start. The functions of
/// Windows that read through a handle read from where it stands.
fn rewind(mut file: &File) {
    // Nothing can be done about a failure here, and the function that
    // reads next reports its own.
    let _ = file.seek(SeekFrom::Start(0));
}
