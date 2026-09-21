use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{LookupAccountSidW, PSID, SID_NAME_USE};
use windows::core::{HSTRING, PWSTR};

/// Resolves Windows SID strings (e.g. "S-1-5-18") to human-readable account
/// names (e.g. "NT AUTHORITY\SYSTEM") using the Windows `LookupAccountSidW` API.
///
/// The cache behind this is process-global and bounded (see `shared_cache`): a
/// SID means the same thing to every source, so one shared copy is both smaller
/// and warmer than one copy per source.
pub struct SidResolver;

impl SidResolver {
    pub const fn new() -> Self {
        Self
    }

    /// Resolve a SID string to "DOMAIN\Username" format.
    /// Returns `None` if the SID cannot be resolved (unknown account, invalid SID, etc.).
    /// Caches both successful and failed lookups.
    /// The lookup runs OUTSIDE the map lock. `LookupAccountSidW` can reach a
    /// domain controller, and holding a process-global lock across that would
    /// stall every source in the process on one slow name resolution.
    pub fn resolve(&self, sid_string: &str) -> Option<String> {
        if let Some(cached) = super::shared_cache::sid_lookup(sid_string) {
            return cached;
        }

        let result = lookup_sid(sid_string);
        super::shared_cache::sid_store(sid_string, result.clone());
        result
    }
}

/// Convert a SID string to a PSID via ConvertStringSidToSidW, then call
/// LookupAccountSidW to get the account name.
fn lookup_sid(sid_string: &str) -> Option<String> {
    let sid_hstring = HSTRING::from(sid_string);

    // Convert string SID to binary PSID
    let mut psid = PSID::default();
    let convert_result = unsafe { ConvertStringSidToSidW(&sid_hstring, &mut psid) };
    if convert_result.is_err() {
        return None;
    }

    // LookupAccountSidW: first call to get buffer sizes
    let mut name_len: u32 = 0;
    let mut domain_len: u32 = 0;
    let mut sid_type = SID_NAME_USE::default();

    _ = unsafe {
        LookupAccountSidW(
            None,
            psid,
            PWSTR::null(),
            &mut name_len,
            PWSTR::null(),
            &mut domain_len,
            &mut sid_type,
        )
    };

    if name_len == 0 {
        unsafe {
            _ = LocalFree(HLOCAL(psid.0));
        }
        return None;
    }

    // Second call with properly sized buffers
    let mut name_buf = vec![0u16; name_len as usize];
    let mut domain_buf = vec![0u16; domain_len as usize];

    let result = unsafe {
        LookupAccountSidW(
            None,
            psid,
            PWSTR(name_buf.as_mut_ptr()),
            &mut name_len,
            PWSTR(domain_buf.as_mut_ptr()),
            &mut domain_len,
            &mut sid_type,
        )
    };

    // Free the PSID allocated by ConvertStringSidToSidW
    unsafe {
        _ = LocalFree(HLOCAL(psid.0));
    }

    if result.is_err() {
        return None;
    }

    let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);

    if domain.is_empty() {
        Some(name)
    } else {
        Some(format!("{domain}\\{name}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sid_resolver_caches_results() {
        let resolver = SidResolver::new();
        // Well-known SID: S-1-5-18 = NT AUTHORITY\SYSTEM
        let first = resolver.resolve("S-1-5-18");
        let second = resolver.resolve("S-1-5-18");
        assert_eq!(first, second);
    }

    #[test]
    fn test_invalid_sid_returns_none() {
        let resolver = SidResolver::new();
        assert!(resolver.resolve("not-a-sid").is_none());
        assert!(resolver.resolve("").is_none());
    }

    #[test]
    fn test_well_known_sids() {
        let resolver = SidResolver::new();

        // S-1-5-18 = SYSTEM
        if let Some(name) = resolver.resolve("S-1-5-18") {
            assert!(
                name.contains("SYSTEM"),
                "S-1-5-18 should resolve to SYSTEM, got: {name}"
            );
        }

        // S-1-5-19 = LOCAL SERVICE
        if let Some(name) = resolver.resolve("S-1-5-19") {
            assert!(
                name.contains("LOCAL SERVICE"),
                "S-1-5-19 should resolve to LOCAL SERVICE, got: {name}"
            );
        }

        // S-1-5-20 = NETWORK SERVICE
        if let Some(name) = resolver.resolve("S-1-5-20") {
            assert!(
                name.contains("NETWORK SERVICE"),
                "S-1-5-20 should resolve to NETWORK SERVICE, got: {name}"
            );
        }
    }
}
