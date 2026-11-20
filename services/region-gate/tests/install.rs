// SPDX-License-Identifier: CC0-1.0

//! The table the request check reads can be replaced while the process runs. This is its own test
//! program because the table is a process-wide slot: another test must not see this one's table.

use region_gate::basics::{Mode, Verdict};
use region_gate::service_availability::{current, decide, install, Decision, ServiceSnapshot};
use std::sync::Arc;
use std::time::SystemTime;

const MEMORYDB: &str = "com.amazonaws.memorydb#AmazonMemoryDB";
const NEWER: &str = "# last_updated 2026-11-21T00:00:00+00:00\n\
                     # regions us-east-1 ap-southeast-7\n\
                     com.amazonaws.memorydb#AmazonMemoryDB 3 MemoryDB\n";

#[test]
fn an_installed_table_replaces_the_bundled_one_for_the_next_request() {
    let before = current();
    assert!(std::ptr::eq(&*before, ServiceSnapshot::bundled()));
    assert_eq!(
        before.service("ap-southeast-7", MEMORYDB),
        Verdict::Unavailable
    );

    install(Arc::new(ServiceSnapshot::parse(NEWER).unwrap()));

    let after = current();
    assert_eq!(after.last_updated(), "2026-11-21T00:00:00+00:00");
    assert_eq!(
        after.service("ap-southeast-7", MEMORYDB),
        Verdict::Available
    );
    assert_eq!(
        decide(
            Mode::Enforce,
            &after,
            MEMORYDB,
            "ap-southeast-7",
            SystemTime::now()
        ),
        Decision::Allow
    );
    // A request that started before the swap still holds the table it began with.
    assert_eq!(
        before.service("ap-southeast-7", MEMORYDB),
        Verdict::Unavailable
    );
}
