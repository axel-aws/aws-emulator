// SPDX-License-Identifier: CC0-1.0

#![forbid(unsafe_code)]
//! Whether AWS offers an API service in a Region, answered for the request router.
//!
//! This crate sits below the router (`vendor/smithy-server-runtime`) and below `service-common`,
//! which depends on the router, so both can use it without a cycle. It holds the pieces the
//! router's check needs and nothing else:
//!
//! * [`basics`], the mode a check runs in (`EMULATOR_REGION_AVAILABILITY`), what the data can
//!   say about one item, and how old data is. `service_common::region_availability` re-exports
//!   them, so the CloudFormation check and this one read one setting and use one set of words;
//! * [`service_availability`], the bundled table of the Regions each API service is offered in,
//!   and the decision for one request;
//! * [`gate`], the one function the router calls.

pub mod basics;
pub mod gate;
pub mod service_availability;
