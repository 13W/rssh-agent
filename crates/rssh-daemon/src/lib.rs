#![allow(clippy::collapsible_if)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::needless_return)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::len_zero)]
#![allow(clippy::useless_conversion)]

pub mod agent;
pub mod daemon;
pub mod extensions;
pub mod key_utils;
pub mod prompt;
pub mod signing;
pub mod socket;

// SSH agent daemon implementation
pub mod optimized_socket;
