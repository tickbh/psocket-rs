

extern crate libc;
// mod windows;
pub mod net;
mod sys;
mod sys_common;

pub use sys::{SOCKET, INVALID_SOCKET};
pub use net::*;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {

    }
}

