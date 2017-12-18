socket for rust
=====================

[![Build Status](https://travis-ci.org/tickbh/psocket-rs.svg?branch=master)](https://travis-ci.org/tickbh/psocket-rs) [![Crates.io](https://img.shields.io/crates/v/psocket.svg)](https://crates.io/crates/psocket)

A Rust library for socket. 

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
psocket = "0.1"
```

and this to your crate root:

```rust
extern crate psocket;
```

How to use
```rust
use psocket::TcpSocket;
use std::io::prelude::*;
use std::time::{Duration, Instant};
use std::io::ErrorKind;

let listener = TcpSocket::bind("127.0.0.1:1234").unwrap();
let addr = listener.local_addr().unwrap();

let mut stream = TcpSocket::connect(&("localhost", addr.port())).expect("connect error");
stream.set_read_timeout(Some(Duration::from_millis(1000))).expect("set read timeout error");

let mut other_end = listener.accept().unwrap().0;
other_end.write_all(b"hello world").expect("write error");

let mut buf = [0; 11];
stream.read(&mut buf).expect("read error");
assert_eq!(b"hello world", &buf[..]);

let start = Instant::now();
let kind = stream.read(&mut buf).err().expect("expected error").kind();
assert!(kind == ErrorKind::WouldBlock || kind == ErrorKind::TimedOut);
assert!(start.elapsed() > Duration::from_millis(400));
drop(listener);

```

## Diff with Rust TcpStream
provide more fuction about socket
```rust
// The func connect remote host asyn
pub fn connect_asyn(addr: &SocketAddr) -> io::Result<TcpSocket>;
// Get the socket fd
pub fn as_raw_socket(&self) -> SOCKET;
// Moves this TCP stream into or out of liner mode.
pub fn set_liner(&self, enable: bool, time: u16) -> io::Result<()>;
// The Method is set stream recv size kernel cache size.
pub fn set_recv_size(&self, size: u32) -> io::Result<()>;
// The Method is set stream send size kernel cache size.
pub fn set_send_size(&self, size: u32) -> io::Result<()>;
// The Method is set tcp stream SO_REUSEADDR.
pub fn set_reuse_addr(&self) -> io::Result<()>;
/// Provide func dtor the object but will not close socket fd. 
pub fn unlink(self) -> io::Result<()>;
```

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
