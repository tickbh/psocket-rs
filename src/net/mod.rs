

use std::fmt;
use std::io::{self, Error, ErrorKind};
use sys_common::net as net_imp;

pub use self::tcp::{TcpSocket, Incoming};
pub use self::udp::UdpSocket;

pub use self::ip::{IpAddr, Ipv4Addr, Ipv6Addr, Ipv6MulticastScope};
pub use self::addr::{SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
// pub use self::udp::UdpSocket;

mod ip;
mod addr;
mod parser;
mod tcp;
mod udp;

/// Possible values which can be passed to the [`shutdown`] method of
/// [`TcpSocket`].
///
/// [`shutdown`]: struct.TcpSocket.html#method.shutdown
/// [`TcpSocket`]: struct.TcpSocket.html
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Shutdown {
    /// The reading portion of the [`TcpSocket`] should be shut down.
    ///
    /// All currently blocked and future [reads] will return [`Ok(0)`].
    ///
    /// [`TcpSocket`]: ../../pscoket/net/struct.TcpSocket.html
    /// [reads]: ../../std/io/trait.Read.html
    /// [`Ok(0)`]: ../../std/result/enum.Result.html#variant.Ok
    Read,
    /// The writing portion of the [`TcpSocket`] should be shut down.
    ///
    /// All currently blocked and future [writes] will return an error.
    ///
    /// [`TcpSocket`]: ../../pscoket/net/struct.TcpSocket.html
    /// [writes]: ../../std/io/trait.Write.html
    Write,
    /// Both the reading and the writing portions of the [`TcpSocket`] should be shut down.
    ///
    /// See [`Shutdown::Read`] and [`Shutdown::Write`] for more information.
    ///
    /// [`TcpSocket`]: ../../pscoket/net/struct.TcpSocket.html
    /// [`Shutdown::Read`]: #variant.Read
    /// [`Shutdown::Write`]: #variant.Write
    Both,
}

#[doc(hidden)]
trait NetInt {
    fn from_be(i: Self) -> Self;
    fn to_be(&self) -> Self;
}
macro_rules! doit {
    ($($t:ident)*) => ($(impl NetInt for $t {
        fn from_be(i: Self) -> Self { <$t>::from_be(i) }
        fn to_be(&self) -> Self { <$t>::to_be(*self) }
    })*)
}
doit! { i8 i16 i32 i64 isize u8 u16 u32 u64 usize }

fn hton<I: NetInt>(i: I) -> I { i.to_be() }
fn ntoh<I: NetInt>(i: I) -> I { I::from_be(i) }

fn each_addr<A: ToSocketAddrs, F, T>(addr: A, mut f: F) -> io::Result<T>
    where F: FnMut(&SocketAddr) -> io::Result<T>
{
    let mut last_err = None;
    for addr in addr.to_socket_addrs()? {
        match f(&addr) {
            Ok(l) => return Ok(l),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        Error::new(ErrorKind::InvalidInput,
                   "could not resolve to any addresses")
    }))
}

/// An iterator over `SocketAddr` values returned from a host lookup operation.
pub struct LookupHost(net_imp::LookupHost);

impl Iterator for LookupHost {
    type Item = SocketAddr;
    fn next(&mut self) -> Option<SocketAddr> { self.0.next() }
}

impl fmt::Debug for LookupHost {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.pad("LookupHost { .. }")
    }
}

/// Resolve the host specified by `host` as a number of `SocketAddr` instances.
///
/// This method may perform a DNS query to resolve `host` and may also inspect
/// system configuration to resolve the specified hostname.
///
/// The returned iterator will skip over any unknown addresses returned by the
/// operating system.
///
/// # Examples
///
/// ```no_run
/// use psocket::net;
///
/// # fn foo() -> std::io::Result<()> {
/// for host in net::lookup_host("rust-lang.org")? {
///     println!("found address: {}", host);
/// }
/// # Ok(())
/// # }
/// ```
pub fn lookup_host(host: &str) -> io::Result<LookupHost> {
    net_imp::lookup_host(host).map(LookupHost)
}

#[cfg(test)]
mod test;