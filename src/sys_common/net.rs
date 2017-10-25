// Copyright 2013-2014 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cmp;
use std::ffi::CString;
use std::fmt;
use std::io::{self, Error, ErrorKind};
use libc::{c_int, c_void};
use std::mem;
use net::{SocketAddr, Shutdown, Ipv4Addr, Ipv6Addr};
use std::ptr;
use sys::net::{cvt, cvt_r, cvt_gai, Socket, init, wrlen_t};
use sys::net::netc as c;
use sys_common::{AsInner, FromInner, IntoInner};
use std::time::Duration;

#[cfg(any(target_os = "dragonfly", target_os = "freebsd",
          target_os = "ios", target_os = "macos",
          target_os = "openbsd", target_os = "netbsd",
          target_os = "solaris", target_os = "haiku", target_os = "l4re"))]
use sys::net::netc::IPV6_JOIN_GROUP as IPV6_ADD_MEMBERSHIP;
#[cfg(not(any(target_os = "dragonfly", target_os = "freebsd",
              target_os = "ios", target_os = "macos",
              target_os = "openbsd", target_os = "netbsd",
              target_os = "solaris", target_os = "haiku", target_os = "l4re")))]
use sys::net::netc::IPV6_ADD_MEMBERSHIP;
#[cfg(any(target_os = "dragonfly", target_os = "freebsd",
          target_os = "ios", target_os = "macos",
          target_os = "openbsd", target_os = "netbsd",
          target_os = "solaris", target_os = "haiku", target_os = "l4re"))]
use sys::net::netc::IPV6_LEAVE_GROUP as IPV6_DROP_MEMBERSHIP;
#[cfg(not(any(target_os = "dragonfly", target_os = "freebsd",
              target_os = "ios", target_os = "macos",
              target_os = "openbsd", target_os = "netbsd",
              target_os = "solaris", target_os = "haiku", target_os = "l4re")))]
use sys::net::netc::IPV6_DROP_MEMBERSHIP;

#[cfg(any(target_os = "linux", target_os = "android",
          target_os = "dragonfly", target_os = "freebsd",
          target_os = "openbsd", target_os = "netbsd",
          target_os = "haiku", target_os = "bitrig"))]
use libc::MSG_NOSIGNAL;
#[cfg(not(any(target_os = "linux", target_os = "android",
              target_os = "dragonfly", target_os = "freebsd",
              target_os = "openbsd", target_os = "netbsd",
              target_os = "haiku", target_os = "bitrig")))]
const MSG_NOSIGNAL: c_int = 0x0;

////////////////////////////////////////////////////////////////////////////////
// sockaddr and misc bindings
////////////////////////////////////////////////////////////////////////////////

pub fn setsockopt<T>(sock: &Socket, opt: c_int, val: c_int,
                     payload: T) -> io::Result<()> {
    unsafe {
        let payload = &payload as *const T as *const c_void;
        cvt(c::setsockopt(*sock.as_inner(), opt, val, payload,
                          mem::size_of::<T>() as c::socklen_t))?;
        Ok(())
    }
}

pub fn getsockopt<T: Copy>(sock: &Socket, opt: c_int,
                       val: c_int) -> io::Result<T> {
    unsafe {
        let mut slot: T = mem::zeroed();
        let mut len = mem::size_of::<T>() as c::socklen_t;
        cvt(c::getsockopt(*sock.as_inner(), opt, val,
                          &mut slot as *mut _ as *mut _,
                          &mut len))?;
        assert_eq!(len as usize, mem::size_of::<T>());
        Ok(slot)
    }
}

fn sockname<F>(f: F) -> io::Result<SocketAddr>
    where F: FnOnce(*mut c::sockaddr, *mut c::socklen_t) -> c_int
{
    unsafe {
        let mut storage: c::sockaddr_storage = mem::zeroed();
        let mut len = mem::size_of_val(&storage) as c::socklen_t;
        cvt(f(&mut storage as *mut _ as *mut _, &mut len))?;
        sockaddr_to_addr(&storage, len as usize)
    }
}

pub fn sockaddr_to_addr(storage: &c::sockaddr_storage,
                    len: usize) -> io::Result<SocketAddr> {
    match storage.ss_family as c_int {
        c::AF_INET => {
            assert!(len as usize >= mem::size_of::<c::sockaddr_in>());
            Ok(SocketAddr::V4(FromInner::from_inner(unsafe {
                *(storage as *const _ as *const c::sockaddr_in)
            })))
        }
        c::AF_INET6 => {
            assert!(len as usize >= mem::size_of::<c::sockaddr_in6>());
            Ok(SocketAddr::V6(FromInner::from_inner(unsafe {
                *(storage as *const _ as *const c::sockaddr_in6)
            })))
        }
        _ => {
            Err(Error::new(ErrorKind::InvalidInput, "invalid argument"))
        }
    }
}

#[cfg(target_os = "android")]
fn to_ipv6mr_interface(value: u32) -> c_int {
    value as c_int
}

#[cfg(not(target_os = "android"))]
fn to_ipv6mr_interface(value: u32) -> ::libc::c_uint {
    value as ::libc::c_uint
}

////////////////////////////////////////////////////////////////////////////////
// get_host_addresses
////////////////////////////////////////////////////////////////////////////////

pub struct LookupHost {
    original: *mut c::addrinfo,
    cur: *mut c::addrinfo,
}

impl Iterator for LookupHost {
    type Item = SocketAddr;
    fn next(&mut self) -> Option<SocketAddr> {
        loop {
            unsafe {
                let cur = match self.cur.as_ref() {
                    None => return None,
                    Some(c) => c,
                };
                self.cur = cur.ai_next;
                match sockaddr_to_addr(mem::transmute(cur.ai_addr),
                                       cur.ai_addrlen as usize)
                {
                    Ok(addr) => return Some(addr),
                    Err(_) => continue,
                }
            }
        }
    }
}

unsafe impl Sync for LookupHost {}
unsafe impl Send for LookupHost {}

impl Drop for LookupHost {
    fn drop(&mut self) {
        unsafe { c::freeaddrinfo(self.original) }
    }
}

pub fn lookup_host(host: &str) -> io::Result<LookupHost> {
    init();

    let c_host = CString::new(host)?;
    let mut hints: c::addrinfo = unsafe { mem::zeroed() };
    hints.ai_socktype = c::SOCK_STREAM;
    let mut res = ptr::null_mut();
    unsafe {
        match cvt_gai(c::getaddrinfo(c_host.as_ptr(), ptr::null(), &hints, &mut res)) {
            Ok(_) => {
                Ok(LookupHost { original: res, cur: res })
            },
            #[cfg(unix)]
            Err(e) => {
                // If we're running glibc prior to version 2.26, the lookup
                // failure could be caused by caching a stale /etc/resolv.conf.
                // We need to call libc::res_init() to clear the cache. But we
                // shouldn't call it in on any other platform, because other
                // res_init implementations aren't thread-safe. See
                // https://github.com/rust-lang/rust/issues/41570 and
                // https://github.com/rust-lang/rust/issues/43592.
                use sys::net::res_init_if_glibc_before_2_26;
                let _ = res_init_if_glibc_before_2_26();
                Err(e)
            },
            // the cfg is needed here to avoid an "unreachable pattern" warning
            #[cfg(not(unix))]
            Err(e) => Err(e),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// TCP streams
////////////////////////////////////////////////////////////////////////////////

pub struct TcpSocket {
    inner: Socket,
}

impl TcpSocket {
    pub fn connect(addr: &SocketAddr) -> io::Result<TcpSocket> {
        init();

        let mut sock = Socket::new(addr, c::SOCK_STREAM)?;
        let (addrp, len) = addr.into_inner();
        cvt_r(|| unsafe { c::connect(*sock.as_inner(), addrp, len) })?;
        sock.set_ready(true);
        Ok(TcpSocket { inner: sock })
    }

    pub fn connect_timeout(addr: &SocketAddr, timeout: Duration) -> io::Result<TcpSocket> {
        init();

        let mut sock = Socket::new(addr, c::SOCK_STREAM)?;
        sock.connect_timeout(addr, timeout)?;
        sock.set_ready(true);
        Ok(TcpSocket { inner: sock })
    }

    pub fn connect_asyn(addr: &SocketAddr) -> io::Result<TcpSocket> {
        init();

        let mut sock = Socket::new(addr, c::SOCK_STREAM)?;
        sock.connect_asyn(addr)?;
        Ok(TcpSocket { inner: sock })
    }

    pub fn get_socket_fd(&self) -> i32 {
        self.inner.get_socket_fd()
    }

    pub fn new_by_fd(fd: i32) -> io::Result<TcpSocket> {
        let sock = Socket::new_out_fd(fd);
        Ok(TcpSocket { inner: sock })
    }

    pub fn is_valid(&self) -> bool {
        self.inner.is_valid()
    }

    pub fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }

    pub fn set_ready(&mut self, ready: bool) {
        self.inner.set_ready(ready);
    }

    pub fn check_ready(&mut self) -> io::Result<bool> {
        self.inner.check_ready()
    }

    pub fn socket(&self) -> &Socket { &self.inner }

    pub fn into_socket(self) -> Socket { self.inner }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_timeout(dur, c::SO_RCVTIMEO)
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_timeout(dur, c::SO_SNDTIMEO)
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.timeout(c::SO_RCVTIMEO)
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.timeout(c::SO_SNDTIMEO)
    }

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.ensure_ready()?;
        self.inner.peek(buf)
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.ensure_ready()?;
        self.inner.read(buf)
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner.ensure_ready()?;
        let len = cmp::min(buf.len(), <wrlen_t>::max_value() as usize) as wrlen_t;
        let ret = cvt(unsafe {
            c::send(*self.inner.as_inner(),
                    buf.as_ptr() as *const c_void,
                    len,
                    MSG_NOSIGNAL)
        })?;
        Ok(ret as usize)
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        sockname(|buf, len| unsafe {
            c::getpeername(*self.inner.as_inner(), buf, len)
        })
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        sockname(|buf, len| unsafe {
            c::getsockname(*self.inner.as_inner(), buf, len)
        })
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }

    pub fn duplicate(&self) -> io::Result<TcpSocket> {
        self.inner.duplicate().map(|s| TcpSocket { inner: s })
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        self.inner.nodelay()
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        setsockopt(&self.inner, c::IPPROTO_IP, c::IP_TTL, ttl as c_int)
    }

    pub fn ttl(&self) -> io::Result<u32> {
        let raw: c_int = getsockopt(&self.inner, c::IPPROTO_IP, c::IP_TTL)?;
        Ok(raw as u32)
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }

    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    pub fn is_nonblocking(&self) -> bool {
        self.inner.is_nonblocking()
    }

    pub fn set_liner(&self, enable: bool, time: u16) -> io::Result<()> {
        self.inner.set_liner(enable, time)
    }

    pub fn liner(&self) -> io::Result<(bool, u16)> {
        self.inner.liner()
    }

    pub fn set_recv_size(&self, size: u32) -> io::Result<()> {
        self.inner.set_recv_size(size)
    }

    pub fn recv_size(&self) -> io::Result<u32> {
        self.inner.recv_size()
    }

    pub fn set_send_size(&self, size: u32) -> io::Result<()> {
        self.inner.set_send_size(size)
    }

    pub fn send_size(&self) -> io::Result<u32> {
        self.inner.send_size()
    }

    pub fn set_reuse_addr(&self) -> io::Result<()> {
        self.inner.set_reuse_addr()
    }

    pub fn bind(addr: &SocketAddr) -> io::Result<TcpSocket> {
        init();

        let sock = Socket::new(addr, c::SOCK_STREAM)?;

        // On platforms with Berkeley-derived sockets, this allows
        // to quickly rebind a socket, without needing to wait for
        // the OS to clean up the previous one.
        if !cfg!(windows) {
            setsockopt(&sock, c::SOL_SOCKET, c::SO_REUSEADDR,
                       1 as c_int)?;
        }

        // Bind our new socket
        let (addrp, len) = addr.into_inner();
        cvt(unsafe { c::bind(*sock.as_inner(), addrp, len as _) })?;

        // Start listening
        cvt(unsafe { c::listen(*sock.as_inner(), 128) })?;
        Ok(TcpSocket { inner: sock })
    }

    pub fn accept(&self) -> io::Result<(TcpSocket, SocketAddr)> {
        let mut storage: c::sockaddr_storage = unsafe { mem::zeroed() };
        let mut len = mem::size_of_val(&storage) as c::socklen_t;
        let sock = self.inner.accept(&mut storage as *mut _ as *mut _,
                                     &mut len)?;
        let addr = sockaddr_to_addr(&storage, len as usize)?;
        Ok((TcpSocket { inner: sock, }, addr))
    }

    pub fn unlink(self) -> io::Result<()> {
        self.inner.unlink();
        Ok(())
    }
}

impl Clone for TcpSocket {
    fn clone(&self) -> TcpSocket {
        TcpSocket { inner: self.inner.clone() }
    }
}

impl FromInner<Socket> for TcpSocket {
    fn from_inner(socket: Socket) -> TcpSocket {
        TcpSocket { inner: socket }
    }
}

impl fmt::Debug for TcpSocket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut res = f.debug_struct("TcpSocket");

        if let Ok(addr) = self.socket_addr() {
            res.field("addr", &addr);
        }

        if let Ok(peer) = self.peer_addr() {
            res.field("peer", &peer);
        }

        let name = if cfg!(windows) {"socket"} else {"fd"};
        res.field(name, &self.inner.as_inner());

        res.field("ready", &self.inner.is_ready())
            .finish()
    }
}

////////////////////////////////////////////////////////////////////////////////
// UDP
////////////////////////////////////////////////////////////////////////////////

pub struct UdpSocket {
    inner: Socket,
}

impl UdpSocket {
    pub fn bind(addr: &SocketAddr) -> io::Result<UdpSocket> {
        init();

        let sock = Socket::new(addr, c::SOCK_DGRAM)?;
        let (addrp, len) = addr.into_inner();
        cvt(unsafe { c::bind(*sock.as_inner(), addrp, len as _) })?;
        Ok(UdpSocket { inner: sock })
    }

    pub fn socket(&self) -> &Socket { &self.inner }

    pub fn into_socket(self) -> Socket { self.inner }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        sockname(|buf, len| unsafe {
            c::getsockname(*self.inner.as_inner(), buf, len)
        })
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf)
    }

    pub fn peek_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.peek_from(buf)
    }

    pub fn send_to(&self, buf: &[u8], dst: &SocketAddr) -> io::Result<usize> {
        let len = cmp::min(buf.len(), <wrlen_t>::max_value() as usize) as wrlen_t;
        let (dstp, dstlen) = dst.into_inner();
        let ret = cvt(unsafe {
            c::sendto(*self.inner.as_inner(),
                      buf.as_ptr() as *const c_void, len,
                      MSG_NOSIGNAL, dstp, dstlen)
        })?;
        Ok(ret as usize)
    }

    pub fn duplicate(&self) -> io::Result<UdpSocket> {
        self.inner.duplicate().map(|s| UdpSocket { inner: s })
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_timeout(dur, c::SO_RCVTIMEO)
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_timeout(dur, c::SO_SNDTIMEO)
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.timeout(c::SO_RCVTIMEO)
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.timeout(c::SO_SNDTIMEO)
    }

    pub fn set_broadcast(&self, broadcast: bool) -> io::Result<()> {
        setsockopt(&self.inner, c::SOL_SOCKET, c::SO_BROADCAST, broadcast as c_int)
    }

    pub fn broadcast(&self) -> io::Result<bool> {
        let raw: c_int = getsockopt(&self.inner, c::SOL_SOCKET, c::SO_BROADCAST)?;
        Ok(raw != 0)
    }

    pub fn set_multicast_loop_v4(&self, multicast_loop_v4: bool) -> io::Result<()> {
        setsockopt(&self.inner, c::IPPROTO_IP, c::IP_MULTICAST_LOOP, multicast_loop_v4 as c_int)
    }

    pub fn multicast_loop_v4(&self) -> io::Result<bool> {
        let raw: c_int = getsockopt(&self.inner, c::IPPROTO_IP, c::IP_MULTICAST_LOOP)?;
        Ok(raw != 0)
    }

    pub fn set_multicast_ttl_v4(&self, multicast_ttl_v4: u32) -> io::Result<()> {
        setsockopt(&self.inner, c::IPPROTO_IP, c::IP_MULTICAST_TTL, multicast_ttl_v4 as c_int)
    }

    pub fn multicast_ttl_v4(&self) -> io::Result<u32> {
        let raw: c_int = getsockopt(&self.inner, c::IPPROTO_IP, c::IP_MULTICAST_TTL)?;
        Ok(raw as u32)
    }

    pub fn set_multicast_loop_v6(&self, multicast_loop_v6: bool) -> io::Result<()> {
        setsockopt(&self.inner, c::IPPROTO_IPV6, c::IPV6_MULTICAST_LOOP, multicast_loop_v6 as c_int)
    }

    pub fn multicast_loop_v6(&self) -> io::Result<bool> {
        let raw: c_int = getsockopt(&self.inner, c::IPPROTO_IPV6, c::IPV6_MULTICAST_LOOP)?;
        Ok(raw != 0)
    }

    pub fn join_multicast_v4(&self, multiaddr: &Ipv4Addr, interface: &Ipv4Addr)
                         -> io::Result<()> {
        let mreq = c::ip_mreq {
            imr_multiaddr: *multiaddr.as_inner(),
            imr_interface: *interface.as_inner(),
        };
        setsockopt(&self.inner, c::IPPROTO_IP, c::IP_ADD_MEMBERSHIP, mreq)
    }

    pub fn join_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32)
                         -> io::Result<()> {
        let mreq = c::ipv6_mreq {
            ipv6mr_multiaddr: *multiaddr.as_inner(),
            ipv6mr_interface: to_ipv6mr_interface(interface),
        };
        setsockopt(&self.inner, c::IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, mreq)
    }

    pub fn leave_multicast_v4(&self, multiaddr: &Ipv4Addr, interface: &Ipv4Addr)
                          -> io::Result<()> {
        let mreq = c::ip_mreq {
            imr_multiaddr: *multiaddr.as_inner(),
            imr_interface: *interface.as_inner(),
        };
        setsockopt(&self.inner, c::IPPROTO_IP, c::IP_DROP_MEMBERSHIP, mreq)
    }

    pub fn leave_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32)
                          -> io::Result<()> {
        let mreq = c::ipv6_mreq {
            ipv6mr_multiaddr: *multiaddr.as_inner(),
            ipv6mr_interface: to_ipv6mr_interface(interface),
        };
        setsockopt(&self.inner, c::IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, mreq)
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        setsockopt(&self.inner, c::IPPROTO_IP, c::IP_TTL, ttl as c_int)
    }

    pub fn ttl(&self) -> io::Result<u32> {
        let raw: c_int = getsockopt(&self.inner, c::IPPROTO_IP, c::IP_TTL)?;
        Ok(raw as u32)
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }

    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.peek(buf)
    }

    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let len = cmp::min(buf.len(), <wrlen_t>::max_value() as usize) as wrlen_t;
        let ret = cvt(unsafe {
            c::send(*self.inner.as_inner(),
                    buf.as_ptr() as *const c_void,
                    len,
                    MSG_NOSIGNAL)
        })?;
        Ok(ret as usize)
    }

    pub fn connect(&self, addr: &SocketAddr) -> io::Result<()> {
        let (addrp, len) = addr.into_inner();
        cvt_r(|| unsafe { c::connect(*self.inner.as_inner(), addrp, len) }).map(|_| ())
    }
}

impl FromInner<Socket> for UdpSocket {
    fn from_inner(socket: Socket) -> UdpSocket {
        UdpSocket { inner: socket }
    }
}

impl fmt::Debug for UdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut res = f.debug_struct("UdpSocket");

        if let Ok(addr) = self.socket_addr() {
            res.field("addr", &addr);
        }

        let name = if cfg!(windows) {"socket"} else {"fd"};
        res.field(name, &self.inner.as_inner())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn no_lookup_host_duplicates() {
        let mut addrs = HashMap::new();
        let lh = match lookup_host("localhost") {
            Ok(lh) => lh,
            Err(e) => panic!("couldn't resolve `localhost': {}", e)
        };
        let _na = lh.map(|sa| *addrs.entry(sa).or_insert(0) += 1).count();
        assert!(addrs.values().filter(|&&v| v > 1).count() == 0);
    }
}