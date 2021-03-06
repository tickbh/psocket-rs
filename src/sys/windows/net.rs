// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::os::windows::io::FromRawSocket;
use std::os::windows::io::IntoRawSocket;
use std::net::{TcpStream, TcpListener};
use std::cmp;
use std::io::{self, Read};
use libc::{c_int, c_void, c_ulong, c_long, c_ushort};
use std::mem;
use net::{SocketAddr, Shutdown};
use std::ptr;
use std::sync::{Once, ONCE_INIT};
use sys::c;
use sys;
use sys_common::{AsInner, FromInner, IntoInner};
use sys_common::net;
use std::time::Duration;
use std::cell::Cell;

pub type wrlen_t = i32;

pub mod netc {
    pub use sys::c::*;
    pub use sys::c::SOCKADDR as sockaddr;
    pub use sys::c::SOCKADDR_STORAGE_LH as sockaddr_storage;
    pub use sys::c::ADDRINFOA as addrinfo;
    pub use sys::c::ADDRESS_FAMILY as sa_family_t;
}

pub struct Socket {
    socket: c::SOCKET,
    ready: Cell<bool>,
    closed: Cell<bool>,
    nonblocking: Cell<bool>,
}

/// Checks whether the Windows socket interface has been started already, and
/// if not, starts it.
pub fn init() {
    static START: Once = ONCE_INIT;

    START.call_once(|| unsafe {
        let mut data: c::WSADATA = mem::zeroed();
        let ret = c::WSAStartup(0x202, // version 2.2
                                &mut data);
        assert_eq!(ret, 0);

        // let _ = ::std::process::exit(|| { c::WSACleanup(); });
    });
}

/// Returns the last error from the Windows socket interface.
fn last_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { c::WSAGetLastError() })
}

#[doc(hidden)]
pub trait IsMinusOne {
    fn is_minus_one(&self) -> bool;
}

macro_rules! impl_is_minus_one {
    ($($t:ident)*) => ($(impl IsMinusOne for $t {
        fn is_minus_one(&self) -> bool {
            *self == -1
        }
    })*)
}

impl_is_minus_one! { i8 i16 i32 i64 isize }

/// Checks if the signed integer is the Windows constant `SOCKET_ERROR` (-1)
/// and if so, returns the last error from the Windows socket interface. This
/// function must be called before another call to the socket API is made.
pub fn cvt<T: IsMinusOne>(t: T) -> io::Result<T> {
    if t.is_minus_one() {
        Err(last_error())
    } else {
        Ok(t)
    }
}

/// A variant of `cvt` for `getaddrinfo` which return 0 for a success.
pub fn cvt_gai(err: c_int) -> io::Result<()> {
    if err == 0 {
        Ok(())
    } else {
        Err(last_error())
    }
}

/// Just to provide the same interface as sys/unix/net.rs
pub fn cvt_r<T, F>(mut f: F) -> io::Result<T>
    where T: IsMinusOne,
          F: FnMut() -> T
{
    cvt(f())
}

impl Socket {
    pub fn new(addr: &SocketAddr, ty: c_int) -> io::Result<Socket> {
        let fam = match *addr {
            SocketAddr::V4(..) => c::AF_INET,
            SocketAddr::V6(..) => c::AF_INET6,
        };
        let socket = unsafe {
            match c::WSASocketW(fam, ty, 0, ptr::null_mut(), 0,
                                c::WSA_FLAG_OVERLAPPED) {
                c::INVALID_SOCKET => Err(last_error()),
                n => Ok(Socket {
                    socket: n,
                    ready: Cell::new(false),
                    closed: Cell::new(false),
                    nonblocking: Cell::new(false),
                }),
            }
        }?;
        Ok(socket)
    }
    
    pub fn new_v4() -> io::Result<Socket> {
        init();
        let socket = unsafe {
            match c::WSASocketW(c::AF_INET, c::SOCK_STREAM, 0, ptr::null_mut(), 0,
                                c::WSA_FLAG_OVERLAPPED) {
                c::INVALID_SOCKET => Err(last_error()),
                n => Ok(Socket {
                    socket: n,
                    ready: Cell::new(false),
                    closed: Cell::new(false),
                    nonblocking: Cell::new(false),
                }),
            }
        }?;
        Ok(socket)
    }

    pub fn new_v6() -> io::Result<Socket> {
        init();
        let socket = unsafe {
            match c::WSASocketW(c::AF_INET6, c::SOCK_STREAM, 0, ptr::null_mut(), 0,
                                c::WSA_FLAG_OVERLAPPED) {
                c::INVALID_SOCKET => Err(last_error()),
                n => Ok(Socket {
                    socket: n,
                    ready: Cell::new(false),
                    closed: Cell::new(false),
                    nonblocking: Cell::new(false),
                }),
            }
        }?;
        Ok(socket)
    }

    pub fn is_valid(&self) -> bool {
        self.socket != c::INVALID_SOCKET    
    }

    pub fn is_ready(&self) -> bool {
        self.ready.get()
    }

    pub fn set_ready(&self, ready: bool) {
        self.ready.set(ready);
    }

    pub fn ensure_ready(&self) -> io::Result<()> {
        if !self.ready.get() {
            return Err(io::Error::new(io::ErrorKind::NotConnected,
                                      "current socket is not ready"));
        }
        Ok(())
    }

    pub fn check_ready(&self) -> io::Result<bool> {
        if self.ready.get() {
            return Ok(self.ready.get());
        }
        let timeout = c::timeval {
            tv_sec: 0 as c_long,
            tv_usec: 0 as c_long,
        };
        let fds = unsafe {
            let mut fds = mem::zeroed::<c::fd_set>();
            fds.fd_count = 1;
            fds.fd_array[0] = self.socket;
            fds
        };
        let mut writefds = fds;
        let mut errorfds = fds;

        let n = unsafe {
            cvt(c::select(1, ptr::null_mut(), &mut writefds, &mut errorfds, &timeout))?
        };

        if n > 0 {
            if writefds.fd_count != 1 {
                if let Some(e) = self.take_error()? {
                    return Err(e);
                }
            }
            self.ready.set(true);
        }

        Ok(self.ready.get())
    }

    pub fn connect_timeout(&self, addr: &SocketAddr, timeout: Duration) -> io::Result<()> {
        self.set_nonblocking(true)?;
        let r = unsafe {
            let (addrp, len) = addr.into_inner();
            cvt(c::connect(self.socket, addrp, len))
        };
        self.set_nonblocking(false)?;

        match r {
            Ok(_) => return Ok(()),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        if timeout.as_secs() == 0 && timeout.subsec_nanos() == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                      "cannot set a 0 duration timeout"));
        }

        let mut timeout = c::timeval {
            tv_sec: timeout.as_secs() as c_long,
            tv_usec: (timeout.subsec_nanos() / 1000) as c_long,
        };
        if timeout.tv_sec == 0 && timeout.tv_usec == 0 {
            timeout.tv_usec = 1;
        }

        let fds = unsafe {
            let mut fds = mem::zeroed::<c::fd_set>();
            fds.fd_count = 1;
            fds.fd_array[0] = self.socket;
            fds
        };

        let mut writefds = fds;
        let mut errorfds = fds;

        let n = unsafe {
            cvt(c::select(1, ptr::null_mut(), &mut writefds, &mut errorfds, &timeout))?
        };

        match n {
            0 => Err(io::Error::new(io::ErrorKind::TimedOut, "connection timed out")),
            _ => {
                if writefds.fd_count != 1 {
                    if let Some(e) = self.take_error()? {
                        return Err(e);
                    }
                }
                Ok(())
            }
        }
    }


    pub fn connect_asyn(&self, addr: &SocketAddr) -> io::Result<()> {
        self.set_nonblocking(true)?;
        let r = unsafe {
            let (addrp, len) = addr.into_inner();
            cvt(c::connect(self.socket, addrp, len))
        };
        self.set_nonblocking(false)?;

        match r {
            Ok(_) => return Ok(()),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Ok(())
            }
            Err(e) => return Err(e),
        }
    }

    pub fn new_out_fd(fd: c::SOCKET) -> Socket {
        Socket {
            socket: fd,
            ready: Cell::new(true),
            closed: Cell::new(false),
            nonblocking: Cell::new(false),
        }
    }

    pub fn accept(&self, storage: *mut c::SOCKADDR,
                  len: *mut c_int) -> io::Result<Socket> {
        let socket = unsafe {
            match c::accept(self.socket, storage, len) {
                c::INVALID_SOCKET => Err(last_error()),
                n => Ok(Socket {
                    socket: n,
                    ready: Cell::new(true),
                    closed: Cell::new(false),
                    nonblocking: Cell::new(false),
                }),
            }
        }?;
        Ok(socket)
    }

    pub fn duplicate(&self) -> io::Result<Socket> {
        let socket = unsafe {
            let mut info: c::WSAPROTOCOL_INFO = mem::zeroed();
            cvt(c::WSADuplicateSocketW(self.socket,
                                            c::GetCurrentProcessId(),
                                            &mut info))?;
            match c::WSASocketW(info.iAddressFamily,
                                info.iSocketType,
                                info.iProtocol,
                                &mut info, 0,
                                c::WSA_FLAG_OVERLAPPED) {
                c::INVALID_SOCKET => Err(last_error()),
                n => Ok(Socket {
                    socket: n,
                    ready: Cell::new(true),
                    closed: Cell::new(false),
                    nonblocking: Cell::new(false),
                }),
            }
        }?;
        Ok(socket)
    }

    fn recv_with_flags(&self, buf: &mut [u8], flags: c_int) -> io::Result<usize> {
        // On unix when a socket is shut down all further reads return 0, so we
        // do the same on windows to map a shut down socket to returning EOF.
        let len = cmp::min(buf.len(), i32::max_value() as usize) as i32;
        unsafe {
            match c::recv(self.socket, buf.as_mut_ptr() as *mut c_void, len, flags) {
                -1 if c::WSAGetLastError() == c::WSAESHUTDOWN => Ok(0),
                -1 => Err(last_error()),
                n => Ok(n as usize)
            }
        }
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_with_flags(buf, 0)
    }

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_with_flags(buf, c::MSG_PEEK)
    }

    fn recv_from_with_flags(&self, buf: &mut [u8], flags: c_int)
                            -> io::Result<(usize, SocketAddr)> {
        let mut storage: c::SOCKADDR_STORAGE_LH = unsafe { mem::zeroed() };
        let mut addrlen = mem::size_of_val(&storage) as c::socklen_t;
        let len = cmp::min(buf.len(), <wrlen_t>::max_value() as usize) as wrlen_t;

        // On unix when a socket is shut down all further reads return 0, so we
        // do the same on windows to map a shut down socket to returning EOF.
        unsafe {
            match c::recvfrom(self.socket,
                              buf.as_mut_ptr() as *mut c_void,
                              len,
                              flags,
                              &mut storage as *mut _ as *mut _,
                              &mut addrlen) {
                -1 if c::WSAGetLastError() == c::WSAESHUTDOWN => {
                    Ok((0, net::sockaddr_to_addr(&storage, addrlen as usize)?))
                },
                -1 => Err(last_error()),
                n => Ok((n as usize, net::sockaddr_to_addr(&storage, addrlen as usize)?)),
            }
        }
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from_with_flags(buf, 0)
    }

    pub fn peek_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from_with_flags(buf, c::MSG_PEEK)
    }

    pub fn set_timeout(&self, dur: Option<Duration>,
                       kind: c_int) -> io::Result<()> {
        let timeout = match dur {
            Some(dur) => {
                let timeout = sys::dur2timeout(dur);
                if timeout == 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                              "cannot set a 0 duration timeout"));
                }
                timeout
            }
            None => 0
        };
        net::setsockopt(self, c::SOL_SOCKET, kind, timeout)
    }

    pub fn timeout(&self, kind: c_int) -> io::Result<Option<Duration>> {
        let raw: c::DWORD = net::getsockopt(self, c::SOL_SOCKET, kind)?;
        if raw == 0 {
            Ok(None)
        } else {
            let secs = raw / 1000;
            let nsec = (raw % 1000) * 1000000;
            Ok(Some(Duration::new(secs as u64, nsec as u32)))
        }
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let how = match how {
            Shutdown::Write => c::SD_SEND,
            Shutdown::Read => c::SD_RECEIVE,
            Shutdown::Both => c::SD_BOTH,
        };
        cvt(unsafe { c::shutdown(self.socket, how) })?;
        Ok(())
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let mut nonblocking = nonblocking as c_ulong;
        let r = unsafe { c::ioctlsocket(self.socket, c::FIONBIO as c_int, &mut nonblocking) };
        if r == 0 {
            self.nonblocking.set(nonblocking == 1);
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn is_nonblocking(&self) -> bool {
        self.nonblocking.get()
    }

    pub fn set_liner(&self, enable: bool, time: u16) -> io::Result<()> {
        let enable = if enable { 1 } else { 0 };
        let linger = c::linger {
            l_onoff: enable as c_ushort,
            l_linger: time as c_ushort,
        };

        net::setsockopt(self, c::SOL_SOCKET, c::SO_LINGER, linger)
    }

    pub fn liner(&self) -> io::Result<(bool, u16)> {
        let liner: c::linger = net::getsockopt(self, c::SOL_SOCKET, c::SO_LINGER)?;

        Ok((liner.l_onoff == 1, liner.l_linger as u16))
    }

    pub fn set_recv_size(&self, size: u32) -> io::Result<()> {
        net::setsockopt(self, c::SOL_SOCKET, c::SO_RCVBUF, size)
    }

    pub fn recv_size(&self) -> io::Result<u32> {
        net::getsockopt(self, c::SOL_SOCKET, c::SO_RCVBUF)
    }

    pub fn set_send_size(&self, size: u32) -> io::Result<()> {
        net::setsockopt(self, c::SOL_SOCKET, c::SO_SNDBUF, size)
    }

    pub fn send_size(&self) -> io::Result<u32> {
        net::getsockopt(self, c::SOL_SOCKET, c::SO_SNDBUF)
    }

    pub fn set_reuse_addr(&self) -> io::Result<()> {
        net::setsockopt(self, c::SOL_SOCKET, c::SO_REUSEADDR, 1)
    }

    pub fn set_reuse_port(&self) -> io::Result<()> {
        Ok(())
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        net::setsockopt(self, c::IPPROTO_TCP, c::TCP_NODELAY, nodelay as c::BYTE)
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        let raw: c::BYTE = net::getsockopt(self, c::IPPROTO_TCP, c::TCP_NODELAY)?;
        Ok(raw != 0)
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        let raw: c_int = net::getsockopt(self, c::SOL_SOCKET, c::SO_ERROR)?;
        if raw == 0 {
            Ok(None)
        } else {
            Ok(Some(io::Error::from_raw_os_error(raw as i32)))
        }
    }

    pub fn close(&self) {
        let _ = unsafe { c::closesocket(self.socket) };
        self.closed.set(true);
    }

    pub fn is_close(&self) -> bool {
        self.closed.get()
    }

    pub fn unlink(mut self) -> c::SOCKET {
        let sock = self.socket;
        self.socket = c::INVALID_SOCKET;
        sock
    }

    pub fn convert_to_stream(self) -> TcpStream {
        let socket = self.unlink();
        unsafe {
            TcpStream::from_raw_socket(socket)
        }
    }

    pub fn convert_to_listener(self) -> TcpListener {
        let socket = self.unlink();
        unsafe { 
            TcpListener::from_raw_socket(socket)
        }
    }

    pub fn from_stream(tcp: TcpStream) -> Socket {
        let socket = tcp.into_raw_socket();
        Self::new_out_fd(socket)
    }

    pub fn from_listener(listen: TcpListener) -> Socket {
        let socket = listen.into_raw_socket();
        Self::new_out_fd(socket)
    }
}

impl<'a> Read for &'a Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read(buf)
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        if self.socket == c::INVALID_SOCKET || self.closed.get() {
            return;
        }
        let _ = unsafe { c::closesocket(self.socket) };
    }
}

impl Clone for Socket {
    fn clone(&self) -> Socket {
        Socket {
            socket: self.socket,
            ready: self.ready.clone(),
            closed: self.closed.clone(),
            nonblocking: self.nonblocking.clone(),
        }
    }
}

impl AsInner<c::SOCKET> for Socket {
    fn as_inner(&self) -> &c::SOCKET { &self.socket }
}

impl FromInner<c::SOCKET> for Socket {
    fn from_inner(sock: c::SOCKET) -> Socket { Socket {
        socket: sock,
        ready: Cell::new(true),
        closed: Cell::new(false),
        nonblocking: Cell::new(false),
    }}
}

impl IntoInner<c::SOCKET> for Socket {
    fn into_inner(self) -> c::SOCKET {
        self.unlink()
    }
}
