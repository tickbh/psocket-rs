// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ffi::CStr;
use std::io;
use libc::{self, c_int, c_void, size_t, sockaddr, socklen_t, EAI_SYSTEM, MSG_PEEK, ssize_t};
use std::mem;
use net::{SocketAddr, Shutdown};
use std::str;
use sys_common::{AsInner, FromInner, IntoInner};
use sys_common::net::{getsockopt, setsockopt, sockaddr_to_addr};
use std::time::{Duration, Instant};
use std::cmp;
use std::cell::Cell;

pub use sys::{cvt, cvt_r};
pub extern crate libc as netc;

pub type wrlen_t = size_t;

pub const INVALID_SOCKET: c_int = -1;
pub type SOCKET = c_int;

fn max_len() -> usize {
    if cfg!(target_os = "macos") {
        <c_int>::max_value() as usize - 1
    } else {
        <ssize_t>::max_value() as usize
    }
}


#[cfg(target_os = "linux")]
use libc::accept4;

// See below for the usage of SOCK_CLOEXEC, but this constant is only defined on
// Linux currently (e.g. support doesn't exist on other platforms). In order to
// get name resolution to work and things to compile we just define a dummy
// SOCK_CLOEXEC here for other platforms. Note that the dummy constant isn't
// actually ever used (the blocks below are wrapped in `if cfg!` as well.
#[cfg(target_os = "linux")]
use libc::SOCK_CLOEXEC;
#[cfg(not(target_os = "linux"))]
const SOCK_CLOEXEC: c_int = 0;

// Another conditional contant for name resolution: Macos et iOS use
// SO_NOSIGPIPE as a setsockopt flag to disable SIGPIPE emission on socket.
// Other platforms do otherwise.
#[cfg(any(target_os = "freebsd", target_os = "ios", target_os = "macos", target_os = "netbsd", target_os = "openbsd"))]
use libc::SO_NOSIGPIPE;

pub struct Socket {
    socket: c_int,
    ready: Cell<bool>,
    nonblocking: Cell<bool>,
    closed: Cell<bool>,
}

pub fn init() {}

pub fn cvt_gai(err: c_int) -> io::Result<()> {
    if err == 0 {
        return Ok(())
    }
    if err == EAI_SYSTEM {
        return Err(io::Error::last_os_error())
    }

    let detail = unsafe {
        str::from_utf8(CStr::from_ptr(libc::gai_strerror(err)).to_bytes()).unwrap()
            .to_owned()
    };
    Err(io::Error::new(io::ErrorKind::Other,
                       &format!("failed to lookup address information: {}",
                                detail)[..]))
}

impl Socket {
    pub fn new(addr: &SocketAddr, ty: c_int) -> io::Result<Socket> {
        let fam = match *addr {
            SocketAddr::V4(..) => libc::AF_INET,
            SocketAddr::V6(..) => libc::AF_INET6,
        };
        Socket::new_raw(fam, ty)
    }

    pub fn new_by_fd(fd: c_int) -> Socket {
        Socket {
            socket: fd,
            ready: Cell::new(false),
            nonblocking: Cell::new(false),
            closed: Cell::new(false),
        }
    }

    pub fn new_ready_fd(fd: c_int) -> Socket {
        Socket {
            socket: fd,
            ready: Cell::new(true),
            nonblocking: Cell::new(false),
            closed: Cell::new(false),
        }
    }

    pub fn new_raw(fam: c_int, ty: c_int) -> io::Result<Socket> {
        unsafe {
            // On linux we first attempt to pass the SOCK_CLOEXEC flag to
            // atomically create the socket and set it as CLOEXEC. Support for
            // this option, however, was added in 2.6.27, and we still support
            // 2.6.18 as a kernel, so if the returned error is EINVAL we
            // fallthrough to the fallback.
            if cfg!(target_os = "linux") {
                match cvt(libc::socket(fam, ty | SOCK_CLOEXEC, 0)) {
                    Ok(fd) => return Ok(Socket::new_by_fd(fd)),
                    Err(ref e) if e.raw_os_error() == Some(libc::EINVAL) => {}
                    Err(e) => return Err(e),
                }
            }

            let fd = cvt(libc::socket(fam, ty, 0))?;
            let fd = fd;
            Self::set_cloexec(fd)?;
            let socket = Socket::new_by_fd(fd);
            // if cfg!(any(target_os = "freebsd", target_os = "ios", target_os = "macos", target_os = "netbsd", target_os = "openbsd")) {
            //     setsockopt(&socket, libc::SOL_SOCKET, SO_NOSIGPIPE, 1)?;
            // }
            Ok(socket)
        }
    }

    pub fn new_v4() -> io::Result<Socket> {
        Self::new_raw(libc::AF_INET, libc::SOCK_STREAM)
    }

    pub fn new_v6() -> io::Result<Socket> {
        Self::new_raw(libc::AF_INET6, libc::SOCK_STREAM)
    }

    pub fn new_pair(fam: c_int, ty: c_int) -> io::Result<(Socket, Socket)> {
        unsafe {
            let mut fds = [0, 0];

            // Like above, see if we can set cloexec atomically
            if cfg!(target_os = "linux") {
                match cvt(libc::socketpair(fam, ty | SOCK_CLOEXEC, 0, fds.as_mut_ptr())) {
                    Ok(_) => {
                        return Ok((Socket::new_by_fd(fds[0]), Socket::new_by_fd(fds[1])));
                    }
                    Err(ref e) if e.raw_os_error() == Some(libc::EINVAL) => {},
                    Err(e) => return Err(e),
                }
            }

            cvt(libc::socketpair(fam, ty, 0, fds.as_mut_ptr()))?;
            let a = fds[0];
            let b = fds[1];
            Self::set_cloexec(a)?;
            Self::set_cloexec(b)?;
            Ok((Socket::new_by_fd(a), Socket::new_by_fd(b)))
        }
    }

    pub fn connect_timeout(&self, addr: &SocketAddr, timeout: Duration) -> io::Result<()> {
        self.set_nonblocking(true)?;
        let r = unsafe {
            let (addrp, len) = addr.into_inner();
            cvt(libc::connect(self.socket, addrp, len))
        };
        self.set_nonblocking(false)?;

        match r {
            Ok(_) => return Ok(()),
            // there's no ErrorKind for EINPROGRESS :(
            Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => return Err(e),
        }

        let mut pollfd = libc::pollfd {
            fd: self.socket,
            events: libc::POLLOUT,
            revents: 0,
        };

        if timeout.as_secs() == 0 && timeout.subsec_nanos() == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                      "cannot set a 0 duration timeout"));
        }

        let start = Instant::now();

        loop {
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "connection timed out"));
            }

            let timeout = timeout - elapsed;
            let mut timeout = timeout.as_secs()
                .saturating_mul(1_000)
                .saturating_add(timeout.subsec_nanos() as u64 / 1_000_000);
            if timeout == 0 {
                timeout = 1;
            }

            let timeout = cmp::min(timeout, c_int::max_value() as u64) as c_int;

            match unsafe { libc::poll(&mut pollfd, 1, timeout) } {
                -1 => {
                    let err = io::Error::last_os_error();
                    if err.kind() != io::ErrorKind::Interrupted {
                        return Err(err);
                    }
                }
                0 => {}
                _ => {
                    // linux returns POLLOUT|POLLERR|POLLHUP for refused connections (!), so look
                    // for POLLHUP rather than read readiness
                    if pollfd.revents & libc::POLLHUP != 0 {
                        let e = self.take_error()?
                            .unwrap_or_else(|| {
                                io::Error::new(io::ErrorKind::Other, "no error set after POLLHUP")
                            });
                        return Err(e);
                    }

                    return Ok(());
                }
            }
        }
    }

    pub fn connect_asyn(&self, addr: &SocketAddr) -> io::Result<()> {
        self.set_nonblocking(true)?;
        let r = unsafe {
            let (addrp, len) = addr.into_inner();
            cvt(libc::connect(self.socket, addrp, len))
        };
        self.set_nonblocking(false)?;

        match r {
            Ok(_) => return Ok(()),
            // there's no ErrorKind for EINPROGRESS :(
            Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {
                return Ok(())
            }
            Err(e) => return Err(e),
        }
    }

    pub fn new_out_fd(fd: SOCKET) -> Socket {
        Socket {
            socket: fd,
            ready: Cell::new(true),
            nonblocking: Cell::new(false),
            closed: Cell::new(false),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.socket != INVALID_SOCKET    
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

        let mut pollfd = libc::pollfd {
            fd: self.socket,
            events: libc::POLLOUT,
            revents: 0,
        };

        let timeout = 0 as c_int;
        match unsafe { libc::poll(&mut pollfd, 1, timeout) } {
            -1 => {
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::Interrupted {
                    return Err(err);
                }
            }
            0 => {}
            _ => {
                // linux returns POLLOUT|POLLERR|POLLHUP for refused connections (!), so look
                // for POLLHUP rather than read readiness
                if pollfd.revents & libc::POLLHUP != 0 {
                    let e = self.take_error()?
                        .unwrap_or_else(|| {
                            io::Error::new(io::ErrorKind::Other, "no error set after POLLHUP")
                        });
                    return Err(e);
                }

                self.ready.set(true);
            }
        }

        Ok(self.ready.get())
    }

    pub fn set_liner(&self, enable: bool, time: u16) -> io::Result<()> {
        let enable = if enable { 1 } else { 0 };
        let linger = libc::linger {
            l_onoff: enable as c_int,
            l_linger: time as c_int,
        };

        setsockopt(self, libc::SOL_SOCKET, libc::SO_LINGER, linger)
    }

    pub fn liner(&self) -> io::Result<(bool, u16)> {
        let liner: libc::linger = getsockopt(self, libc::SOL_SOCKET, libc::SO_LINGER)?;

        Ok((liner.l_onoff == 1, liner.l_linger as u16))
    }

    pub fn set_recv_size(&self, size: u32) -> io::Result<()> {
        let size = size / 2;
        setsockopt(self, libc::SOL_SOCKET, libc::SO_RCVBUF, size)
    }

    pub fn recv_size(&self) -> io::Result<u32> {
        getsockopt(self, libc::SOL_SOCKET, libc::SO_RCVBUF)
    }

    pub fn set_send_size(&self, size: u32) -> io::Result<()> {
        let size = size / 2;
        setsockopt(self, libc::SOL_SOCKET, libc::SO_SNDBUF, size)
    }

    pub fn send_size(&self) -> io::Result<u32> {
        getsockopt(self, libc::SOL_SOCKET, libc::SO_SNDBUF)
    }

    pub fn set_reuse_addr(&self) -> io::Result<()> {
        setsockopt(self, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)
    }

    pub fn accept(&self, storage: *mut sockaddr, len: *mut socklen_t)
                  -> io::Result<Socket> {
        // Unfortunately the only known way right now to accept a socket and
        // atomically set the CLOEXEC flag is to use the `accept4` syscall on
        // Linux. This was added in 2.6.28, however, and because we support
        // 2.6.18 we must detect this support dynamically.
        // if cfg!(target_os = "linux") {
        //     let res = cvt_r(|| unsafe {
        //         accept4(self.socket, storage, len, SOCK_CLOEXEC)
        //     });
        //     match res {
        //         Ok(fd) => return Ok(Socket::new_ready_fd(fd)),
        //         Err(ref e) if e.raw_os_error() == Some(libc::ENOSYS) => {}
        //         Err(e) => return Err(e),
        //     }
        // }

        let fd = cvt_r(|| unsafe {
            libc::accept(self.socket, storage, len)
        })?;
        let fd = fd;
        Self::set_cloexec(fd);
        Ok(Socket::new_ready_fd(fd))
    }

    pub fn duplicate(&self) -> io::Result<Socket> {
        use libc::F_DUPFD_CLOEXEC;
        let fd = self.socket;
        match cvt(unsafe { libc::fcntl(fd, F_DUPFD_CLOEXEC, 0) }) {
            Ok(fd) => {
                Self::set_cloexec(fd);
                return Ok(Socket::new_ready_fd(fd));
            }
            Err(e) => return Err(e),
        }
        // cvt(unsafe { libc::fcntl(fd, libc::F_DUPFD, 0) }).and_then(make_filedesc)
    }

    fn recv_with_flags(&self, buf: &mut [u8], flags: c_int) -> io::Result<usize> {
        let ret = cvt(unsafe {
            libc::recv(self.socket,
                       buf.as_mut_ptr() as *mut c_void,
                       buf.len(),
                       flags)
        })?;
        Ok(ret as usize)
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_with_flags(buf, 0)
    }

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_with_flags(buf, MSG_PEEK)
    }

    fn recv_from_with_flags(&self, buf: &mut [u8], flags: c_int)
                            -> io::Result<(usize, SocketAddr)> {
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut addrlen = mem::size_of_val(&storage) as libc::socklen_t;

        let n = cvt(unsafe {
            libc::recvfrom(self.socket,
                        buf.as_mut_ptr() as *mut c_void,
                        buf.len(),
                        flags,
                        &mut storage as *mut _ as *mut _,
                        &mut addrlen)
        })?;
        Ok((n as usize, sockaddr_to_addr(&storage, addrlen as usize)?))
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from_with_flags(buf, 0)
    }

    pub fn peek_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from_with_flags(buf, MSG_PEEK)
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let ret = cvt(unsafe {
            libc::write(self.socket,
                        buf.as_ptr() as *const c_void,
                        cmp::min(buf.len(), max_len()))
        })?;
        Ok(ret as usize)
    }

    pub fn set_timeout(&self, dur: Option<Duration>, kind: libc::c_int) -> io::Result<()> {
        let timeout = match dur {
            Some(dur) => {
                if dur.as_secs() == 0 && dur.subsec_nanos() == 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                              "cannot set a 0 duration timeout"));
                }

                let secs = if dur.as_secs() > libc::time_t::max_value() as u64 {
                    libc::time_t::max_value()
                } else {
                    dur.as_secs() as libc::time_t
                };
                let mut timeout = libc::timeval {
                    tv_sec: secs,
                    tv_usec: (dur.subsec_nanos() / 1000) as libc::suseconds_t,
                };
                if timeout.tv_sec == 0 && timeout.tv_usec == 0 {
                    timeout.tv_usec = 1;
                }
                timeout
            }
            None => {
                libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                }
            }
        };
        setsockopt(self, libc::SOL_SOCKET, kind, timeout)
    }

    pub fn timeout(&self, kind: libc::c_int) -> io::Result<Option<Duration>> {
        let raw: libc::timeval = getsockopt(self, libc::SOL_SOCKET, kind)?;
        if raw.tv_sec == 0 && raw.tv_usec == 0 {
            Ok(None)
        } else {
            let sec = raw.tv_sec as u64;
            let nsec = (raw.tv_usec as u32) * 1000;
            Ok(Some(Duration::new(sec, nsec)))
        }
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let how = match how {
            Shutdown::Write => libc::SHUT_WR,
            Shutdown::Read => libc::SHUT_RD,
            Shutdown::Both => libc::SHUT_RDWR,
        };
        cvt(unsafe { libc::shutdown(self.socket, how) })?;
        Ok(())
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        setsockopt(self, libc::IPPROTO_TCP, libc::TCP_NODELAY, nodelay as c_int)
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        let raw: c_int = getsockopt(self, libc::IPPROTO_TCP, libc::TCP_NODELAY)?;
        Ok(raw != 0)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let mut nonblocking = nonblocking as libc::c_int;
        cvt(unsafe { libc::ioctl(*self.as_inner(), libc::FIONBIO, &mut nonblocking) })?;
        self.nonblocking.set(nonblocking == 1);
        Ok(())
    }

    pub fn is_nonblocking(&self) -> bool {
        self.nonblocking.get()
    }


    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        let raw: c_int = getsockopt(self, libc::SOL_SOCKET, libc::SO_ERROR)?;
        if raw == 0 {
            Ok(None)
        } else {
            Ok(Some(io::Error::from_raw_os_error(raw as i32)))
        }
    }

    pub fn set_cloexec(fd: c_int) -> io::Result<()> {
        unsafe {
            cvt(libc::ioctl(fd, libc::FIOCLEX))?;
            Ok(())
        }
    }

    pub fn close(&self) {
        let _ = unsafe { libc::close(self.socket) };
        self.closed.set(true);
    }

    pub fn is_close(&self) -> bool {
        self.closed.get()
    }


    pub fn unlink(mut self) -> c_int {
        let sock = self.socket;
        self.socket = INVALID_SOCKET;
        sock
    } 
}

impl Drop for Socket {
    fn drop(&mut self) {
        if self.socket == INVALID_SOCKET || self.is_close() {
            return;
        }
        let _ = unsafe { libc::close(self.socket) };
    }
}

impl Clone for Socket {
    fn clone(&self) -> Socket {
        Socket {
            socket: self.socket,
            ready: self.ready.clone(),
            nonblocking: self.nonblocking.clone(),
            closed: self.closed.clone(),
        }
    }
}

impl AsInner<c_int> for Socket {
    fn as_inner(&self) -> &c_int { &self.socket }
}

impl FromInner<c_int> for Socket {
    fn from_inner(fd: c_int) -> Socket { Socket::new_ready_fd(fd) }
}

impl IntoInner<c_int> for Socket {
    fn into_inner(self) -> c_int {
        self.unlink()
    }
}
