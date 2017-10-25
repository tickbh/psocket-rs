// Copyright 2014 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! C definitions used by libnative that don't belong in liblibc

#![allow(bad_style)]
#![cfg_attr(test, allow(dead_code))]

use std::os::raw::{c_int, c_uint, c_ulong, c_long, c_ushort, c_char};
#[cfg(target_arch = "x86_64")]
use libc::{size_t, c_void};


#[cfg(target_pointer_width = "32")]
pub type SOCKET = u32;
#[cfg(target_pointer_width = "64")]
pub type SOCKET = u64;

pub type DWORD = c_ulong;
pub type HANDLE = LPVOID;
pub type BOOL = c_int;
pub type BYTE = u8;
pub type GROUP = c_uint;
pub type USHORT = c_ushort;
pub type WORD = u16;
pub type CHAR = c_char;

pub type LPHANDLE = *mut HANDLE;
pub type LPVOID = *mut c_void;
pub type LPWSADATA = *mut WSADATA;
pub type LPWSAPROTOCOL_INFO = *mut WSAPROTOCOL_INFO;

pub type socklen_t = c_int;
pub type ADDRESS_FAMILY = USHORT;


pub const FIONBIO: c_ulong = 0x8004667e;

pub const WSA_FLAG_OVERLAPPED: DWORD = 0x01;

pub const WSADESCRIPTION_LEN: usize = 256;
pub const WSASYS_STATUS_LEN: usize = 128;
pub const WSAPROTOCOL_LEN: DWORD = 255;
pub const INVALID_SOCKET: SOCKET = !0;

pub const WSAEACCES: c_int = 10013;
pub const WSAEINVAL: c_int = 10022;
pub const WSAEWOULDBLOCK: c_int = 10035;
pub const WSAEADDRINUSE: c_int = 10048;
pub const WSAEADDRNOTAVAIL: c_int = 10049;
pub const WSAECONNABORTED: c_int = 10053;
pub const WSAECONNRESET: c_int = 10054;
pub const WSAENOTCONN: c_int = 10057;
pub const WSAESHUTDOWN: c_int = 10058;
pub const WSAETIMEDOUT: c_int = 10060;
pub const WSAECONNREFUSED: c_int = 10061;

pub const MAX_PROTOCOL_CHAIN: DWORD = 7;


pub const HANDLE_FLAG_INHERIT: DWORD = 0x00000001;


pub const INFINITE: DWORD = !0;

pub const AF_INET: c_int = 2;
pub const AF_INET6: c_int = 23;
pub const SD_BOTH: c_int = 2;
pub const SD_RECEIVE: c_int = 0;
pub const SD_SEND: c_int = 1;
pub const SOCK_DGRAM: c_int = 2;
pub const SOCK_STREAM: c_int = 1;
pub const SOL_SOCKET: c_int = 0xffff;


pub const SO_SNDBUF: c_int = 0x1001;
pub const SO_RCVBUF: c_int = 0x1002;
pub const SO_RCVTIMEO: c_int = 0x1006;
pub const SO_SNDTIMEO: c_int = 0x1005;
pub const SO_REUSEADDR: c_int = 0x0004;
pub const IPPROTO_IP: c_int = 0;
pub const IPPROTO_TCP: c_int = 6;
pub const IPPROTO_IPV6: c_int = 41;
pub const TCP_NODELAY: c_int = 0x0001;
pub const IP_TTL: c_int = 4;
pub const IPV6_V6ONLY: c_int = 27;
pub const SO_ERROR: c_int = 0x1007;
pub const SO_BROADCAST: c_int = 0x0020;
pub const SO_LINGER: c_int = 0x0080;
pub const IP_MULTICAST_LOOP: c_int = 11;
pub const IPV6_MULTICAST_LOOP: c_int = 11;
pub const IP_MULTICAST_TTL: c_int = 10;
pub const IP_ADD_MEMBERSHIP: c_int = 12;
pub const IP_DROP_MEMBERSHIP: c_int = 13;
pub const IPV6_ADD_MEMBERSHIP: c_int = 12;
pub const IPV6_DROP_MEMBERSHIP: c_int = 13;
pub const MSG_PEEK: c_int = 0x2;

#[repr(C)]
pub struct ip_mreq {
    pub imr_multiaddr: in_addr,
    pub imr_interface: in_addr,
}

#[repr(C)]
pub struct ipv6_mreq {
    pub ipv6mr_multiaddr: in6_addr,
    pub ipv6mr_interface: c_uint,
}



pub const FD_SETSIZE: usize = 64;

#[repr(C)]
#[cfg(not(target_pointer_width = "64"))]
pub struct WSADATA {
    pub wVersion: WORD,
    pub wHighVersion: WORD,
    pub szDescription: [u8; WSADESCRIPTION_LEN + 1],
    pub szSystemStatus: [u8; WSASYS_STATUS_LEN + 1],
    pub iMaxSockets: u16,
    pub iMaxUdpDg: u16,
    pub lpVendorInfo: *mut u8,
}
#[repr(C)]
#[cfg(target_pointer_width = "64")]
pub struct WSADATA {
    pub wVersion: WORD,
    pub wHighVersion: WORD,
    pub iMaxSockets: u16,
    pub iMaxUdpDg: u16,
    pub lpVendorInfo: *mut u8,
    pub szDescription: [u8; WSADESCRIPTION_LEN + 1],
    pub szSystemStatus: [u8; WSASYS_STATUS_LEN + 1],
}

#[repr(C)]
pub struct WSAPROTOCOL_INFO {
    pub dwServiceFlags1: DWORD,
    pub dwServiceFlags2: DWORD,
    pub dwServiceFlags3: DWORD,
    pub dwServiceFlags4: DWORD,
    pub dwProviderFlags: DWORD,
    pub ProviderId: GUID,
    pub dwCatalogEntryId: DWORD,
    pub ProtocolChain: WSAPROTOCOLCHAIN,
    pub iVersion: c_int,
    pub iAddressFamily: c_int,
    pub iMaxSockAddr: c_int,
    pub iMinSockAddr: c_int,
    pub iSocketType: c_int,
    pub iProtocol: c_int,
    pub iProtocolMaxOffset: c_int,
    pub iNetworkByteOrder: c_int,
    pub iSecurityScheme: c_int,
    pub dwMessageSize: DWORD,
    pub dwProviderReserved: DWORD,
    pub szProtocol: [u16; (WSAPROTOCOL_LEN as usize) + 1],
}



#[repr(C)]
pub struct GUID {
    pub Data1: DWORD,
    pub Data2: WORD,
    pub Data3: WORD,
    pub Data4: [BYTE; 8],
}

#[repr(C)]
pub struct WSAPROTOCOLCHAIN {
    pub ChainLen: c_int,
    pub ChainEntries: [DWORD; MAX_PROTOCOL_CHAIN as usize],
}

#[repr(C)]
pub struct SOCKADDR {
    pub sa_family: ADDRESS_FAMILY,
    pub sa_data: [CHAR; 14],
}

#[repr(C)]
pub struct SOCKADDR_STORAGE_LH {
    pub ss_family: ADDRESS_FAMILY,
    pub __ss_pad1: [CHAR; 6],
    pub __ss_align: i64,
    pub __ss_pad2: [CHAR; 112],
}

#[repr(C)]
pub struct ADDRINFOA {
    pub ai_flags: c_int,
    pub ai_family: c_int,
    pub ai_socktype: c_int,
    pub ai_protocol: c_int,
    pub ai_addrlen: size_t,
    pub ai_canonname: *mut c_char,
    pub ai_addr: *mut SOCKADDR,
    pub ai_next: *mut ADDRINFOA,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_in {
    pub sin_family: ADDRESS_FAMILY,
    pub sin_port: USHORT,
    pub sin_addr: in_addr,
    pub sin_zero: [CHAR; 8],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_in6 {
    pub sin6_family: ADDRESS_FAMILY,
    pub sin6_port: USHORT,
    pub sin6_flowinfo: c_ulong,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: c_ulong,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct in_addr {
    pub s_addr: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct in6_addr {
    pub s6_addr: [u8; 16],
}

#[repr(C)]
#[derive(Copy)]
pub struct fd_set {
    pub fd_count: c_uint,
    pub fd_array: [SOCKET; FD_SETSIZE],
}

impl Clone for fd_set {
    fn clone(&self) -> fd_set {
        *self
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct timeval {
    pub tv_sec: c_long,
    pub tv_usec: c_long,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct  linger {
    pub l_onoff: c_ushort,
    pub l_linger: c_ushort,
}

extern "system" {
    pub fn WSAStartup(wVersionRequested: WORD,
                      lpWSAData: LPWSADATA) -> c_int;
    pub fn WSACleanup() -> c_int;
    pub fn WSAGetLastError() -> c_int;
    pub fn WSADuplicateSocketW(s: SOCKET,
                               dwProcessId: DWORD,
                               lpProtocolInfo: LPWSAPROTOCOL_INFO)
                               -> c_int;
    pub fn GetCurrentProcessId() -> DWORD;
    pub fn WSASocketW(af: c_int,
                      kind: c_int,
                      protocol: c_int,
                      lpProtocolInfo: LPWSAPROTOCOL_INFO,
                      g: GROUP,
                      dwFlags: DWORD) -> SOCKET;
    pub fn ioctlsocket(s: SOCKET, cmd: c_long, argp: *mut c_ulong) -> c_int;

    pub fn SetLastError(dwErrCode: DWORD);
    pub fn SetHandleInformation(hObject: HANDLE,
                                dwMask: DWORD,
                                dwFlags: DWORD) -> BOOL;
    
    pub fn GetLastError() -> DWORD;

    pub fn closesocket(socket: SOCKET) -> c_int;
    pub fn recv(socket: SOCKET, buf: *mut c_void, len: c_int,
                flags: c_int) -> c_int;
    pub fn send(socket: SOCKET, buf: *const c_void, len: c_int,
                flags: c_int) -> c_int;
    pub fn recvfrom(socket: SOCKET,
                    buf: *mut c_void,
                    len: c_int,
                    flags: c_int,
                    addr: *mut SOCKADDR,
                    addrlen: *mut c_int)
                    -> c_int;
    pub fn sendto(socket: SOCKET,
                  buf: *const c_void,
                  len: c_int,
                  flags: c_int,
                  addr: *const SOCKADDR,
                  addrlen: c_int)
                  -> c_int;
    pub fn shutdown(socket: SOCKET, how: c_int) -> c_int;
    pub fn accept(socket: SOCKET,
                  address: *mut SOCKADDR,
                  address_len: *mut c_int)
                  -> SOCKET;
    pub fn DuplicateHandle(hSourceProcessHandle: HANDLE,
                           hSourceHandle: HANDLE,
                           hTargetProcessHandle: HANDLE,
                           lpTargetHandle: LPHANDLE,
                           dwDesiredAccess: DWORD,
                           bInheritHandle: BOOL,
                           dwOptions: DWORD)
                           -> BOOL;
    
    pub fn getsockopt(s: SOCKET,
                      level: c_int,
                      optname: c_int,
                      optval: *mut c_char,
                      optlen: *mut c_int)
                      -> c_int;
    pub fn setsockopt(s: SOCKET,
                      level: c_int,
                      optname: c_int,
                      optval: *const c_void,
                      optlen: c_int)
                      -> c_int;
    pub fn getsockname(socket: SOCKET,
                       address: *mut SOCKADDR,
                       address_len: *mut c_int)
                       -> c_int;
    pub fn getpeername(socket: SOCKET,
                       address: *mut SOCKADDR,
                       address_len: *mut c_int)
                       -> c_int;
    pub fn bind(socket: SOCKET, address: *const SOCKADDR,
                address_len: socklen_t) -> c_int;
    pub fn listen(socket: SOCKET, backlog: c_int) -> c_int;
    pub fn connect(socket: SOCKET, address: *const SOCKADDR, len: c_int)
                   -> c_int;
    pub fn getaddrinfo(node: *const c_char, service: *const c_char,
                       hints: *const ADDRINFOA,
                       res: *mut *mut ADDRINFOA) -> c_int;
    pub fn freeaddrinfo(res: *mut ADDRINFOA);

    pub fn select(nfds: c_int,
                  readfds: *mut fd_set,
                  writefds: *mut fd_set,
                  exceptfds: *mut fd_set,
                  timeout: *const timeval) -> c_int;
}

#[cfg(target_env = "gnu")]
mod gnu {
    use super::*;

}

#[cfg(target_env = "gnu")]
pub use self::gnu::*;
