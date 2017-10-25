// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::io::prelude::*;

use std::fmt;
use std::io::{self};
use net::{ToSocketAddrs, SocketAddr, Shutdown};
use sys_common::net as net_imp;
use sys_common::{AsInner, FromInner, IntoInner};
use std::time::Duration;

/// A TCP stream between a local and a remote socket.
///
/// After creating a `TcpSocket` by either [`connect`]ing to a remote host or
/// [`accept`]ing a connection on a [`TcpSocket`], data can be transmitted
/// by [reading] and [writing] to it.
///
/// The connection will be closed when the value is dropped. The reading and writing
/// portions of the connection can also be shut down individually with the [`shutdown`]
/// method.
///
/// The Transmission Control Protocol is specified in [IETF RFC 793].
///
/// [`accept`]: ../../pscoket/net/struct.TcpSocket.html#method.accept
/// [`connect`]: #method.connect
/// [IETF RFC 793]: https://tools.ietf.org/html/rfc793
/// [reading]: ../../std/io/trait.Read.html
/// [`shutdown`]: #method.shutdown
/// [`TcpSocket`]: ../../pscoket/net/struct.TcpSocket.html
/// [writing]: ../../std/io/trait.Write.html
///
/// # Examples
///
/// ```no_run
/// use std::io::prelude::*;
/// use psocket::TcpSocket;
///
/// {
///     let mut stream = TcpSocket::connect("127.0.0.1:34254").unwrap();
///
///     // ignore the Result
///     let _ = stream.write(&[1]);
///     let _ = stream.read(&mut [0; 128]); // ignore here too
/// } // the stream is closed here
/// ```
pub struct TcpSocket(net_imp::TcpSocket);

/// An iterator that infinitely [`accept`]s connections on a [`TcpSocket`].
///
/// This `struct` is created by the [`incoming`] method on [`TcpSocket`].
/// See its documentation for more.
///
/// [`accept`]: ../../pscoket/net/struct.TcpSocket.html#method.accept
/// [`incoming`]: ../../pscoket/net/struct.TcpSocket.html#method.incoming
/// [`TcpSocket`]: ../../pscoket/net/struct.TcpSocket.html
#[derive(Debug)]
pub struct Incoming<'a> { listener: &'a TcpSocket }

impl TcpSocket {
    /// Opens a TCP connection to a remote host.
    ///
    /// `addr` is an address of the remote host. Anything which implements
    /// [`ToSocketAddrs`] trait can be supplied for the address; see this trait
    /// documentation for concrete examples.
    ///
    /// If `addr` yields multiple addresses, `connect` will be attempted with
    /// each of the addresses until a connection is successful. If none of
    /// the addresses result in a successful connection, the error returned from
    /// the last connection attempt (the last address) is returned.
    ///
    /// [`ToSocketAddrs`]: ../../pscoket/net/trait.ToSocketAddrs.html
    ///
    /// # Examples
    ///
    /// Open a TCP connection to `127.0.0.1:8080`:
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// if let Ok(stream) = TcpSocket::connect("127.0.0.1:8080") {
    ///     println!("Connected to the server!");
    /// } else {
    ///     println!("Couldn't connect to server...");
    /// }
    /// ```
    ///
    /// Open a TCP connection to `127.0.0.1:8080`. If the connection fails, open
    /// a TCP connection to `127.0.0.1:8081`:
    ///
    /// ```no_run
    /// use psocket::{SocketAddr, TcpSocket};
    ///
    /// let addrs = [
    ///     SocketAddr::from(([127, 0, 0, 1], 8080)),
    ///     SocketAddr::from(([127, 0, 0, 1], 8081)),
    /// ];
    /// if let Ok(stream) = TcpSocket::connect(&addrs[..]) {
    ///     println!("Connected to the server!");
    /// } else {
    ///     println!("Couldn't connect to server...");
    /// }
    /// ```
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<TcpSocket> {
        super::each_addr(addr, net_imp::TcpSocket::connect).map(TcpSocket)
    }

    /// Opens a TCP connection to a remote host with a timeout.
    ///
    /// Unlike `connect`, `connect_timeout` takes a single [`SocketAddr`] since
    /// timeout must be applied to individual addresses.
    ///
    /// It is an error to pass a zero `Duration` to this function.
    ///
    /// Unlike other methods on `TcpSocket`, this does not correspond to a
    /// single system call. It instead calls `connect` in nonblocking mode and
    /// then uses an OS-specific mechanism to await the completion of the
    /// connection request.
    ///
    /// [`SocketAddr`]: ../../pscoket/net/enum.SocketAddr.html
    pub fn connect_timeout(addr: &SocketAddr, timeout: Duration) -> io::Result<TcpSocket> {
        net_imp::TcpSocket::connect_timeout(addr, timeout).map(TcpSocket)
    }

    /// Opens a TCP connection to a remote host with asyn.
    /// It will return immediately but the stream status is not ok, 
    /// when you want to use it, must call check_ready to check ok
    pub fn connect_asyn(addr: &SocketAddr) -> io::Result<TcpSocket> {
        net_imp::TcpSocket::connect_asyn(addr).map(TcpSocket)
    }

    /// return -1 is not a valid socket
    /// return > 0 when the socket is ok
    pub fn get_socket_fd(&self) -> i32 {
        self.0.get_socket_fd()
    }

    /// new by the socket fd, it will always set ready ok
    /// it will not a valid socket, when fd set -1
    pub fn new_by_fd(fd: i32) -> io::Result<TcpSocket> {
        net_imp::TcpSocket::new_by_fd(fd).map(TcpSocket)
    }

    /// check the socket is valid.
    pub fn is_valid(&self) -> bool {
        self.0.is_valid()
    }

    /// check the socket status is ready.
    pub fn is_ready(&self) -> bool {
        self.0.is_ready()
    }

    /// set socket ready status manual.
    pub fn set_ready(&mut self, ready: bool) {
        self.0.set_ready(ready);
    }

    /// check socket ready status, when you connect remote host by asyn.
    pub fn check_ready(&mut self) -> io::Result<bool> {
        self.0.check_ready()
    }

    /// Returns the socket address of the remote peer of this TCP connection.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpSocket};
    ///
    /// let stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// assert_eq!(stream.peer_addr().unwrap(),
    ///            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)));
    /// ```
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.0.peer_addr()
    }

    /// Returns the socket address of the local half of this TCP connection.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::{IpAddr, Ipv4Addr, TcpSocket};
    ///
    /// let stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// assert_eq!(stream.local_addr().unwrap().ip(),
    ///            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    /// ```
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.socket_addr()
    }

    /// Shuts down the read, write, or both halves of this connection.
    ///
    /// This function will cause all pending and future I/O on the specified
    /// portions to return immediately with an appropriate value (see the
    /// documentation of [`Shutdown`]).
    ///
    /// [`Shutdown`]: ../../pscoket/net/enum.Shutdown.html
    ///
    /// # Platform-specific behavior
    ///
    /// Calling this function multiple times may result in different behavior,
    /// depending on the operating system. On Linux, the second call will
    /// return `Ok(())`, but on macOS, it will return `ErrorKind::NotConnected`.
    /// This may change in the future.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::{Shutdown, TcpSocket};
    ///
    /// let stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.shutdown(Shutdown::Both).expect("shutdown call failed");
    /// ```
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.0.shutdown(how)
    }

    /// Creates a new independently owned handle to the underlying socket.
    ///
    /// The returned `TcpSocket` is a reference to the same stream that this
    /// object references. Both handles will read and write the same stream of
    /// data, and options set on one stream will be propagated to the other
    /// stream.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// let stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// let stream_clone = stream.try_clone().expect("clone failed...");
    /// ```
    pub fn try_clone(&self) -> io::Result<TcpSocket> {
        self.0.duplicate().map(TcpSocket)
    }

    /// Sets the read timeout to the timeout specified.
    ///
    /// If the value specified is [`None`], then [`read`] calls will block
    /// indefinitely. It is an error to pass the zero `Duration` to this
    /// method.
    ///
    /// # Note
    ///
    /// Platforms may return a different error code whenever a read times out as
    /// a result of setting this option. For example Unix typically returns an
    /// error of the kind [`WouldBlock`], but Windows may return [`TimedOut`].
    ///
    /// [`None`]: ../../std/option/enum.Option.html#variant.None
    /// [`read`]: ../../std/io/trait.Read.html#tymethod.read
    /// [`WouldBlock`]: ../../std/io/enum.ErrorKind.html#variant.WouldBlock
    /// [`TimedOut`]: ../../std/io/enum.ErrorKind.html#variant.TimedOut
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// let stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.set_read_timeout(None).expect("set_read_timeout call failed");
    /// ```
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(dur)
    }

    /// Sets the write timeout to the timeout specified.
    ///
    /// If the value specified is [`None`], then [`write`] calls will block
    /// indefinitely. It is an error to pass the zero [`Duration`] to this
    /// method.
    ///
    /// # Note
    ///
    /// Platforms may return a different error code whenever a write times out
    /// as a result of setting this option. For example Unix typically returns
    /// an error of the kind [`WouldBlock`], but Windows may return [`TimedOut`].
    ///
    /// [`None`]: ../../std/option/enum.Option.html#variant.None
    /// [`write`]: ../../std/io/trait.Write.html#tymethod.write
    /// [`Duration`]: ../../std/time/struct.Duration.html
    /// [`WouldBlock`]: ../../std/io/enum.ErrorKind.html#variant.WouldBlock
    /// [`TimedOut`]: ../../std/io/enum.ErrorKind.html#variant.TimedOut
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// let stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.set_write_timeout(None).expect("set_write_timeout call failed");
    /// ```
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(dur)
    }

    /// Returns the read timeout of this socket.
    ///
    /// If the timeout is [`None`], then [`read`] calls will block indefinitely.
    ///
    /// # Note
    ///
    /// Some platforms do not provide access to the current timeout.
    ///
    /// [`None`]: ../../std/option/enum.Option.html#variant.None
    /// [`read`]: ../../std/io/trait.Read.html#tymethod.read
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// let stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.set_read_timeout(None).expect("set_read_timeout call failed");
    /// assert_eq!(stream.read_timeout().unwrap(), None);
    /// ```
    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.0.read_timeout()
    }

    /// Returns the write timeout of this socket.
    ///
    /// If the timeout is [`None`], then [`write`] calls will block indefinitely.
    ///
    /// # Note
    ///
    /// Some platforms do not provide access to the current timeout.
    ///
    /// [`None`]: ../../std/option/enum.Option.html#variant.None
    /// [`write`]: ../../std/io/trait.Write.html#tymethod.write
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// let stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.set_write_timeout(None).expect("set_write_timeout call failed");
    /// assert_eq!(stream.write_timeout().unwrap(), None);
    /// ```
    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.0.write_timeout()
    }

    /// Receives data on the socket from the remote address to which it is
    /// connected, without removing that data from the queue. On success,
    /// returns the number of bytes peeked.
    ///
    /// Successive calls return the same data. This is accomplished by passing
    /// `MSG_PEEK` as a flag to the underlying `recv` system call.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// let stream = TcpSocket::connect("127.0.0.1:8000")
    ///                        .expect("couldn't bind to address");
    /// let mut buf = [0; 10];
    /// let len = stream.peek(&mut buf).expect("peek failed");
    /// ```
    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.peek(buf)
    }

    /// Sets the value of the `TCP_NODELAY` option on this socket.
    ///
    /// If set, this option disables the Nagle algorithm. This means that
    /// segments are always sent as soon as possible, even if there is only a
    /// small amount of data. When not set, data is buffered until there is a
    /// sufficient amount to send out, thereby avoiding the frequent sending of
    /// small packets.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// let stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.set_nodelay(true).expect("set_nodelay call failed");
    /// ```
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.0.set_nodelay(nodelay)
    }

    /// Gets the value of the `TCP_NODELAY` option on this socket.
    ///
    /// For more information about this option, see [`set_nodelay`][link].
    ///
    /// [link]: #method.set_nodelay
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// let stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.set_nodelay(true).expect("set_nodelay call failed");
    /// assert_eq!(stream.nodelay().unwrap_or(false), true);
    /// ```
    pub fn nodelay(&self) -> io::Result<bool> {
        self.0.nodelay()
    }

    /// Sets the value for the `IP_TTL` option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent
    /// from this socket.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// let stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.set_ttl(100).expect("set_ttl call failed");
    /// ```
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.0.set_ttl(ttl)
    }

    /// Gets the value of the `IP_TTL` option for this socket.
    ///
    /// For more information about this option, see [`set_ttl`][link].
    ///
    /// [link]: #method.set_ttl
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// let stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.set_ttl(100).expect("set_ttl call failed");
    /// assert_eq!(stream.ttl().unwrap_or(0), 100);
    /// ```
    pub fn ttl(&self) -> io::Result<u32> {
        self.0.ttl()
    }

    /// Get the value of the `SO_ERROR` option on this socket.
    ///
    /// This will retrieve the stored error in the underlying socket, clearing
    /// the field in the process. This can be useful for checking errors between
    /// calls.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// let stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.take_error().expect("No error was expected...");
    /// ```
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.0.take_error()
    }

    /// Moves this TCP stream into or out of nonblocking mode.
    ///
    /// On Unix this corresponds to calling fcntl, and on Windows this
    /// corresponds to calling ioctlsocket.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// let mut stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.set_nonblocking(true).expect("set_nonblocking call failed");
    /// ```
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    /// The method measure the socket is nonblocking
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// let mut stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.set_nonblocking(true).expect("set_nonblocking call failed");
    /// assert!(stream.is_nonblocking());
    /// ```
    pub fn is_nonblocking(&self) -> bool {
        self.0.is_nonblocking()
    }
    
    /// Moves this TCP stream into or out of liner mode.
    /// If set disable when close the stream, it return immediately but may miss data send in kernel cache,
    /// If set enable when close the stream, the kernel cache will send by kernel until timeout
    /// time unit is second
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// let mut stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.set_liner(true, 10).expect("set_liner call failed");
    /// assert_eq!((true, 10), stream.liner().unwrap());
    /// ```
    pub fn set_liner(&self, enable: bool, time: u16) -> io::Result<()> {
        self.0.set_liner(enable, time)
    }

    /// The method get the socket liner info
    pub fn liner(&self) -> io::Result<(bool, u16)> {
        self.0.liner()
    }

    /// The Method is set stream recv size kernel cache size.
    /// When in linux it will double the size you set, so inner already div double.
    /// It's size will limit by linux limit size set
    /// the unit is byte
    /// # Examples
    ///
    /// ```no_run
    /// use std::cmp;
    /// use psocket::TcpSocket;
    ///
    /// let mut stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.set_recv_size(20480).expect("set_recv_size call failed");
    /// assert!(stream.recv_size().unwrap() <= 20480);
    /// ```
    pub fn set_recv_size(&self, size: u32) -> io::Result<()> {
        self.0.set_recv_size(size)
    }

    /// The Method is get stream recv size kernel cache size.
    pub fn recv_size(&self) -> io::Result<u32> {
        self.0.recv_size()
    }

    /// The Method is set stream send size kernel cache size.
    /// When in linux it will double the size you set, so inner already div double.
    /// It's size will limit by linux limit size set
    /// the unit is byte
    /// # Examples
    ///
    /// ```no_run
    /// use std::cmp;
    /// use psocket::TcpSocket;
    ///
    /// let mut stream = TcpSocket::connect("127.0.0.1:8080")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.set_send_size(20480).expect("set_recv_size call failed");
    /// assert!(stream.send_size().unwrap() <= 20480);
    /// ```
    pub fn set_send_size(&self, size: u32) -> io::Result<()> {
        self.0.set_send_size(size)
    }

    /// The Method is get stream send size kernel cache size.
    pub fn send_size(&self) -> io::Result<u32> {
        self.0.send_size()
    }

    /// The Method is set tcp stream SO_REUSEADDR.
    pub fn set_reuse_addr(&self) -> io::Result<()> {
        self.0.set_reuse_addr()
    }

    /// Creates a new `TcpSocket` which will be bound to the specified
    /// address.
    ///
    /// The returned listener is ready for accepting connections.
    ///
    /// Binding with a port number of 0 will request that the OS assigns a port
    /// to this listener. The port allocated can be queried via the
    /// [`local_addr`] method.
    ///
    /// The address type can be any implementor of [`ToSocketAddrs`] trait. See
    /// its documentation for concrete examples.
    ///
    /// If `addr` yields multiple addresses, `bind` will be attempted with
    /// each of the addresses until one succeeds and returns the listener. If
    /// none of the addresses succeed in creating a listener, the error returned
    /// from the last attempt (the last address) is returned.
    ///
    /// [`local_addr`]: #method.local_addr
    /// [`ToSocketAddrs`]: ../../pscoket/net/trait.ToSocketAddrs.html
    ///
    /// # Examples
    ///
    /// Create a TCP listener bound to `127.0.0.1:80`:
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// let listener = TcpSocket::bind("127.0.0.1:80").unwrap();
    /// ```
    ///
    /// Create a TCP listener bound to `127.0.0.1:80`. If that fails, create a
    /// TCP listener bound to `127.0.0.1:443`:
    ///
    /// ```no_run
    /// use psocket::{SocketAddr, TcpSocket};
    ///
    /// let addrs = [
    ///     SocketAddr::from(([127, 0, 0, 1], 80)),
    ///     SocketAddr::from(([127, 0, 0, 1], 443)),
    /// ];
    /// let listener = TcpSocket::bind(&addrs[..]).unwrap();
    /// ```
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<TcpSocket> {
        super::each_addr(addr, net_imp::TcpSocket::bind).map(TcpSocket)
    }


    /// Accept a new incoming connection from this listener.
    ///
    /// This function will block the calling thread until a new TCP connection
    /// is established. When established, the corresponding [`TcpSocket`] and the
    /// remote peer's address will be returned.
    ///
    /// [`TcpSocket`]: ../../pscoket/net/struct.TcpSocket.html
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// let listener = TcpSocket::bind("127.0.0.1:8080").unwrap();
    /// match listener.accept() {
    ///     Ok((_socket, addr)) => println!("new client: {:?}", addr),
    ///     Err(e) => println!("couldn't get client: {:?}", e),
    /// }
    /// ```
    pub fn accept(&self) -> io::Result<(TcpSocket, SocketAddr)> {
        self.0.accept().map(|(a, b)| (TcpSocket(a), b))
    }

    /// Returns an iterator over the connections being received on this
    /// listener.
    ///
    /// The returned iterator will never return [`None`] and will also not yield
    /// the peer's [`SocketAddr`] structure. Iterating over it is equivalent to
    /// calling [`accept`] in a loop.
    ///
    /// [`None`]: ../../std/option/enum.Option.html#variant.None
    /// [`SocketAddr`]: ../../pscoket/net/enum.SocketAddr.html
    /// [`accept`]: #method.accept
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use psocket::TcpSocket;
    ///
    /// let listener = TcpSocket::bind("127.0.0.1:80").unwrap();
    ///
    /// for stream in listener.incoming() {
    ///     match stream {
    ///         Ok(stream) => {
    ///             println!("new client!");
    ///         }
    ///         Err(e) => { /* connection failed */ }
    ///     }
    /// }
    /// ```
    pub fn incoming(&self) -> Incoming {
        Incoming { listener: self }
    }

    /// It will unclose the tcp socket. When call this method, the tcp socket will be invalid, can't do anything, it need be call in clone func or new_by_fd func
    pub fn unlink(self) -> io::Result<()> {
        self.0.unlink()
    }
}

impl Clone for TcpSocket {
    fn clone(&self) -> TcpSocket {
        TcpSocket(self.0.clone())
    }
}

impl Read for TcpSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.0.read(buf) }
}
impl Write for TcpSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.0.write(buf) }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
impl<'a> Read for &'a TcpSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.0.read(buf) }
}
impl<'a> Write for &'a TcpSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.0.write(buf) }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl AsInner<net_imp::TcpSocket> for TcpSocket {
    fn as_inner(&self) -> &net_imp::TcpSocket { &self.0 }
}

impl FromInner<net_imp::TcpSocket> for TcpSocket {
    fn from_inner(inner: net_imp::TcpSocket) -> TcpSocket { TcpSocket(inner) }
}

impl IntoInner<net_imp::TcpSocket> for TcpSocket {
    fn into_inner(self) -> net_imp::TcpSocket { self.0 }
}

impl fmt::Debug for TcpSocket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<'a> Iterator for Incoming<'a> {
    type Item = io::Result<TcpSocket>;
    fn next(&mut self) -> Option<io::Result<TcpSocket>> {
        Some(self.listener.accept().map(|p| p.0))
    }
}

#[cfg(all(test, not(target_os = "emscripten")))]
mod tests {
    use std::io::ErrorKind;
    use std::io::prelude::*;
    use net::*;
    use std::sync::mpsc::channel;
    use sys_common::AsInner;
    use std::time::{Instant, Duration};
    use std::thread;
    use net::test::{next_test_ip4, next_test_ip6};

    // static IP4_PORT: u16 = 1234;
    // pub fn next_test_ip4() -> SocketAddr {
    //     IP4_PORT = IP4_PORT + 1;
    //     SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), IP4_PORT))
    // }

    // pub fn next_test_ip6() -> SocketAddr {
    //     SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
    //                                     1234, 0, 0))
    // }

    fn each_ip(f: &mut FnMut(SocketAddr)) {
        f(next_test_ip4());
        f(next_test_ip6());
    }

    macro_rules! t {
        ($e:expr) => {
            match $e {
                Ok(t) => t,
                Err(e) => panic!("received error for `{}`: {}", stringify!($e), e),
            }
        }
    }

    #[test]
    fn bind_error() {
        match TcpSocket::bind("1.1.1.1:9999") {
            Ok(..) => panic!(),
            Err(e) =>
                assert_eq!(e.kind(), ErrorKind::AddrNotAvailable),
        }
    }

    #[test]
    fn connect_error() {
        match TcpSocket::connect("0.0.0.0:1") {
            Ok(..) => panic!(),
            Err(e) => assert!(e.kind() == ErrorKind::ConnectionRefused ||
                              e.kind() == ErrorKind::InvalidInput ||
                              e.kind() == ErrorKind::AddrInUse ||
                              e.kind() == ErrorKind::AddrNotAvailable,
                              "bad error: {} {:?}", e, e.kind()),
        }
    }

    #[test]
    fn listen_localhost() {
        let socket_addr = next_test_ip4();
        let listener = t!(TcpSocket::bind(&socket_addr));

        let _t = thread::spawn(move || {
            let mut stream = t!(TcpSocket::connect(&("localhost",
                                                     socket_addr.port())));
            t!(stream.write(&[144]));
        });

        let mut stream = t!(listener.accept()).0;
        let mut buf = [0];
        t!(stream.read(&mut buf));
        assert!(buf[0] == 144);
    }

    #[test]
    fn connect_loopback() {
        each_ip(&mut |addr| {
            let acceptor = t!(TcpSocket::bind(&addr));

            let _t = thread::spawn(move|| {
                let host = match addr {
                    SocketAddr::V4(..) => "127.0.0.1",
                    SocketAddr::V6(..) => "::1",
                };
                let mut stream = t!(TcpSocket::connect(&(host, addr.port())));
                t!(stream.write(&[66]));
            });

            let mut stream = t!(acceptor.accept()).0;
            let mut buf = [0];
            t!(stream.read(&mut buf));
            assert!(buf[0] == 66);
        })
    }

    #[test]
    fn smoke_test() {
        each_ip(&mut |addr| {
            let acceptor = t!(TcpSocket::bind(&addr));

            let (tx, rx) = channel();
            let _t = thread::spawn(move|| {
                let mut stream = t!(TcpSocket::connect(&addr));
                t!(stream.write(&[99]));
                tx.send(t!(stream.local_addr())).unwrap();
            });

            let (mut stream, addr) = t!(acceptor.accept());
            let mut buf = [0];
            t!(stream.read(&mut buf));
            assert!(buf[0] == 99);
            assert_eq!(addr, t!(rx.recv()));
        })
    }

    #[test]
    fn read_eof() {
        each_ip(&mut |addr| {
            let acceptor = t!(TcpSocket::bind(&addr));

            let _t = thread::spawn(move|| {
                let _stream = t!(TcpSocket::connect(&addr));
                // Close
            });

            let mut stream = t!(acceptor.accept()).0;
            let mut buf = [0];
            let nread = t!(stream.read(&mut buf));
            assert_eq!(nread, 0);
            let nread = t!(stream.read(&mut buf));
            assert_eq!(nread, 0);
        })
    }

    #[test]
    fn write_close() {
        each_ip(&mut |addr| {
            let acceptor = t!(TcpSocket::bind(&addr));

            let (tx, rx) = channel();
            let _t = thread::spawn(move|| {
                drop(t!(TcpSocket::connect(&addr)));
                tx.send(()).unwrap();
            });

            let mut stream = t!(acceptor.accept()).0;
            rx.recv().unwrap();
            let buf = [0];
            match stream.write(&buf) {
                Ok(..) => {}
                Err(e) => {
                    assert!(e.kind() == ErrorKind::ConnectionReset ||
                            e.kind() == ErrorKind::BrokenPipe ||
                            e.kind() == ErrorKind::ConnectionAborted,
                            "unknown error: {}", e);
                }
            }
        })
    }

    #[test]
    fn multiple_connect_serial() {
        each_ip(&mut |addr| {
            let max = 10;
            let acceptor = t!(TcpSocket::bind(&addr));

            let _t = thread::spawn(move|| {
                for _ in 0..max {
                    let mut stream = t!(TcpSocket::connect(&addr));
                    t!(stream.write(&[99]));
                }
            });

            for stream in acceptor.incoming().take(max) {
                let mut stream = t!(stream);
                let mut buf = [0];
                t!(stream.read(&mut buf));
                assert_eq!(buf[0], 99);
            }
        })
    }

    #[test]
    fn multiple_connect_interleaved_greedy_schedule() {
        const MAX: usize = 10;
        each_ip(&mut |addr| {
            let acceptor = t!(TcpSocket::bind(&addr));

            let _t = thread::spawn(move|| {
                let acceptor = acceptor;
                for (i, stream) in acceptor.incoming().enumerate().take(MAX) {
                    // Start another thread to handle the connection
                    let _t = thread::spawn(move|| {
                        let mut stream = t!(stream);
                        let mut buf = [0];
                        t!(stream.read(&mut buf));
                        assert!(buf[0] == i as u8);
                    });
                }
            });

            connect(0, addr);
        });

        fn connect(i: usize, addr: SocketAddr) {
            if i == MAX { return }

            let t = thread::spawn(move|| {
                let mut stream = t!(TcpSocket::connect(&addr));
                // Connect again before writing
                connect(i + 1, addr);
                t!(stream.write(&[i as u8]));
            });
            t.join().ok().unwrap();
        }
    }

    #[test]
    fn multiple_connect_interleaved_lazy_schedule() {
        const MAX: usize = 10;
        each_ip(&mut |addr| {
            let acceptor = t!(TcpSocket::bind(&addr));

            let _t = thread::spawn(move|| {
                for stream in acceptor.incoming().take(MAX) {
                    // Start another thread to handle the connection
                    let _t = thread::spawn(move|| {
                        let mut stream = t!(stream);
                        let mut buf = [0];
                        t!(stream.read(&mut buf));
                        assert!(buf[0] == 99);
                    });
                }
            });

            connect(0, addr);
        });

        fn connect(i: usize, addr: SocketAddr) {
            if i == MAX { return }

            let t = thread::spawn(move|| {
                let mut stream = t!(TcpSocket::connect(&addr));
                connect(i + 1, addr);
                t!(stream.write(&[99]));
            });
            t.join().ok().unwrap();
        }
    }

    #[test]
    fn socket_and_peer_name() {
        each_ip(&mut |addr| {
            let listener = t!(TcpSocket::bind(&addr));
            let so_name = t!(listener.local_addr());
            assert_eq!(addr, so_name);
            let _t = thread::spawn(move|| {
                t!(listener.accept());
            });

            let stream = t!(TcpSocket::connect(&addr));
            assert_eq!(addr, t!(stream.peer_addr()));
        })
    }

    #[test]
    fn partial_read() {
        each_ip(&mut |addr| {
            let (tx, rx) = channel();
            let srv = t!(TcpSocket::bind(&addr));
            let _t = thread::spawn(move|| {
                let mut cl = t!(srv.accept()).0;
                cl.write(&[10]).unwrap();
                let mut b = [0];
                t!(cl.read(&mut b));
                tx.send(()).unwrap();
            });

            let mut c = t!(TcpSocket::connect(&addr));
            let mut b = [0; 10];
            assert_eq!(c.read(&mut b).unwrap(), 1);
            t!(c.write(&[1]));
            rx.recv().unwrap();
        })
    }

    #[test]
    fn double_bind() {
        each_ip(&mut |addr| {
            let _listener = t!(TcpSocket::bind(&addr));
            match TcpSocket::bind(&addr) {
                Ok(..) => panic!(),
                Err(e) => {
                    assert!(e.kind() == ErrorKind::ConnectionRefused ||
                            e.kind() == ErrorKind::Other ||
                            e.kind() == ErrorKind::AddrInUse,
                            "unknown error: {} {:?}", e, e.kind());
                }
            }
        })
    }

    #[test]
    fn fast_rebind() {
        each_ip(&mut |addr| {
            let acceptor = t!(TcpSocket::bind(&addr));

            let _t = thread::spawn(move|| {
                t!(TcpSocket::connect(&addr));
            });

            t!(acceptor.accept());
            drop(acceptor);
            t!(TcpSocket::bind(&addr));
        });
    }

    #[test]
    fn tcp_clone_smoke() {
        each_ip(&mut |addr| {
            let acceptor = t!(TcpSocket::bind(&addr));

            let _t = thread::spawn(move|| {
                let mut s = t!(TcpSocket::connect(&addr));
                let mut buf = [0, 0];
                assert_eq!(s.read(&mut buf).unwrap(), 1);
                assert_eq!(buf[0], 1);
                t!(s.write(&[2]));
            });

            let mut s1 = t!(acceptor.accept()).0;
            let s2 = t!(s1.try_clone());

            let (tx1, rx1) = channel();
            let (tx2, rx2) = channel();
            let _t = thread::spawn(move|| {
                let mut s2 = s2;
                rx1.recv().unwrap();
                t!(s2.write(&[1]));
                tx2.send(()).unwrap();
            });
            tx1.send(()).unwrap();
            let mut buf = [0, 0];
            assert_eq!(s1.read(&mut buf).unwrap(), 1);
            rx2.recv().unwrap();
        })
    }

    #[test]
    fn tcp_clone_two_read() {
        each_ip(&mut |addr| {
            let acceptor = t!(TcpSocket::bind(&addr));
            let (tx1, rx) = channel();
            let tx2 = tx1.clone();

            let _t = thread::spawn(move|| {
                let mut s = t!(TcpSocket::connect(&addr));
                t!(s.write(&[1]));
                rx.recv().unwrap();
                t!(s.write(&[2]));
                rx.recv().unwrap();
            });

            let mut s1 = t!(acceptor.accept()).0;
            let s2 = t!(s1.try_clone());

            let (done, rx) = channel();
            let _t = thread::spawn(move|| {
                let mut s2 = s2;
                let mut buf = [0, 0];
                t!(s2.read(&mut buf));
                tx2.send(()).unwrap();
                done.send(()).unwrap();
            });
            let mut buf = [0, 0];
            t!(s1.read(&mut buf));
            tx1.send(()).unwrap();

            rx.recv().unwrap();
        })
    }

    #[test]
    fn tcp_clone_two_write() {
        each_ip(&mut |addr| {
            let acceptor = t!(TcpSocket::bind(&addr));

            let _t = thread::spawn(move|| {
                let mut s = t!(TcpSocket::connect(&addr));
                let mut buf = [0, 1];
                t!(s.read(&mut buf));
                t!(s.read(&mut buf));
            });

            let mut s1 = t!(acceptor.accept()).0;
            let s2 = t!(s1.try_clone());

            let (done, rx) = channel();
            let _t = thread::spawn(move|| {
                let mut s2 = s2;
                t!(s2.write(&[1]));
                done.send(()).unwrap();
            });
            t!(s1.write(&[2]));

            rx.recv().unwrap();
        })
    }

    #[test]
    fn shutdown_smoke() {
        each_ip(&mut |addr| {
            let a = t!(TcpSocket::bind(&addr));
            let _t = thread::spawn(move|| {
                let mut c = t!(a.accept()).0;
                let mut b = [0];
                assert_eq!(c.read(&mut b).unwrap(), 0);
                t!(c.write(&[1]));
            });

            let mut s = t!(TcpSocket::connect(&addr));
            t!(s.shutdown(Shutdown::Write));
            assert!(s.write(&[1]).is_err());
            let mut b = [0, 0];
            assert_eq!(t!(s.read(&mut b)), 1);
            assert_eq!(b[0], 1);
        })
    }

    #[test]
    fn close_readwrite_smoke() {
        each_ip(&mut |addr| {
            let a = t!(TcpSocket::bind(&addr));
            let (tx, rx) = channel::<()>();
            let _t = thread::spawn(move|| {
                let _s = t!(a.accept());
                let _ = rx.recv();
            });

            let mut b = [0];
            let mut s = t!(TcpSocket::connect(&addr));
            let mut s2 = t!(s.try_clone());

            // closing should prevent reads/writes
            t!(s.shutdown(Shutdown::Write));
            assert!(s.write(&[0]).is_err());
            t!(s.shutdown(Shutdown::Read));
            assert_eq!(s.read(&mut b).unwrap(), 0);

            // closing should affect previous handles
            assert!(s2.write(&[0]).is_err());
            assert_eq!(s2.read(&mut b).unwrap(), 0);

            // closing should affect new handles
            let mut s3 = t!(s.try_clone());
            assert!(s3.write(&[0]).is_err());
            assert_eq!(s3.read(&mut b).unwrap(), 0);

            // make sure these don't die
            let _ = s2.shutdown(Shutdown::Read);
            let _ = s2.shutdown(Shutdown::Write);
            let _ = s3.shutdown(Shutdown::Read);
            let _ = s3.shutdown(Shutdown::Write);
            drop(tx);
        })
    }

    #[test]
    #[cfg(unix)] // test doesn't work on Windows, see #31657
    fn close_read_wakes_up() {
        each_ip(&mut |addr| {
            let a = t!(TcpSocket::bind(&addr));
            let (tx1, rx) = channel::<()>();
            let _t = thread::spawn(move|| {
                let _s = t!(a.accept());
                let _ = rx.recv();
            });

            let s = t!(TcpSocket::connect(&addr));
            let s2 = t!(s.try_clone());
            let (tx, rx) = channel();
            let _t = thread::spawn(move|| {
                let mut s2 = s2;
                assert_eq!(t!(s2.read(&mut [0])), 0);
                tx.send(()).unwrap();
            });
            // this should wake up the child thread
            t!(s.shutdown(Shutdown::Read));

            // this test will never finish if the child doesn't wake up
            rx.recv().unwrap();
            drop(tx1);
        })
    }

    #[test]
    fn clone_while_reading() {
        each_ip(&mut |addr| {
            let accept = t!(TcpSocket::bind(&addr));

            // Enqueue a thread to write to a socket
            let (tx, rx) = channel();
            let (txdone, rxdone) = channel();
            let txdone2 = txdone.clone();
            let _t = thread::spawn(move|| {
                let mut tcp = t!(TcpSocket::connect(&addr));
                rx.recv().unwrap();
                t!(tcp.write(&[0]));
                txdone2.send(()).unwrap();
            });

            // Spawn off a reading clone
            let tcp = t!(accept.accept()).0;
            let tcp2 = t!(tcp.try_clone());
            let txdone3 = txdone.clone();
            let _t = thread::spawn(move|| {
                println!("tcp2 = {:?}", tcp2);
                let mut tcp2 = tcp2;
                println!("tcp2 = {:?}", tcp2);
                t!(tcp2.read(&mut [0]));
                txdone3.send(()).unwrap();
            });

            // Try to ensure that the reading clone is indeed reading
            for _ in 0..50 {
                thread::yield_now();
            }

            // clone the handle again while it's reading, then let it finish the
            // read.
            let _ = t!(tcp.try_clone());
            tx.send(()).unwrap();
            rxdone.recv().unwrap();
            rxdone.recv().unwrap();
        })
    }

    #[test]
    fn clone_accept_smoke() {
        each_ip(&mut |addr| {
            let a = t!(TcpSocket::bind(&addr));
            let a2 = t!(a.try_clone());

            let _t = thread::spawn(move|| {
                let _ = TcpSocket::connect(&addr);
            });
            let _t = thread::spawn(move|| {
                let _ = TcpSocket::connect(&addr);
            });

            t!(a.accept());
            t!(a2.accept());
        })
    }

    #[test]
    fn clone_accept_concurrent() {
        each_ip(&mut |addr| {
            let a = t!(TcpSocket::bind(&addr));
            let a2 = t!(a.try_clone());

            let (tx, rx) = channel();
            let tx2 = tx.clone();

            let _t = thread::spawn(move|| {
                tx.send(t!(a.accept())).unwrap();
            });
            let _t = thread::spawn(move|| {
                tx2.send(t!(a2.accept())).unwrap();
            });

            let _t = thread::spawn(move|| {
                let _ = TcpSocket::connect(&addr);
            });
            let _t = thread::spawn(move|| {
                let _ = TcpSocket::connect(&addr);
            });

            rx.recv().unwrap();
            rx.recv().unwrap();
        })
    }

    #[test]
    fn debug() {
        let name = if cfg!(windows) {"socket"} else {"fd"};
        let socket_addr = next_test_ip4();

        let listener = t!(TcpSocket::bind(&socket_addr));
        let listener_inner = listener.0.socket().as_inner();
        let compare = format!("TcpSocket {{ addr: {:?}, {}: {:?}, ready: {:?} }}",
                              socket_addr, name, listener_inner, listener.is_ready());
        assert_eq!(format!("{:?}", listener), compare);

        let stream = t!(TcpSocket::connect(&("localhost",
                                                 socket_addr.port())));
        let stream_inner = stream.0.socket().as_inner();
        let compare = format!("TcpSocket {{ addr: {:?}, \
                              peer: {:?}, {}: {:?}, ready: {:?} }}",
                              stream.local_addr().unwrap(),
                              stream.peer_addr().unwrap(),
                              name,
                              stream_inner,
                              stream.is_ready());
        assert_eq!(format!("{:?}", stream), compare);
    }

    // FIXME: re-enabled bitrig/openbsd tests once their socket timeout code
    //        no longer has rounding errors.
    #[cfg_attr(any(target_os = "bitrig", target_os = "netbsd", target_os = "openbsd"), ignore)]
    #[test]
    fn timeouts() {
        let addr = next_test_ip4();
        let listener = t!(TcpSocket::bind(&addr));

        let stream = t!(TcpSocket::connect(&("localhost", addr.port())));
        let dur = Duration::new(15410, 0);

        assert_eq!(None, t!(stream.read_timeout()));

        t!(stream.set_read_timeout(Some(dur)));
        assert_eq!(Some(dur), t!(stream.read_timeout()));

        assert_eq!(None, t!(stream.write_timeout()));

        t!(stream.set_write_timeout(Some(dur)));
        assert_eq!(Some(dur), t!(stream.write_timeout()));

        t!(stream.set_read_timeout(None));
        assert_eq!(None, t!(stream.read_timeout()));

        t!(stream.set_write_timeout(None));
        assert_eq!(None, t!(stream.write_timeout()));
        drop(listener);
    }

    #[test]
    fn test_read_timeout() {
        let addr = next_test_ip4();
        let listener = t!(TcpSocket::bind(&addr));

        let mut stream = t!(TcpSocket::connect(&("localhost", addr.port())));
        t!(stream.set_read_timeout(Some(Duration::from_millis(1000))));

        let mut buf = [0; 10];
        let start = Instant::now();
        let kind = stream.read(&mut buf).err().expect("expected error").kind();
        assert!(kind == ErrorKind::WouldBlock || kind == ErrorKind::TimedOut);
        assert!(start.elapsed() > Duration::from_millis(400));
        drop(listener);
    }

    #[test]
    fn test_read_with_timeout() {
        let addr = next_test_ip4();
        let listener = t!(TcpSocket::bind(&addr));

        let mut stream = t!(TcpSocket::connect(&("localhost", addr.port())));
        t!(stream.set_read_timeout(Some(Duration::from_millis(1000))));

        let mut other_end = t!(listener.accept()).0;
        t!(other_end.write_all(b"hello world"));

        let mut buf = [0; 11];
        t!(stream.read(&mut buf));
        assert_eq!(b"hello world", &buf[..]);

        let start = Instant::now();
        let kind = stream.read(&mut buf).err().expect("expected error").kind();
        assert!(kind == ErrorKind::WouldBlock || kind == ErrorKind::TimedOut);
        assert!(start.elapsed() > Duration::from_millis(400));
        drop(listener);
    }

    #[test]
    fn nodelay() {
        let addr = next_test_ip4();
        let _listener = t!(TcpSocket::bind(&addr));

        let stream = t!(TcpSocket::connect(&("localhost", addr.port())));

        assert_eq!(false, t!(stream.nodelay()));
        t!(stream.set_nodelay(true));
        assert_eq!(true, t!(stream.nodelay()));
        t!(stream.set_nodelay(false));
        assert_eq!(false, t!(stream.nodelay()));
    }

    #[test]
    fn ttl() {
        let ttl = 100;

        let addr = next_test_ip4();
        let listener = t!(TcpSocket::bind(&addr));

        t!(listener.set_ttl(ttl));
        assert_eq!(ttl, t!(listener.ttl()));

        let stream = t!(TcpSocket::connect(&("localhost", addr.port())));

        t!(stream.set_ttl(ttl));
        assert_eq!(ttl, t!(stream.ttl()));
    }

    #[test]
    fn set_nonblocking() {
        let addr = next_test_ip4();
        let mut listener = t!(TcpSocket::bind(&addr));

        t!(listener.set_nonblocking(true));
        t!(listener.set_nonblocking(false));

        let mut stream = t!(TcpSocket::connect(&("localhost", addr.port())));

        t!(stream.set_nonblocking(false));
        t!(stream.set_nonblocking(true));

        let mut buf = [0];
        match stream.read(&mut buf) {
            Ok(_) => panic!("expected error"),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => panic!("unexpected error {}", e),
        }
    }

    #[test]
    fn peek() {
        each_ip(&mut |addr| {
            let (txdone, rxdone) = channel();

            let srv = t!(TcpSocket::bind(&addr));
            let _t = thread::spawn(move|| {
                let mut cl = t!(srv.accept()).0;
                cl.write(&[1,3,3,7]).unwrap();
                t!(rxdone.recv());
            });

            let mut c = t!(TcpSocket::connect(&addr));
            let mut b = [0; 10];
            for _ in 1..3 {
                let len = c.peek(&mut b).unwrap();
                assert_eq!(len, 4);
            }
            let len = c.read(&mut b).unwrap();
            assert_eq!(len, 4);

            t!(c.set_nonblocking(true));
            match c.peek(&mut b) {
                Ok(_) => panic!("expected error"),
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => panic!("unexpected error {}", e),
            }
            t!(txdone.send(()));
        })
    }

    #[test]
    fn connect_timeout_unroutable() {
        // this IP is unroutable, so connections should always time out,
        // provided the network is reachable to begin with.
        let addr = "10.255.255.1:80".parse().unwrap();
        let e = TcpSocket::connect_timeout(&addr, Duration::from_millis(250)).unwrap_err();
        assert!(e.kind() == io::ErrorKind::TimedOut ||
                e.kind() == io::ErrorKind::Other,
                "bad error: {} {:?}", e, e.kind());
    }

    #[test]
    fn connect_timeout_unbound() {
        // bind and drop a socket to track down a "probably unassigned" port
        let socket = TcpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);

        let timeout = Duration::from_secs(1);
        let e = TcpSocket::connect_timeout(&addr, timeout).unwrap_err();
        assert!(e.kind() == io::ErrorKind::ConnectionRefused ||
                e.kind() == io::ErrorKind::TimedOut ||
                e.kind() == io::ErrorKind::Other,
                "bad error: {} {:?}", e, e.kind());
    }

    #[test]
    fn connect_timeout_valid() {
        let listener = TcpSocket::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        TcpSocket::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    }
}
