extern crate psocket;

use psocket::TcpSocket;
use std::io::prelude::*;
use std::time::{Duration, Instant};
use std::io::ErrorKind;


fn main() {

    // bind and drop a socket to track down a "probably unassigned" port
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

    // socket.set_liner(true, 10);
    // assert_eq!((true, 10), socket.liner().unwrap());

    // socket.set_recv_size(20480);
    // assert_eq!(20480, socket.recv_size().unwrap());
    
    // socket.set_send_size(40960);
    // assert_eq!(40960, socket.send_size().unwrap());
    
    // let mut new_socket = socket.clone();
    // assert_eq!(20480, new_socket.recv_size().unwrap());
    
    // new_socket.unlink();    
    // drop(new_socket);
    // assert_eq!(20480, socket.recv_size().unwrap());
    
    // let new_socket = socket.clone();
    // drop(new_socket);
    // assert!(socket.recv_size().is_err());

    // println!("finish");
    // let addr = "www.baidu.com:80".to_socket_addrs().unwrap().next().unwrap();
    // // drop(socket);

    // println!("addr = {:?}", addr);

    // let timeout = Duration::from_secs(1);
    // let mut e = TcpSocket::connect_asyn(&addr).unwrap();
    // loop {
    //     println!("e = {:?}", e);
    //     println!("e.check_ready() = {:?}", e.check_ready().unwrap());
    //     if e.is_ready() {
    //         break;
    //     }
    // }
    // println!("e = {:?}", e);
    // assert!(e.kind() == io::ErrorKind::ConnectionRefused ||
    //         e.kind() == io::ErrorKind::TimedOut ||
    //         e.kind() == io::ErrorKind::Other,
    //         "bad error: {} {:?}", e, e.kind());
}