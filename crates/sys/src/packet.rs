// SPDX-License-Identifier: Apache-2.0
//! Packet sockets (`AF_PACKET`), which `rustix` has no address type for,
//! and the options of sockets that it has no call for.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// A raw packet socket for every protocol (`ETH_P_ALL`), close-on-exec and
/// bound to the link with the index `ifindex`.
pub fn bound_socket(ifindex: u32) -> io::Result<OwnedFd> {
    let proto = (libc::ETH_P_ALL as u16).to_be();
    // SAFETY: socket takes integers.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            i32::from(proto),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a new descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: an all-zero sockaddr_ll is a valid value of plain data.
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = proto;
    addr.sll_ifindex = ifindex as i32;
    // SAFETY: bind reads `addr`, a local of the size given, and the socket
    // is open for the call.
    let r = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Restrict the socket `fd` to the interface `name` (`SO_BINDTODEVICE`):
/// it sends and receives on that interface only.  Needs `CAP_NET_RAW`.
pub fn bind_to_device(fd: BorrowedFd<'_>, name: &str) -> io::Result<()> {
    // SAFETY: setsockopt reads `name.len()` bytes of the name, which lives
    // through the call, and the socket is open.
    let r = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.len() as u32,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Let the socket `fd` bind to an address that is not one of the host's,
/// and send from it (`IP_TRANSPARENT`): the address routed to the host by a
/// route of type local only.  Needs `CAP_NET_ADMIN` or `CAP_NET_RAW` (once
/// set, the socket keeps it).
pub fn set_transparent(fd: BorrowedFd<'_>) -> io::Result<()> {
    let on: libc::c_int = 1;
    // SAFETY: setsockopt reads the int `on`, which lives through the call,
    // and the socket is open.
    let r = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            (&on as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as u32,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Turn off the transmit checksum offload (and with it the segmentation
/// offloads) of the interface `name`: what its stack sends has its checksums
/// complete, as a packet socket that reads the frames (and gives them to
/// another host) needs.  Needs `CAP_NET_ADMIN`.
pub fn tx_checksum_off(name: &str) -> io::Result<()> {
    #[repr(C)]
    struct EthtoolValue {
        cmd: u32,
        data: u32,
    }
    const ETHTOOL_STXCSUM: u32 = 0x17;
    let sock = rustix::net::socket_with(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::DGRAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )?;
    let mut value = EthtoolValue {
        cmd: ETHTOOL_STXCSUM,
        data: 0,
    };
    // SAFETY: an all-zero ifreq is a valid value of plain data.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    if name.len() >= request.ifr_name.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "an interface name that is too long",
        ));
    }
    for (to, from) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *to = from as libc::c_char;
    }
    request.ifr_ifru.ifru_data = (&mut value as *mut EthtoolValue).cast();
    // SAFETY: SIOCETHTOOL reads the ifreq, a local, and the ethtool value
    // it points to, which lives through the call; the socket is open.
    let r = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCETHTOOL as _, &mut request) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// What `recv_frame` read: the length of the frame, and its packet type
/// (`PACKET_HOST` 0, ..., `PACKET_OUTGOING` 4).
pub struct Frame {
    pub len: usize,
    pub packet_type: u8,
}

/// Read one frame of the packet socket `fd` into `buf` (`recvfrom`; a
/// socket that is non blocking gives `WouldBlock`).
pub fn recv_frame(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<Frame> {
    // SAFETY: an all-zero sockaddr_ll is a valid value of plain data.
    let mut from: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    let mut from_len = std::mem::size_of::<libc::sockaddr_ll>() as u32;
    // SAFETY: recvfrom writes at most `buf.len()` bytes into `buf` and at
    // most `from_len` into the local address; the socket is open for the call.
    let n = unsafe {
        libc::recvfrom(
            fd.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
            &mut from as *mut libc::sockaddr_ll as *mut libc::sockaddr,
            &mut from_len,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Frame {
        len: n as usize,
        packet_type: from.sll_pkttype,
    })
}
