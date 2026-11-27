// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The network devices an XDP upatch runs on: what rtnetlink, the devlink
//! and netdev generic netlink families and the ethtool ioctl say of each,
//! the class an upatch selects it by, the XDP program it runs and whether
//! its driver can run one; and what a failed attach says.

use core::ffi::{CStr, c_int};
use core::sync::atomic::{AtomicU16, Ordering};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use crate::errno::{
    E2BIG, EACCES, EAGAIN, EBADMSG, EINVAL, EMEDIUMTYPE, EMFILE, ENFILE, ENOBUFS, ENODEV, ENOMEM,
    ENOPROTOOPT, ENOSPC, ENOTTY, EOPNOTSUPP, EPERM, ERANGE, EREMOTE, ETIMEDOUT, EXDEV, last_errno,
};
use crate::sys::libc;
use crate::util::upatch::{XDP_NETWORK, XDP_UNKNOWN, XDP_VIRTUAL, XDP_VM};

/// `XDP_IFNAME_MAX`: a device's name and its terminator.
pub(crate) const IFNAME_MAX: usize = 16;

/// What shirudo makes of a failed XDP attach, `enum xdp_attach_err`:
/// positive, so that no errno a lookup or the kernel returns along the way
/// can be read as one of them.
/// The driver has no native XDP: the device is passed over.
pub(crate) const ERR_NO_NATIVE: c_int = 1;
/// Every XDP program is loaded with frags, so the device must report them.
pub(crate) const ERR_NO_MULTIBUF: c_int = 2;
/// A driver with native XDP that rules it out in its current settings.
pub(crate) const ERR_DRIVER_SETTINGS: c_int = 3;
/// The device runs another XDP program: the link create says so.
pub(crate) const ERR_OCCUPIED: c_int = 4;
/// The kernel made the link for another device.
pub(crate) const ERR_LINK_SCOPE: c_int = 5;

const NETLINK_BUFFER_SIZE: usize = 65536;
const DEVICES_READ_ATTEMPTS: u32 = 5;
const REQUEST_MAX: usize = NLMSG_HDRLEN + 512;

const NLA_HDRLEN: usize = 4;
const NLA_TYPE_MASK: u16 = 0x3fff;
const NLMSG_HDRLEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_MULTI: u16 = 2;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLMSGERR_LEN: usize = 20;
const NETLINK_ROUTE: c_int = 0;
const NETLINK_GENERIC: c_int = 16;

const RTM_GETLINK: u16 = 18;
const IFINFOMSG_LEN: usize = 16;
const IFLA_IFNAME: u16 = 3;
const IFLA_LINK: u16 = 5;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_LINK_NETNSID: u16 = 37;
const IFLA_XDP: u16 = 43;
const IFLA_XDP_DRV_PROG_ID: u16 = 5;
const IFLA_XDP_SKB_PROG_ID: u16 = 6;
const IFLA_XDP_HW_PROG_ID: u16 = 7;
const IFLA_PARENT_DEV_BUS_NAME: u16 = 57;
const IFLA_DEVLINK_PORT: u16 = 62;
const IFF_LOOPBACK: u32 = 8;

const GENL_HDRLEN: usize = 4;
const GENL_ID_CTRL: u16 = 16;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const DEVLINK_GENL_NAME: &CStr = c"devlink";
const DEVLINK_GENL_VERSION: u8 = 1;
const DEVLINK_CMD_PORT_GET: u8 = 5;
const DEVLINK_ATTR_BUS_NAME: u16 = 1;
const DEVLINK_ATTR_DEV_NAME: u16 = 2;
const DEVLINK_ATTR_PORT_INDEX: u16 = 3;
const DEVLINK_ATTR_PORT_FLAVOUR: u16 = 77;
const FLAVOUR_PHYSICAL: u16 = 0;
const FLAVOUR_CPU: u16 = 1;
const FLAVOUR_DSA: u16 = 2;
const FLAVOUR_PCI_PF: u16 = 3;
const FLAVOUR_PCI_VF: u16 = 4;
const FLAVOUR_VIRTUAL: u16 = 5;
const FLAVOUR_PCI_SF: u16 = 7;

const NETDEV_FAMILY_NAME: &CStr = c"netdev";
const NETDEV_FAMILY_VERSION: u8 = 1;
const NETDEV_CMD_DEV_GET: u8 = 1;
const NETDEV_A_DEV_IFINDEX: u16 = 1;
const NETDEV_A_DEV_XDP_FEATURES: u16 = 3;
const NETDEV_XDP_ACT_BASIC: u64 = 1;
const NETDEV_XDP_ACT_RX_SG: u64 = 32;

const SIOCGIFINDEX: core::ffi::c_ulong = 0x8933;
const SIOCETHTOOL: core::ffi::c_ulong = 0x8946;
const ETHTOOL_GDRVINFO: u32 = 3;
const DRVINFO_LEN: usize = 196;
const DRVINFO_DRIVER: usize = 4;

/// The initial network namespace's cookie, NET_NS_INIT_ID of linux/nsfs.h.
const NET_NS_INIT_COOKIE: u64 = 7;
const SO_NETNS_COOKIE: c_int = 71;

/// `struct xdp_device`: what discovery tells of one network device.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct XdpDevice {
    pub(crate) devlink_device: [u8; 128],
    pub(crate) devlink_bus: [u8; 128],
    pub(crate) parent_bus: [u8; 64],
    pub(crate) kind: [u8; 64],
    pub(crate) driver: [u8; 32],
    pub(crate) name: [u8; IFNAME_MAX],
    pub(crate) ifindex: u32,
    pub(crate) peer_ifindex: u32,
    /// The driver-mode XDP program it runs, and a generic or offloaded one.
    pub(crate) xdp_drv_id: u32,
    pub(crate) xdp_other_id: u32,
    /// Why the driver or devlink facts could not be read, or 0.
    pub(crate) unclassified_err: c_int,
    pub(crate) flags: u32,
    pub(crate) port_index: u32,
    pub(crate) port_flavour: u16,
    pub(crate) peer_other_netns: bool,
    pub(crate) devlink_port: bool,
    pub(crate) unresolved: bool,
}

const _: () = assert!(size_of::<XdpDevice>() == 468);

/// The bytes of a C string field, up to its terminator.
fn text(field: &[u8]) -> &[u8] {
    crate::text::cstr(field)
}

impl XdpDevice {
    /// A device of nothing known, with no devlink port flavour.
    pub(crate) fn empty() -> Self {
        XdpDevice {
            devlink_device: [0; 128],
            devlink_bus: [0; 128],
            parent_bus: [0; 64],
            kind: [0; 64],
            driver: [0; 32],
            name: [0; IFNAME_MAX],
            ifindex: 0,
            peer_ifindex: 0,
            xdp_drv_id: 0,
            xdp_other_id: 0,
            unclassified_err: 0,
            flags: 0,
            port_index: 0,
            port_flavour: u16::MAX,
            peer_other_netns: false,
            devlink_port: false,
            unresolved: false,
        }
    }

    pub(crate) fn name(&self) -> &[u8] {
        text(&self.name)
    }

    /// The class an upatch selects the device by, 0 for loopback.
    pub(crate) fn class(&self) -> u32 {
        const VM_DRIVERS: [&[u8]; 5] = [
            b"virtio_net",
            b"vmxnet3",
            b"hv_netvsc",
            b"xen-netfront",
            b"vif",
        ];
        let driver = text(&self.driver);

        if self.flags & IFF_LOOPBACK != 0 {
            return 0;
        }
        // netback is "vif" too: in dom0 it is the host end of a guest's link.
        if text(&self.parent_bus) == b"xen-backend" {
            return XDP_VIRTUAL;
        }
        if VM_DRIVERS.contains(&driver) {
            return XDP_VM;
        }
        // Its ports are simulated, whatever flavour they claim.
        if driver == b"netdevsim" {
            return XDP_VIRTUAL;
        }
        if self.devlink_port {
            return match self.port_flavour {
                FLAVOUR_PHYSICAL => XDP_NETWORK,
                FLAVOUR_CPU | FLAVOUR_DSA | FLAVOUR_PCI_PF | FLAVOUR_PCI_VF | FLAVOUR_VIRTUAL
                | FLAVOUR_PCI_SF => XDP_VIRTUAL,
                _ => XDP_UNKNOWN,
            };
        }
        if self.parent_bus[0] != 0 {
            return XDP_NETWORK;
        }
        if self.kind[0] != 0 {
            return XDP_VIRTUAL;
        }
        XDP_UNKNOWN
    }

    /// The program the device runs, 0 for none. shirudo attaches in
    /// driver mode only, so a generic or offloaded program is another's.
    pub(crate) fn attached(&self) -> u32 {
        if self.xdp_drv_id != 0 {
            self.xdp_drv_id
        } else {
            self.xdp_other_id
        }
    }
}

/// Whether devs[index] is one an upatch of class `mask` runs on: of the
/// class, its facts read, and of the two ends of a veth pair in this
/// namespace, the one of the lower ifindex alone.
pub(crate) fn selected(devs: &[XdpDevice], index: usize, mask: u32) -> bool {
    let dev = &devs[index];

    if dev.unresolved || dev.class() & mask == 0 {
        return false;
    }
    if text(&dev.kind) != b"veth" || dev.peer_other_netns {
        return true;
    }
    devs.iter()
        .find(|peer| {
            peer.ifindex != dev.ifindex
                && peer.ifindex == dev.peer_ifindex
                && peer.peer_ifindex == dev.ifindex
                && !peer.peer_other_netns
                && !peer.unresolved
                && text(&peer.kind) == b"veth"
        })
        .is_some_and(|peer| dev.ifindex < peer.ifindex)
}

/// `enum xdp_reconcile`: what reconcile does of a device.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reconcile {
    None,
    Covered,
    Attach,
    Occupied,
}

/// `attached` is what the device runs now, 0 for nothing.
pub(crate) fn reconcile_action(selected: bool, attached: u32, prog_id: u32) -> Reconcile {
    match (selected, attached) {
        (false, _) => Reconcile::None,
        (true, 0) => Reconcile::Attach,
        (true, id) if id == prog_id => Reconcile::Covered,
        (true, _) => Reconcile::Occupied,
    }
}

/// The attributes of a netlink message, from `data` on.
#[derive(Clone, Copy)]
struct Attrs<'a>(&'a [u8]);

fn nla_align(len: usize) -> usize {
    (len + 3) & !3
}

impl<'a> Attrs<'a> {
    /// The payload of the attribute of type `ty`, None without one;
    /// -EINVAL for a malformed list or the type given twice.
    fn find(self, ty: u16) -> Result<Option<&'a [u8]>, c_int> {
        let mut rest = self.0;
        let mut found = None;

        while !rest.is_empty() {
            if rest.len() < NLA_HDRLEN {
                return Err(-EINVAL);
            }
            let len = usize::from(u16::from_ne_bytes([rest[0], rest[1]]));
            let kind = u16::from_ne_bytes([rest[2], rest[3]]);
            if len < NLA_HDRLEN || len > rest.len() {
                return Err(-EINVAL);
            }
            let step = nla_align(len);
            if step > rest.len() {
                return Err(-EINVAL);
            }
            if kind & NLA_TYPE_MASK == ty {
                if found.is_some() {
                    return Err(-EINVAL);
                }
                found = Some(&rest[NLA_HDRLEN..len]);
            }
            rest = &rest[step..];
        }
        Ok(found)
    }

    /// The string attribute `ty` into `out`, its terminator with it: a
    /// value of at most `out.len()` bytes, NUL-terminated and with no NUL
    /// before, or -EINVAL. `out` is left as it was without one.
    fn string(self, ty: u16, out: &mut [u8]) -> Result<(), c_int> {
        let Some(value) = self.find(ty)? else {
            return Ok(());
        };
        let size = value.len();
        if size == 0 || size > out.len() || value[size - 1] != 0 || value[..size - 1].contains(&0) {
            return Err(-EINVAL);
        }
        out[..size].copy_from_slice(value);
        Ok(())
    }

    /// The number attribute `ty` of exactly N bytes, None without one.
    fn number<const N: usize>(self, ty: u16) -> Result<Option<[u8; N]>, c_int> {
        match self.find(ty)? {
            None => Ok(None),
            Some(v) if v.len() == N => Ok(Some(v.try_into().map_err(|_| -EINVAL)?)),
            Some(_) => Err(-EINVAL),
        }
    }

    fn u32(self, ty: u16) -> Result<Option<u32>, c_int> {
        Ok(self.number::<4>(ty)?.map(u32::from_ne_bytes))
    }
}

/// A netlink request of at most 512 bytes after its header.
struct Request(Vec<u8>);

impl Request {
    fn new(ty: u16, flags: u16, body: &[u8]) -> Self {
        let mut msg = vec![0u8; NLMSG_HDRLEN];

        msg[4..6].copy_from_slice(&ty.to_ne_bytes());
        msg[6..8].copy_from_slice(&flags.to_ne_bytes());
        msg.extend_from_slice(body);
        let mut r = Request(msg);
        r.set_len();
        r
    }

    /// A generic netlink request of command `cmd`.
    fn genl(family: u16, cmd: u8, version: u8) -> Self {
        Self::new(family, NLM_F_REQUEST, &[cmd, version, 0, 0])
    }

    fn set_len(&mut self) {
        let len = self.0.len() as u32;
        self.0[..4].copy_from_slice(&len.to_ne_bytes());
    }

    /// An attribute of `ty` holding `data`, or -E2BIG past the room.
    fn put(&mut self, ty: u16, data: &[u8]) -> Result<(), c_int> {
        let size = NLA_HDRLEN + data.len();
        let end = self.0.len() + nla_align(size);

        if end > REQUEST_MAX || size > usize::from(u16::MAX) {
            return Err(-E2BIG);
        }
        self.0.extend_from_slice(&(size as u16).to_ne_bytes());
        self.0.extend_from_slice(&ty.to_ne_bytes());
        self.0.extend_from_slice(data);
        self.0.resize(end, 0);
        self.set_len();
        Ok(())
    }
}

/// A socket, closed by its owner on every return.
fn open_socket(domain: c_int, kind: c_int, protocol: c_int) -> Result<OwnedFd, c_int> {
    // SAFETY: socket(2) takes numbers.
    let fd = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, protocol) };
    if fd < 0 {
        return Err(last_errno());
    }
    // SAFETY: socket returned a new descriptor owned here alone.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The request sent on a netlink socket of `protocol`, and each message
/// of the answer given to `receive` until the answer ends, an error
/// message says how, or `receive` fails it.
fn exchange(
    protocol: c_int,
    req: &mut Request,
    receive: &mut dyn FnMut(&[u8]) -> Result<(), c_int>,
) -> c_int {
    let sock = match open_socket(libc::AF_NETLINK, libc::SOCK_RAW, protocol) {
        Ok(sock) => sock,
        Err(err) => return err,
    };
    let timeout = libc::Timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    // SAFETY: the socket, and a timeval of its size.
    if unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            size_of::<libc::Timeval>() as u32,
        )
    } != 0
    {
        return last_errno();
    }
    let mut buf = Vec::new();
    if buf.try_reserve_exact(NETLINK_BUFFER_SIZE).is_err() {
        return -ENOMEM;
    }
    buf.resize(NETLINK_BUFFER_SIZE, 0u8);
    req.0[8..12].copy_from_slice(&1u32.to_ne_bytes());
    let kernel = libc::netlink_kernel();
    // SAFETY: the socket, the request's bytes and the kernel's address.
    if unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            req.0.as_ptr().cast(),
            req.0.len(),
            0,
            (&raw const kernel).cast(),
            size_of::<libc::SockaddrNl>() as u32,
        )
    } < 0
    {
        return last_errno();
    }
    loop {
        let mut sender = libc::netlink_kernel();
        sender.nl_family = 0;
        let mut iov = libc::Iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut msg = libc::Msghdr {
            msg_name: (&raw mut sender).cast(),
            msg_namelen: size_of::<libc::SockaddrNl>() as u32,
            msg_iov: &raw mut iov,
            msg_iovlen: 1,
            msg_control: core::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        // SAFETY: the socket and a message header over the buffer.
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) };
        if n < 0 {
            // EAGAIN is SO_RCVTIMEO, not a dump to start again.
            let err = libc::errno();
            return if err == EAGAIN { -ETIMEDOUT } else { -err };
        }
        if n == 0
            || msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || msg.msg_namelen != size_of::<libc::SockaddrNl>() as u32
            || sender.nl_pid != 0
            || sender.nl_family != libc::AF_NETLINK as u16
        {
            return -EBADMSG;
        }
        let mut rest = &buf[..n as usize];
        while !rest.is_empty() {
            if rest.len() < NLMSG_HDRLEN {
                return -EBADMSG;
            }
            let len = u32::from_ne_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            let ty = u16::from_ne_bytes([rest[4], rest[5]]);
            let flags = u16::from_ne_bytes([rest[6], rest[7]]);
            let seq = u32::from_ne_bytes([rest[8], rest[9], rest[10], rest[11]]);
            if len < NLMSG_HDRLEN || len > rest.len() {
                return -EBADMSG;
            }
            let step = nla_align(len);
            if step > rest.len() || seq != 1 {
                return -EBADMSG;
            }
            if flags & NLM_F_DUMP_INTR != 0 {
                return -EAGAIN;
            }
            let payload = &rest[NLMSG_HDRLEN..len];
            if ty == NLMSG_ERROR {
                if payload.len() < NLMSGERR_LEN {
                    return -EBADMSG;
                }
                let err = i32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
                return if err <= 0 { err } else { -EBADMSG };
            }
            if ty == NLMSG_DONE {
                if !payload.is_empty() && payload.len() < 4 {
                    return -EBADMSG;
                }
                let err = if payload.is_empty() {
                    0
                } else {
                    i32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]])
                };
                return if err <= 0 { err } else { -EBADMSG };
            }
            if let Err(err) = receive(payload) {
                return err;
            }
            if flags & NLM_F_MULTI == 0 {
                return 0;
            }
            rest = &rest[step..];
        }
    }
}

/// The program ids of an IFLA_XDP attribute's payload.
fn xdp_ids_parse(xdp: &[u8], out: &mut XdpDevice) -> Result<(), c_int> {
    let attrs = Attrs(xdp);

    out.xdp_drv_id = attrs.u32(IFLA_XDP_DRV_PROG_ID)?.unwrap_or(out.xdp_drv_id);
    let skb = attrs.u32(IFLA_XDP_SKB_PROG_ID)?.unwrap_or(0);
    let hw = attrs.u32(IFLA_XDP_HW_PROG_ID)?.unwrap_or(0);
    out.xdp_other_id = if skb != 0 { skb } else { hw };
    Ok(())
}

/// One RTM_NEWLINK message's payload as a device, its driver and devlink
/// facts not yet read.
pub(crate) fn device_parse(data: &[u8]) -> Result<XdpDevice, c_int> {
    let mut out = XdpDevice::empty();

    if data.len() < IFINFOMSG_LEN {
        return Err(-EINVAL);
    }
    let index = i32::from_ne_bytes([data[4], data[5], data[6], data[7]]);
    if index <= 0 {
        return Err(-EINVAL);
    }
    out.ifindex = index as u32;
    out.flags = u32::from_ne_bytes([data[8], data[9], data[10], data[11]]);
    let attrs = Attrs(&data[IFINFOMSG_LEN..]);
    attrs.string(IFLA_IFNAME, &mut out.name)?;
    if out.name[0] == 0 {
        return Err(-EINVAL);
    }
    out.peer_ifindex = attrs.u32(IFLA_LINK)?.unwrap_or(0);
    out.peer_other_netns = attrs.number::<4>(IFLA_LINK_NETNSID)?.is_some();
    attrs.string(IFLA_PARENT_DEV_BUS_NAME, &mut out.parent_bus)?;
    if let Some(linkinfo) = attrs.find(IFLA_LINKINFO)? {
        Attrs(linkinfo).string(IFLA_INFO_KIND, &mut out.kind)?;
    }
    if let Some(xdp) = attrs.find(IFLA_XDP)? {
        xdp_ids_parse(xdp, &mut out)?;
    }
    let Some(port) = attrs.find(IFLA_DEVLINK_PORT)?.filter(|p| !p.is_empty()) else {
        return Ok(out);
    };
    let port = Attrs(port);
    out.devlink_port = true;
    port.string(DEVLINK_ATTR_BUS_NAME, &mut out.devlink_bus)?;
    port.string(DEVLINK_ATTR_DEV_NAME, &mut out.devlink_device)?;
    if out.devlink_bus[0] == 0 || out.devlink_device[0] == 0 {
        return Err(-EINVAL);
    }
    out.port_index = port.u32(DEVLINK_ATTR_PORT_INDEX)?.ok_or(-EINVAL)?;
    Ok(out)
}

/// The id of a generic netlink family, looked up once a run: a family
/// keeps its id while it is registered, and devlink and netdev are built
/// in, so one lookup serves every device and attach.
fn genl_family(name: &CStr, cached: &AtomicU16) -> Result<u16, c_int> {
    let id = cached.load(Ordering::Relaxed);
    if id != 0 {
        return Ok(id);
    }
    let mut req = Request::genl(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1);
    req.put(CTRL_ATTR_FAMILY_NAME, name.to_bytes_with_nul())?;
    let mut found = 0u16;
    let ret = exchange(NETLINK_GENERIC, &mut req, &mut |data| {
        if data.len() < GENL_HDRLEN {
            return Err(-EINVAL);
        }
        if let Some(id) = Attrs(&data[GENL_HDRLEN..]).number::<2>(CTRL_ATTR_FAMILY_ID)? {
            found = u16::from_ne_bytes(id);
        }
        Ok(())
    });
    if ret != 0 {
        return Err(ret);
    }
    cached.store(found, Ordering::Relaxed);
    Ok(found)
}

static DEVLINK_FAMILY: AtomicU16 = AtomicU16::new(0);
static NETDEV_FAMILY: AtomicU16 = AtomicU16::new(0);

/// `struct ifreq`: a name and a union of 24 bytes.
#[repr(C)]
struct Ifreq {
    name: [u8; IFNAME_MAX],
    data: [u64; 3],
}

/// The ifindex `name` has now, -EXDEV for another than `ifindex`.
fn same_device(fd: BorrowedFd<'_>, name: &[u8; IFNAME_MAX], ifindex: u32) -> bool {
    let mut identity = Ifreq {
        name: *name,
        data: [0; 3],
    };
    // SAFETY: a socket and an ifreq the ioctl fills.
    let ok = unsafe { libc::ioctl(fd.as_raw_fd(), SIOCGIFINDEX, &raw mut identity) } == 0;
    ok && identity.data[0] as u32 as i32 == ifindex as i32
}

/// The driver ethtool names and, for a devlink port, its flavour.
fn device_details(dev: &mut XdpDevice) -> Result<(), c_int> {
    let mut name = [0u8; IFNAME_MAX];
    if crate::text::strscpy(&mut name, text(&dev.name)).is_err() {
        return Err(-EINVAL);
    }
    let sock = open_socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
    if !same_device(sock.as_fd(), &name, dev.ifindex) {
        return Err(-EXDEV);
    }
    let mut info = [0u8; DRVINFO_LEN];
    info[..4].copy_from_slice(&ETHTOOL_GDRVINFO.to_ne_bytes());
    let mut ifr = Ifreq {
        name,
        data: [info.as_mut_ptr() as u64, 0, 0],
    };
    // SAFETY: a socket and an ifreq whose data points at the drvinfo.
    let mut ret = if unsafe { libc::ioctl(sock.as_raw_fd(), SIOCETHTOOL, &raw mut ifr) } != 0 {
        last_errno()
    } else {
        0
    };
    if !same_device(sock.as_fd(), &name, dev.ifindex) {
        ret = -EXDEV;
    }
    drop(sock);
    if ret != 0 && ret != -EOPNOTSUPP && ret != -ENOTTY {
        return Err(ret);
    }
    if ret == 0 {
        let driver = &info[DRVINFO_DRIVER..DRVINFO_DRIVER + dev.driver.len()];
        if !driver.contains(&0) {
            return Err(-EINVAL);
        }
        dev.driver.copy_from_slice(driver);
    }
    if !dev.devlink_port {
        return Ok(());
    }
    let family = genl_family(DEVLINK_GENL_NAME, &DEVLINK_FAMILY)?;
    if family == 0 {
        return Err(-EINVAL);
    }
    let mut req = Request::genl(family, DEVLINK_CMD_PORT_GET, DEVLINK_GENL_VERSION);
    req.put(
        DEVLINK_ATTR_BUS_NAME,
        &dev.devlink_bus[..=text(&dev.devlink_bus).len()],
    )?;
    req.put(
        DEVLINK_ATTR_DEV_NAME,
        &dev.devlink_device[..=text(&dev.devlink_device).len()],
    )?;
    req.put(DEVLINK_ATTR_PORT_INDEX, &dev.port_index.to_ne_bytes())?;
    let mut flavour = dev.port_flavour;
    let ret = exchange(NETLINK_GENERIC, &mut req, &mut |data| {
        if data.len() < GENL_HDRLEN {
            return Err(-EINVAL);
        }
        if let Some(f) = Attrs(&data[GENL_HDRLEN..]).number::<2>(DEVLINK_ATTR_PORT_FLAVOUR)? {
            flavour = u16::from_ne_bytes(f);
        }
        Ok(())
    });
    dev.port_flavour = flavour;
    if ret != 0 { Err(ret) } else { Ok(()) }
}

/// The XDP features of a netdev family answer's payload, which must say
/// them.
pub(crate) fn features_parse(data: &[u8]) -> Result<u64, c_int> {
    if data.len() < GENL_HDRLEN {
        return Err(-EINVAL);
    }
    Attrs(&data[GENL_HDRLEN..])
        .number::<8>(NETDEV_A_DEV_XDP_FEATURES)?
        .map(u64::from_ne_bytes)
        .ok_or(-EINVAL)
}

/// The XDP features the device of `ifindex` reports.
pub(crate) fn device_features(ifindex: u32) -> Result<u64, c_int> {
    // -ENOENT would read as a missing attach target and be skipped.
    let family = match genl_family(NETDEV_FAMILY_NAME, &NETDEV_FAMILY) {
        Err(err) if err == -crate::errno::ENOENT => return Err(-EOPNOTSUPP),
        r => r?,
    };
    if family == 0 {
        return Err(-EINVAL);
    }
    let mut req = Request::genl(family, NETDEV_CMD_DEV_GET, NETDEV_FAMILY_VERSION);
    req.put(NETDEV_A_DEV_IFINDEX, &ifindex.to_ne_bytes())?;
    let mut features = 0;
    let ret = exchange(NETLINK_GENERIC, &mut req, &mut |data| {
        features = features_parse(data)?;
        Ok(())
    });
    if ret != 0 { Err(ret) } else { Ok(features) }
}

/// Native XDP without multi-buffer; a device with neither fails on its own.
pub(crate) fn multibuf_refused(features: u64) -> bool {
    features & NETDEV_XDP_ACT_BASIC != 0 && features & NETDEV_XDP_ACT_RX_SG == 0
}

/// Whether a failed link create says the device has no native XDP. A
/// driver that has it refuses with the same EOPNOTSUPP in some settings,
/// such as virtio_net under host GRO_HW or bnxt with header-data split.
pub(crate) fn attach_unsupported(err: c_int, features: u64) -> bool {
    err == -EOPNOTSUPP && features & NETDEV_XDP_ACT_BASIC == 0
}

/// Whether a failed link create is the driver refusing in its current
/// settings: mlx5 with LRO says EINVAL, veth with too few rx queues
/// ENOSPC, a driver whose MTU is too large ERANGE.
pub(crate) fn driver_refused(err: c_int) -> bool {
    [-EOPNOTSUPP, -EINVAL, -ENOSPC, -ERANGE].contains(&err)
}

/// What `err`, an attach error or a negative errno, says.
pub(crate) fn attach_strerror(err: c_int) -> &'static CStr {
    match err {
        ERR_NO_NATIVE => c"the driver has no native XDP",
        ERR_NO_MULTIBUF => c"the device does not report multi-buffer XDP support",
        ERR_DRIVER_SETTINGS => c"the driver refuses XDP in its current settings",
        ERR_OCCUPIED => c"the device runs another XDP program",
        ERR_LINK_SCOPE => c"the link is not on the device it was made for",
        // SAFETY: strerror() gives a C string that outlives the caller's
        // use of it.
        _ => unsafe { CStr::from_ptr(libc::strerror(-err)) },
    }
}

/// The negative errno a report carries for `err`.
pub(crate) fn attach_errno(err: c_int) -> c_int {
    match err {
        ERR_NO_NATIVE => -EOPNOTSUPP,
        ERR_NO_MULTIBUF => -EMEDIUMTYPE,
        ERR_DRIVER_SETTINGS => -ENOPROTOOPT,
        ERR_OCCUPIED => -crate::errno::EBUSY,
        ERR_LINK_SCOPE => -EREMOTE,
        _ => err,
    }
}

/// Why a device a program selects does not run it: `attached` as above,
/// `features` as read, unless `features_err` says they could not be.
pub(crate) fn uncovered_reason(attached: u32, features_err: c_int, features: u64) -> &'static CStr {
    if attached != 0 {
        c"another XDP program attached"
    } else if features_err != 0 {
        c"not attached"
    } else if features & NETDEV_XDP_ACT_BASIC == 0 {
        c"no native XDP"
    } else if multibuf_refused(features) {
        c"no multi-buffer XDP"
    } else {
        c"not attached"
    }
}

/// 0 in the initial network namespace, -EXDEV in another. Devices, and
/// the hook of a netfilter link, are the caller's namespace's.
pub(crate) fn netns_initial() -> c_int {
    let sock = match open_socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) {
        Ok(sock) => sock,
        Err(err) => return err,
    };
    let mut cookie = 0u64;
    let mut len = size_of::<u64>() as u32;
    // SAFETY: the socket and room for the cookie.
    if unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_NETNS_COOKIE,
            (&raw mut cookie).cast(),
            &mut len,
        )
    } != 0
    {
        return last_errno();
    }
    if cookie == NET_NS_INIT_COOKIE {
        0
    } else {
        -EXDEV
    }
}

/// A lookup that could not be made at all, which would leave every
/// device out.
fn lookup_failed(err: c_int) -> bool {
    [
        -ENOMEM, -ENOBUFS, -EMFILE, -ENFILE, -ETIMEDOUT, -EPERM, -EACCES, -EBADMSG,
    ]
    .contains(&err)
}

/// Every device rtnetlink lists, by ifindex, each with what its driver
/// and devlink port say.
fn devices_read_once() -> Result<Vec<XdpDevice>, c_int> {
    let mut req = Request::new(
        RTM_GETLINK,
        NLM_F_REQUEST | NLM_F_DUMP,
        &[0u8; IFINFOMSG_LEN],
    );
    let mut devices: Vec<XdpDevice> = Vec::new();
    let ret = exchange(NETLINK_ROUTE, &mut req, &mut |data| {
        let dev = device_parse(data)?;
        // Doubling keeps a dump of n devices to O(n) copies.
        devices.try_reserve(1).map_err(|_| -ENOMEM)?;
        devices.push(dev);
        Ok(())
    });
    if ret != 0 {
        return Err(ret);
    }
    devices.sort_by_key(|d| d.ifindex);
    for i in 0..devices.len() {
        if i > 0 && devices[i - 1].ifindex == devices[i].ifindex {
            return Err(-EAGAIN);
        }
        // A rename or removal racing the dump, or a driver or devlink
        // answer about this device alone, says nothing about the others;
        // without its facts this one can't be classified, so it sits out
        // this discovery. Only a failure is shown to the operator. A
        // lookup that could not be made at all would leave every device
        // out, so it fails the discovery.
        let dev = &mut devices[i];
        if let Err(err) = device_details(dev) {
            if lookup_failed(err) {
                return Err(err);
            }
            dev.unresolved = true;
            if err != -EXDEV && err != -ENODEV {
                dev.unclassified_err = err;
            }
        }
    }
    devices.shrink_to_fit();
    Ok(devices)
}

/// The driver-mode XDP program of `ifindex`, by its id, or 0 for none,
/// read through a dump of the links as libbpf's bpf_xdp_query_id() does.
#[cfg(feature = "test-helpers")]
pub(crate) fn drv_prog_id(ifindex: u32) -> Result<u32, c_int> {
    let mut req = Request::new(
        RTM_GETLINK,
        NLM_F_REQUEST | NLM_F_DUMP,
        &[0u8; IFINFOMSG_LEN],
    );
    let mut id = None;
    let ret = exchange(NETLINK_ROUTE, &mut req, &mut |data| {
        let dev = device_parse(data)?;
        if dev.ifindex == ifindex {
            id = Some(dev.xdp_drv_id);
        }
        Ok(())
    });
    match (ret, id) {
        (0, Some(id)) => Ok(id),
        (0, None) => Err(-ENODEV),
        (err, _) => Err(err),
    }
}

/// The driver-mode XDP program of `ifindex` taken off through netlink,
/// as libbpf's bpf_xdp_detach() takes it: what the kernel answers.
#[cfg(feature = "test-helpers")]
pub(crate) fn drv_detach(ifindex: u32) -> c_int {
    const RTM_SETLINK: u16 = 19;
    const NLM_F_ACK: u16 = 4;
    const NLA_F_NESTED: u16 = 0x8000;
    const IFLA_XDP_FD: u16 = 1;
    const IFLA_XDP_FLAGS: u16 = 3;
    const XDP_FLAGS_DRV_MODE: u32 = 4;
    let mut ifi = [0u8; IFINFOMSG_LEN];
    ifi[4..8].copy_from_slice(&(ifindex as i32).to_ne_bytes());
    let mut xdp = Vec::new();
    for (ty, value) in [
        (IFLA_XDP_FD, (-1i32).to_ne_bytes()),
        (IFLA_XDP_FLAGS, XDP_FLAGS_DRV_MODE.to_ne_bytes()),
    ] {
        xdp.extend_from_slice(&((NLA_HDRLEN + value.len()) as u16).to_ne_bytes());
        xdp.extend_from_slice(&ty.to_ne_bytes());
        xdp.extend_from_slice(&value);
    }
    let mut req = Request::new(RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK, &ifi);
    if let Err(err) = req.put(IFLA_XDP | NLA_F_NESTED, &xdp) {
        return err;
    }
    exchange(NETLINK_ROUTE, &mut req, &mut |_| Ok(()))
}

/// A device whose facts cannot be read sits out, unresolved, rather than
/// failing the read: it need not be one any upatch selects.
pub(crate) fn devices_read() -> Result<Vec<XdpDevice>, c_int> {
    let mut ret = Err(-EAGAIN);

    for _ in 0..DEVICES_READ_ATTEMPTS {
        ret = devices_read_once();
        if !matches!(ret, Err(err) if err == -EAGAIN) {
            break;
        }
    }
    ret
}

/// The devices whose facts could not be read, said.
pub(crate) fn warn_unclassified(devs: &[XdpDevice]) {
    for d in devs.iter().filter(|d| d.unclassified_err != 0) {
        crate::log::warn(
            format!(
                "XDP: cannot classify {} (ifindex {}), it sits out: {}",
                String::from_utf8_lossy(d.name()),
                d.ifindex,
                attach_strerror(d.unclassified_err).to_string_lossy()
            )
            .as_bytes(),
        );
    }
}

/// Whether the device `expected` describes is still that one: 0, -EXDEV
/// for another or none, or the error of the lookup.
pub(crate) fn device_verify(expected: &XdpDevice) -> c_int {
    let mut body = [0u8; IFINFOMSG_LEN];
    body[4..8].copy_from_slice(&(expected.ifindex as i32).to_ne_bytes());
    let mut req = Request::new(RTM_GETLINK, NLM_F_REQUEST, &body);
    let mut found = Vec::new();
    let ret = exchange(NETLINK_ROUTE, &mut req, &mut |data| {
        found.push(device_parse(data)?);
        Ok(())
    });
    if ret != 0 {
        return ret;
    }
    if found.len() != 1 {
        return -EXDEV;
    }
    let mut dev = found[0];
    if let Err(err) = device_details(&mut dev) {
        return err;
    }
    if dev.ifindex != expected.ifindex
        || dev.peer_ifindex != expected.peer_ifindex
        || dev.peer_other_netns != expected.peer_other_netns
        || text(&dev.kind) != text(&expected.kind)
        || dev.class() != expected.class()
    {
        return -EXDEV;
    }
    0
}

/// Whether a failed attach is left for a later pass rather than fatal. A
/// driver refusal or an occupied device fails a restore as it fails a
/// load: neither a setting that survives a reboot nor another program may
/// take a device out of the upatch unreported. The kernel reports a
/// vanished ifindex as EINVAL, so ask, and take only an answer that the
/// device is gone or changed: a lookup that itself fails says nothing
/// about the refusal.
pub(crate) fn attach_skippable(err: c_int, dev: &XdpDevice) -> bool {
    if err == 0 || err == -EACCES || err == -EPERM || err == ERR_LINK_SCOPE || err == ERR_OCCUPIED {
        return false;
    }
    if err == -EXDEV || err == -ENODEV {
        return true;
    }
    let err = device_verify(dev);
    err == -EXDEV || err == -ENODEV
}

#[cfg(test)]
mod tests;
