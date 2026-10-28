//! The net-io integration (feature `net-io`): bouncer as net-io's [`Gate`].
//!
//! net-io calls the gate after accept and before any read, after a trusted
//! PROXY header, before every write system call, and once when a connection
//! closes. net-io never depends on bouncer.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::OnceLock;

use net_io::{
    AdmitStage, Admitted, CloseReason, ConnectionId, ConnectionInfo, Denial, Gate, GateTag,
    KillReason, ServerHandle, WriteCheck,
};

use crate::{
    Bouncer, CloseKind, ConnId, Ejector, Provenance, Ticket, TicketTag, Verdict, keys::Cidr,
    strikes::StrikeKind,
};

/// The refusal code net-io reports for every door refusal. One code for
/// every reason, so a refused peer learns nothing about why.
pub const REFUSED: u16 = 1;

/// The kill reason [`NetIoEjector`] gives net-io.
pub const EJECTED: KillReason = KillReason(0xb0);

/// The address a peer with no IP address (a Unix socket or a named pipe)
/// enters the door as, with [`Provenance::Local`]: all such peers are one
/// source, and banning it bans them together.
pub const LOCAL_PEER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The connection ticket net-io keeps beside each admitted connection.
/// Dropping it (net-io does, once the connection has closed) releases the
/// ticket: the connection's live requests are denied from then on.
///
/// # Examples
///
/// ```
/// use bouncer_io::Bouncer;
/// use net_io::{AdmitStage, ConnectionInfo, Gate};
///
/// let bouncer = Bouncer::new();
/// let info = ConnectionInfo::for_testing("192.0.2.40:5000".parse()?);
/// let mut admitted = bouncer.admit(&info, AdmitStage::Accept).unwrap();
/// assert_eq!(admitted.ticket.ticket().conn().0, info.id.get());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct ConnectionGate {
    ticket: Ticket,
    tag: TicketTag,
}

impl ConnectionGate {
    /// The connection ticket, to open request tickets or bind identities.
    pub fn ticket(&mut self) -> &mut Ticket {
        &mut self.ticket
    }

    /// The connection's tag (also net-io's `GateTag` for it).
    #[must_use]
    pub fn tag(&self) -> TicketTag {
        self.tag
    }
}

impl Gate for Bouncer {
    type Ticket = ConnectionGate;

    /// The door, with net-io's connection id and accept time. A refusal is
    /// a silent reset, the same for every reason.
    fn admit(
        &self,
        info: &ConnectionInfo,
        _stage: AdmitStage,
    ) -> Result<Admitted<ConnectionGate>, net_io::Refusal> {
        let (peer, provenance) = match info.socket_peer() {
            Some(addr) => (addr.ip(), Provenance::Socket),
            None => (LOCAL_PEER, Provenance::Local),
        };
        let now = self.now_at(info.accepted_at);
        match self.door_at(ConnId::from(info.id), peer, provenance, now) {
            Ok(ticket) => {
                let tag = ticket.tag();
                Ok(Admitted {
                    lane: info.lane,
                    ticket: ConnectionGate { ticket, tag },
                    tag: GateTag::from(tag),
                })
            }
            Err(_) => Err(net_io::Refusal::Reset { code: REFUSED }),
        }
    }

    /// Binds the client a trusted PROXY header named. A banned client is
    /// refused, the same way as at the door.
    fn readmit(
        &self,
        gate: &mut ConnectionGate,
        info: &ConnectionInfo,
    ) -> Result<(), net_io::Refusal> {
        let Some(real) = info.real_peer else {
            return Ok(());
        };
        match gate
            .ticket
            .bind_client(real.ip(), Provenance::ProxyProtocol)
        {
            Verdict::Pass => Ok(()),
            Verdict::Deny(_) => Err(net_io::Refusal::Reset { code: REFUSED }),
        }
    }

    /// The egress check: the request whose response is being written when
    /// the session tagged it, otherwise the connection and its latest
    /// request. A handful of loads while nothing is revoked.
    #[inline]
    fn check(&self, gate: &mut ConnectionGate, write: &WriteCheck) -> Result<(), Denial> {
        let tag = write.response.map_or(gate.tag, TicketTag::from);
        match self.egress(tag) {
            Verdict::Pass => Ok(()),
            Verdict::Deny(d) => Err(Denial {
                code: d.code.number(),
            }),
        }
    }

    /// Releases the connection ticket; a close that means misbehaviour is a
    /// strike first.
    fn closed(&self, gate: ConnectionGate, _info: &ConnectionInfo, reason: CloseReason) {
        if let Some(kind) = strike_for(reason) {
            let _ = gate.ticket.strike(kind);
        }
    }
}

/// The strike a close reason stands for, if any.
fn strike_for(reason: CloseReason) -> Option<StrikeKind> {
    match reason {
        CloseReason::SlowPeer { .. } => Some(StrikeKind::SlowPeer),
        CloseReason::ProxyInvalid | CloseReason::ProxyUntrusted => Some(StrikeKind::ProxyViolation),
        CloseReason::TlsFailed | CloseReason::HelloRefused => Some(StrikeKind::HandshakeFailed),
        _ => None,
    }
}

impl From<ConnectionId> for ConnId {
    fn from(id: ConnectionId) -> ConnId {
        ConnId(id.get())
    }
}

impl From<TicketTag> for GateTag {
    fn from(tag: TicketTag) -> GateTag {
        GateTag(tag.get())
    }
}

impl From<GateTag> for TicketTag {
    fn from(tag: GateTag) -> TicketTag {
        TicketTag::from_raw(tag.0)
    }
}

impl From<net_io::Cidr> for Cidr {
    fn from(c: net_io::Cidr) -> Cidr {
        // net-io's prefixes are masked and within their family's length, so
        // this cannot fail; a host prefix is the fallback all the same.
        Cidr::new(c.network(), c.prefix_len()).unwrap_or_else(|_| Cidr::host(c.network()))
    }
}

/// An [`Ejector`] over a net-io server: closes connections bouncer holds
/// only by id (eject-now sweeps, idle checks). net-io aborts with
/// `SO_LINGER` 0; a close after a flush is an abort too, since a connection
/// ejected this way is one bouncer has nothing more to say to.
///
/// The bouncer takes its ejector when it is built, and the server takes the
/// bouncer as its gate, so the ejector is attached to the server afterwards.
/// Ejections before that have no connection to close and are dropped.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use bouncer_io::{Bouncer, NetIoEjector};
/// use net_io::{ListenerSpec, ServerBuilder};
///
/// let ejector = Arc::new(NetIoEjector::new());
/// let bouncer = Bouncer::builder().ejector(ejector.clone()).try_build()?;
/// let server = ServerBuilder::new()
///     .listener(ListenerSpec::tcp("127.0.0.1:0"))
///     .handler(|_conn: &mut net_io::TcpConnection| Ok(()))
///     .gate(bouncer.clone())
///     .build()?;
/// assert!(ejector.attach(server.handle()));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Default)]
pub struct NetIoEjector {
    server: OnceLock<ServerHandle>,
}

impl NetIoEjector {
    /// An ejector not yet attached to a server.
    #[must_use]
    pub fn new() -> NetIoEjector {
        NetIoEjector::default()
    }

    /// Attaches the server whose connections it closes. `false` when one
    /// was already attached (the first stays).
    pub fn attach(&self, server: ServerHandle) -> bool {
        self.server.set(server).is_ok()
    }
}

impl core::fmt::Debug for NetIoEjector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NetIoEjector")
            .field("attached", &self.server.get().is_some())
            .finish()
    }
}

impl Ejector for NetIoEjector {
    fn eject(&self, conn: ConnId, _kind: CloseKind) {
        if let (Some(server), Some(id)) = (self.server.get(), ConnectionId::new(conn.0)) {
            let _ = server.kill(id, EJECTED);
        }
    }
}
