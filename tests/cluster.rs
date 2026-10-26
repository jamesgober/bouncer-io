//! Three nodes under partitions, clock skew, reordering, and duplication
//! (ROADMAP 0.7, threat T-27, dev/PLAN.md 7.13, D-096). Each node bans and
//! lifts addresses from a small shared pool, so the same key is often
//! banned by more than one node; deltas travel over links that go down and
//! come back, arrive out of order, and arrive twice. An administrator's
//! lift also reaches every node through the administration channel, as the
//! operator's tooling delivers it; an automated lift travels only on its
//! node's links. After the partitions heal and every delta has been
//! delivered, the three nodes agree on every ban and every verdict.

use std::{collections::BTreeSet, net::IpAddr, sync::Arc, time::Duration};

use bouncer_io::{
    Actor, Bouncer, Budgets, Delta, EscalationPolicy, Filter, LiftSpec, NodeId, Page, Sequence,
};
use clock_lib::ManualClock;

/// A small, fast generator (xorshift64*).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const NODES: usize = 3;
const POOL: u64 = 16;

fn addr(i: u64) -> IpAddr {
    IpAddr::from([198, 51, 100, i as u8 + 1])
}

struct Node {
    b: Bouncer,
    clock: Arc<ManualClock>,
    /// What this node has exported to each peer so far.
    since: [Sequence; NODES],
    /// What this node has handed to the administration channel so far.
    admin_since: Sequence,
}

fn banned(b: &Bouncer) -> BTreeSet<String> {
    b.list(&Filter::all(), Page::first(1000))
        .items
        .iter()
        .map(|r| r.key.to_string())
        .collect()
}

fn verdicts(b: &Bouncer) -> Vec<bool> {
    (0..POOL).map(|i| b.door(addr(i)).is_ok()).collect()
}

/// One delta in flight to `to`: from node `from` over a node link, or
/// through the administration channel (`admin`).
struct InFlight {
    from: usize,
    to: usize,
    admin: bool,
    delta: Delta,
}

impl InFlight {
    fn actor(&self) -> Actor {
        if self.admin {
            Actor::Admin(1)
        } else {
            Actor::Channel(self.from as u64 + 1)
        }
    }
}

fn run(seed: u64, steps: usize, escalate: bool) {
    let trace = std::env::var("CLUSTER_TRACE").is_ok();
    let mut rng = Rng(seed | 1);
    let mut nodes: Vec<Node> = (0..NODES)
        .map(|i| {
            let clock = Arc::new(ManualClock::new());
            // Node 3's wall clock runs 30 seconds ahead (inside the skew
            // bound): stamps, not arrival, must order its records.
            if i == 2 {
                clock.step_wall_forward(Duration::from_secs(30));
            }
            let mut builder = Bouncer::builder()
                .node(NodeId(i as u16 + 1))
                .clock(clock.clone())
                .budgets(Budgets::off());
            if !escalate {
                builder = builder.escalation(EscalationPolicy::default().off());
            }
            Node {
                b: builder.try_build().unwrap(),
                clock,
                since: [Sequence::START; NODES],
                admin_since: Sequence::START,
            }
        })
        .collect();
    // up[i][j]: the link from i to j carries deltas.
    let mut up = [[true; NODES]; NODES];
    let mut wire: Vec<InFlight> = Vec::new();

    let export = |n: &mut Node, to: usize, wire: &mut Vec<InFlight>, from: usize| {
        let d = n.b.export_delta(n.since[to]).unwrap();
        n.since[to] = d.last();
        wire.push(InFlight {
            from,
            to,
            admin: false,
            delta: d,
        });
    };

    for _ in 0..steps {
        match rng.below(10) {
            // A ban or a lift on a random node.
            0..=4 => {
                let n = rng.below(NODES as u64) as usize;
                let a = addr(rng.below(POOL));
                match rng.below(6) {
                    0 => {
                        // An administrator's lift: here at once, and to every
                        // other node through the administration channel.
                        let r = nodes[n].b.lift(LiftSpec::key(a).by(Actor::Admin(7)));
                        if trace {
                            println!("node {} admin lift {a}: {:?}", n + 1, r.map(|l| l.removed));
                        }
                        let d = nodes[n].b.export_delta(nodes[n].admin_since).unwrap();
                        nodes[n].admin_since = d.last();
                        for to in (0..NODES).filter(|&to| to != n) {
                            wire.push(InFlight {
                                from: n,
                                to,
                                admin: true,
                                delta: d.clone(),
                            });
                        }
                    }
                    1 => {
                        // An automated lift: this node's own ban only.
                        let r = nodes[n].b.lift(LiftSpec::key(a).by(Actor::Gate));
                        if trace {
                            println!("node {} gate lift {a}: {:?}", n + 1, r.map(|l| l.removed));
                        }
                    }
                    _ => {
                        let r = nodes[n].b.ban(a);
                        if trace {
                            println!("node {} ban {a}: {:?}", n + 1, r.is_ok());
                        }
                    }
                }
            }
            // A node exports to every peer whose link is up.
            5 | 6 => {
                let n = rng.below(NODES as u64) as usize;
                let links = up[n];
                for (to, open) in links.into_iter().enumerate() {
                    if to != n && open {
                        export(&mut nodes[n], to, &mut wire, n);
                    }
                }
            }
            // Deliver one delta in flight, chosen at random (reordering);
            // sometimes keep a copy to deliver again (duplication).
            7 | 8 => {
                if !wire.is_empty() {
                    let i = rng.below(wire.len() as u64) as usize;
                    let f = if rng.below(4) == 0 {
                        InFlight {
                            from: wire[i].from,
                            to: wire[i].to,
                            admin: wire[i].admin,
                            delta: wire[i].delta.clone(),
                        }
                    } else {
                        wire.swap_remove(i)
                    };
                    if f.admin || up[f.from][f.to] {
                        let r = nodes[f.to].b.import(&f.delta, f.actor()).unwrap();
                        if trace {
                            let how = if f.admin { "admin" } else { "link" };
                            println!("deliver {} -> {} ({how}): {r:?}", f.from + 1, f.to + 1);
                        }
                    } else {
                        // A partition drops what was on the link.
                        nodes[f.from].since[f.to] = Sequence::START;
                    }
                }
            }
            // A link goes down or comes back; time passes.
            _ => {
                let i = rng.below(NODES as u64) as usize;
                let j = rng.below(NODES as u64) as usize;
                if i != j {
                    up[i][j] = !up[i][j];
                }
                let ms = rng.below(2_000);
                for n in &nodes {
                    n.clock.advance(Duration::from_millis(ms));
                    n.clock.step_wall_forward(Duration::from_millis(ms));
                }
            }
        }
    }

    // Heal: deliver what is in flight, then exchange until nothing new
    // moves.
    for f in wire.drain(..) {
        let _ = nodes[f.to].b.import(&f.delta, f.actor()).unwrap();
    }
    for _round in 0..4 {
        for from in 0..NODES {
            for to in (0..NODES).filter(|&to| to != from) {
                let mut tmp = Vec::new();
                export(&mut nodes[from], to, &mut tmp, from);
                for f in tmp {
                    let _ = nodes[to].b.import(&f.delta, f.actor()).unwrap();
                }
            }
        }
    }
    let doors: Vec<Vec<bool>> = nodes.iter().map(|n| verdicts(&n.b)).collect();
    if trace {
        for i in 0..POOL {
            if doors.iter().any(|d| d[i as usize] != doors[0][i as usize]) {
                for (k, n) in nodes.iter().enumerate() {
                    let e = n.b.explain(addr(i));
                    let held: Vec<_> = e
                        .bans
                        .iter()
                        .map(|r| (r.origin, r.id.get() >> 48))
                        .collect();
                    println!(
                        "{}: node {} admitted {} bans {held:?}",
                        addr(i),
                        k + 1,
                        e.admitted
                    );
                }
            }
        }
    }
    for (i, d) in doors.iter().enumerate().skip(1) {
        assert_eq!(
            d,
            &doors[0],
            "seed {seed}: node {} and node 1 give different verdicts after healing",
            i + 1
        );
    }
    if !escalate {
        let views: Vec<BTreeSet<String>> = nodes.iter().map(|n| banned(&n.b)).collect();
        for (i, v) in views.iter().enumerate().skip(1) {
            assert_eq!(
                v,
                &views[0],
                "seed {seed}: node {} and node 1 hold different bans after healing",
                i + 1
            );
        }
    }
}

#[test]
#[ignore = "investigation: CLUSTER_SEED, CLUSTER_STEPS, CLUSTER_ESCALATE"]
fn cluster_one_seed() {
    let seed: u64 = std::env::var("CLUSTER_SEED").unwrap().parse().unwrap();
    let steps: usize = std::env::var("CLUSTER_STEPS").unwrap().parse().unwrap();
    run(seed, steps, std::env::var("CLUSTER_ESCALATE").is_ok());
}

/// Seeds per test: 200, or `CLUSTER_SEEDS` (the 0.7 run used 5,000).
fn seeds() -> u64 {
    std::env::var("CLUSTER_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200)
}

#[test]
fn test_three_nodes_converge_under_partitions_skew_and_reordering() {
    for seed in 1..=seeds() {
        run(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15), 400, false);
    }
}

#[test]
fn test_three_nodes_agree_on_verdicts_with_escalation() {
    // Escalation folds children into a parent on the node that escalates;
    // every node still gives the same verdict on every address.
    for seed in 1..=seeds() {
        run(seed.wrapping_mul(0xc2b2_ae3d_27d4_eb4f), 400, true);
    }
}
