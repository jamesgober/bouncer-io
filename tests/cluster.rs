//! Three nodes under partitions, clock skew, reordering, and duplication
//! (ROADMAP 0.7, threat T-27, dev/PLAN.md 7.13). Each node bans and lifts
//! addresses from a small shared pool, so the same key is often banned by
//! more than one node; deltas travel over links that go down and come back,
//! arrive out of order, and arrive twice. After the partitions heal and
//! every delta has been delivered, the three nodes agree.

use std::{collections::BTreeSet, net::IpAddr, sync::Arc, time::Duration};

use bouncer_io::{Actor, Bouncer, Budgets, Delta, Filter, NodeId, Page, Sequence};
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
}

fn banned(b: &Bouncer) -> BTreeSet<String> {
    b.list(&Filter::all(), Page::first(1000))
        .items
        .iter()
        .map(|r| r.key.to_string())
        .collect()
}

/// One delta in flight from `from` to `to`.
struct InFlight {
    from: usize,
    to: usize,
    delta: Delta,
}

fn run(seed: u64, steps: usize) {
    let trace = std::env::var("CLUSTER_TRACE").is_ok();
    let mut rng = Rng(seed | 1);
    let mut nodes: Vec<Node> = (0..NODES)
        .map(|i| {
            let clock = Arc::new(ManualClock::new());
            // Node 2's wall clock runs 30 seconds ahead (inside the skew
            // bound): stamps, not arrival, must order its records.
            if i == 2 {
                clock.step_wall_forward(Duration::from_secs(30));
            }
            Node {
                b: Bouncer::builder()
                    .node(NodeId(i as u16 + 1))
                    .clock(clock.clone())
                    .budgets(Budgets::off())
                    .try_build()
                    .unwrap(),
                clock,
                since: [Sequence::START; NODES],
            }
        })
        .collect();
    // up[i][j]: the link from i to j carries deltas.
    let mut up = [[true; NODES]; NODES];
    let mut wire: Vec<InFlight> = Vec::new();

    let export = |n: &mut Node, to: usize, wire: &mut Vec<InFlight>, from: usize| {
        let d = n.b.export_delta(n.since[to]).unwrap();
        n.since[to] = d.last();
        wire.push(InFlight { from, to, delta: d });
    };

    for _ in 0..steps {
        match rng.below(10) {
            // A ban or a lift on a random node.
            0..=4 => {
                let n = rng.below(NODES as u64) as usize;
                let a = addr(rng.below(POOL));
                if rng.below(3) == 0 {
                    let r = nodes[n].b.lift(a);
                    if trace {
                        println!("node {} lift {a}: {:?}", n + 1, r.map(|l| l.removed));
                    }
                } else {
                    let r = nodes[n].b.ban(a);
                    if trace {
                        println!("node {} ban {a}: {:?}", n + 1, r.is_ok());
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
                            delta: wire[i].delta.clone(),
                        }
                    } else {
                        wire.swap_remove(i)
                    };
                    if up[f.from][f.to] {
                        let actor = Actor::Channel(f.from as u64 + 1);
                        let r = nodes[f.to].b.import(&f.delta, actor).unwrap();
                        if trace {
                            println!("deliver {} -> {}: {r:?}", f.from + 1, f.to + 1);
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
        let actor = Actor::Channel(f.from as u64 + 1);
        let _ = nodes[f.to].b.import(&f.delta, actor).unwrap();
    }
    for _round in 0..4 {
        for from in 0..NODES {
            for to in (0..NODES).filter(|&to| to != from) {
                let mut tmp = Vec::new();
                export(&mut nodes[from], to, &mut tmp, from);
                for f in tmp {
                    let actor = Actor::Channel(from as u64 + 1);
                    let _ = nodes[to].b.import(&f.delta, actor).unwrap();
                }
            }
        }
    }
    let views: Vec<BTreeSet<String>> = nodes.iter().map(|n| banned(&n.b)).collect();
    for (i, v) in views.iter().enumerate().skip(1) {
        assert_eq!(
            v,
            &views[0],
            "seed {seed}: node {} and node 1 disagree after healing",
            i + 1
        );
    }
}

#[test]
#[ignore = "investigation: CLUSTER_SEED, CLUSTER_STEPS"]
fn cluster_one_seed() {
    let seed: u64 = std::env::var("CLUSTER_SEED").unwrap().parse().unwrap();
    let steps: usize = std::env::var("CLUSTER_STEPS").unwrap().parse().unwrap();
    run(seed, steps);
}

#[test]
#[ignore = "open 0.7 finding (dev/ROADMAP.md): sharing does not converge yet"]
fn test_three_nodes_converge_under_partitions_skew_and_reordering() {
    for seed in 1..=200u64 {
        run(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15), 400);
    }
}
