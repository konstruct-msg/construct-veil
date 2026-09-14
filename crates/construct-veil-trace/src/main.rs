//! `veil-trace` — read a capture, report what it leaks.
//!
//! ```text
//! veil-trace parse   capture.pcap --port 443 > trace.jsonl
//! veil-trace summary trace.jsonl
//! veil-trace compare a.jsonl b.jsonl
//! ```
//!
//! `parse` is the only step that needs the capture; everything after it works on the record stream,
//! so a trace can be archived and re-analysed without keeping traffic around.

use std::collections::HashMap;
use std::io::{BufRead, BufWriter, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use construct_veil_trace::capture::{TraceBuilder, TracedRecord};
use construct_veil_trace::records::{Direction, Record};
use construct_veil_trace::stats::{ConnectionFeatures, Support, quantile, separations};

#[derive(Parser)]
#[command(name = "veil-trace", about = "What a capture of our traffic looks like to an observer")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Recover the TLS record stream from a capture file.
    Parse {
        capture: PathBuf,
        /// Server port that identifies the connections of interest.
        #[arg(long, default_value_t = 443)]
        port: u16,
    },
    /// Describe one trace: sizes, gaps, direction balance.
    Summary { trace: PathBuf },
    /// How well the cheapest classifiers tell two sets of traces apart.
    Compare { a: PathBuf, b: PathBuf },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Parse { capture, port } => parse(&capture, port),
        Command::Summary { trace } => summary(&trace),
        Command::Compare { a, b } => compare(&a, &b),
    }
}

// ── parse ────────────────────────────────────────────────────────────────────

fn parse(path: &PathBuf, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = pcap::Capture::from_file(path)?;
    let mut builder = TraceBuilder::new(port);

    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    while let Ok(packet) = capture.next_packet() {
        let timestamp =
            packet.header.ts.tv_sec as f64 + packet.header.ts.tv_usec as f64 / 1_000_000.0;
        for traced in builder.push(packet.data, timestamp) {
            writeln!(out, "{}", serde_json::to_string(&traced)?)?;
        }
    }
    out.flush()?;

    // To stderr, so it annotates the run without contaminating the trace.
    eprintln!("connections: {}", builder.connections());
    let broken = builder.broken_directions();
    if broken > 0 {
        eprintln!(
            "warning: {broken} direction(s) desynced or lost bytes — their records stop early \
             and their connections should be discarded, not trusted short"
        );
    }
    Ok(())
}

// ── summary ──────────────────────────────────────────────────────────────────

fn load(path: &PathBuf) -> Result<HashMap<u32, Vec<Record>>, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(path)?;
    let mut by_conn: HashMap<u32, Vec<Record>> = HashMap::new();
    for line in std::io::BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let traced: TracedRecord = serde_json::from_str(&line)?;
        by_conn.entry(traced.conn).or_default().push(traced.record);
    }
    for records in by_conn.values_mut() {
        records.sort_by(|a, b| a.t.partial_cmp(&b.t).expect("no NaN in capture timestamps"));
    }
    Ok(by_conn)
}

fn features(path: &PathBuf) -> Result<Vec<ConnectionFeatures>, Box<dyn std::error::Error>> {
    Ok(load(path)?.values().filter_map(|r| ConnectionFeatures::from_records(r)).collect())
}

fn summary(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let by_conn = load(path)?;
    let all: Vec<&Record> = by_conn.values().flatten().filter(|r| r.is_application()).collect();
    if all.is_empty() {
        println!("no application-data records — nothing to describe");
        return Ok(());
    }

    println!("connections     {}", by_conn.len());
    println!("records         {}", all.len());
    println!("bytes           {}", all.iter().map(|r| r.len).sum::<usize>());

    for dir in [Direction::Up, Direction::Down] {
        let mut sizes: Vec<usize> = all.iter().filter(|r| r.dir == dir).map(|r| r.len).collect();
        if sizes.is_empty() {
            continue;
        }
        sizes.sort_unstable();
        let label = if dir == Direction::Up { "up  " } else { "down" };
        println!("\n{label} records   {}", sizes.len());

        // Sizes as counts, not a histogram with invented bins: a bucketed sender has a handful of
        // values and binning them would hide exactly the property being checked.
        let mut counts: HashMap<usize, usize> = HashMap::new();
        for s in &sizes {
            *counts.entry(*s).or_default() += 1;
        }
        let mut top: Vec<(usize, usize)> = counts.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        println!("{label} distinct  {}", top.len());
        for (size, count) in top.iter().take(8) {
            println!(
                "{label}   {size:>6} B  {count:>6}  {:>5.1}%",
                100.0 * *count as f64 / sizes.len() as f64
            );
        }
        if top.len() > 8 {
            println!("{label}   … {} more size(s)", top.len() - 8);
        }
    }

    let mut gaps: Vec<f64> = by_conn
        .values()
        .flat_map(|records| {
            let app: Vec<&Record> = records.iter().filter(|r| r.is_application()).collect();
            app.windows(2).map(|w| w[1].t - w[0].t).collect::<Vec<_>>()
        })
        .collect();
    gaps.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    if !gaps.is_empty() {
        println!("\ngaps between records, seconds (within a connection)");
        for q in [0.05, 0.25, 0.5, 0.75, 0.95] {
            println!("  p{:<3} {:>10.4}", (q * 100.0) as u32, quantile(&gaps, q));
        }
    }
    Ok(())
}

// ── compare ──────────────────────────────────────────────────────────────────

fn compare(a: &PathBuf, b: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let fa = features(a)?;
    let fb = features(b)?;
    let support = Support { connections_a: fa.len(), connections_b: fb.len() };

    println!("connections     A {}   B {}", support.connections_a, support.connections_b);
    println!("\nfeature              separation (0.5 = a coin flip)");
    for f in separations(&fa, &fb) {
        let bar = "#".repeat(((f.separation - 0.5) * 40.0).round().max(0.0) as usize);
        println!("  {:<18} {:>5.3}  {bar}", f.feature, f.separation);
    }

    println!();
    if support.is_suggestive_only() {
        println!(
            "SUGGESTIVE ONLY — fewer than 20 connections on a side. These numbers say which\n\
             feature to look at next, not whether the traffic is distinguishable."
        );
    } else {
        println!(
            "Read the top row: an adversary uses the feature that works. A low score here means\n\
             these particular classifiers failed on these captures — it is not a claim that no\n\
             classifier succeeds."
        );
    }
    Ok(())
}
