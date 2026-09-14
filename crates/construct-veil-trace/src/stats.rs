//! Turning a trace into the numbers an adversary would get, and refusing to report more than that.
//!
//! Two rules, both from the review (§14):
//!
//! * **A connection is one observation.** Records inside a connection are not independent draws.
//!   Every figure here is computed per connection and only then aggregated, so a single chatty
//!   capture cannot masquerade as a thousand samples.
//! * **No p-values.** "The test did not reject" is not "the distributions are equal", and it is
//!   certainly not "the traffic is unclassifiable". What is reported instead is how well the
//!   cheapest classifiers separate two sets — an upper bound on nothing and a lower bound on the
//!   adversary's cheapest attack, which is the honest direction for a defender to measure.

use serde::{Deserialize, Serialize};

use crate::records::{Direction, Record};

/// Everything one connection contributes, as an adversary's feature vector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionFeatures {
    pub records: usize,
    pub bytes: usize,
    pub duration: f64,
    pub up_records: usize,
    pub down_records: usize,
    /// Share of records that are the smallest size seen. Padding schemes concentrate here.
    pub modal_size_share: f64,
    /// Distinct record sizes. A bucketed sender has few; an ordinary web client has many.
    pub distinct_sizes: usize,
    /// Median gap between consecutive records, seconds.
    pub median_gap: f64,
    /// Spread of those gaps (interquartile range). A metronome has an IQR near zero.
    pub gap_iqr: f64,
    /// Bytes per second over the connection's life.
    pub bytes_per_second: f64,
}

impl ConnectionFeatures {
    /// Derives the features of one connection from its application-data records.
    ///
    /// Handshake records are excluded on purpose: they are a fingerprint question (§3.1), measured
    /// by their own means, and leaving them in would let a certificate's size drown out the shape
    /// of the session that follows.
    pub fn from_records(records: &[Record]) -> Option<Self> {
        let app: Vec<&Record> = records.iter().filter(|r| r.is_application()).collect();
        if app.len() < 2 {
            return None;
        }

        let bytes: usize = app.iter().map(|r| r.len).sum();
        let duration = app.last().unwrap().t - app.first().unwrap().t;

        let mut sizes: Vec<usize> = app.iter().map(|r| r.len).collect();
        sizes.sort_unstable();
        let distinct_sizes = {
            let mut d = sizes.clone();
            d.dedup();
            d.len()
        };
        let modal_size_share = {
            let mut best = 0usize;
            let mut run = 0usize;
            let mut prev = None;
            for &s in &sizes {
                run = if Some(s) == prev { run + 1 } else { 1 };
                best = best.max(run);
                prev = Some(s);
            }
            best as f64 / sizes.len() as f64
        };

        let mut gaps: Vec<f64> = app.windows(2).map(|w| w[1].t - w[0].t).collect();
        gaps.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in capture timestamps"));

        Some(Self {
            records: app.len(),
            bytes,
            duration,
            up_records: app.iter().filter(|r| r.dir == Direction::Up).count(),
            down_records: app.iter().filter(|r| r.dir == Direction::Down).count(),
            modal_size_share,
            distinct_sizes,
            median_gap: quantile(&gaps, 0.5),
            gap_iqr: quantile(&gaps, 0.75) - quantile(&gaps, 0.25),
            bytes_per_second: if duration > 0.0 { bytes as f64 / duration } else { 0.0 },
        })
    }

    /// The features by name, so the classifier can walk them without knowing what they mean.
    pub fn named(&self) -> Vec<(&'static str, f64)> {
        vec![
            ("records", self.records as f64),
            ("bytes", self.bytes as f64),
            ("duration", self.duration),
            ("up_down_ratio", self.up_records as f64 / (self.down_records.max(1)) as f64),
            ("modal_size_share", self.modal_size_share),
            ("distinct_sizes", self.distinct_sizes as f64),
            ("median_gap", self.median_gap),
            ("gap_iqr", self.gap_iqr),
            ("bytes_per_second", self.bytes_per_second),
        ]
    }
}

/// Linear-interpolated quantile of an already sorted slice.
pub fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let pos = q * (sorted.len() - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo as f64)
}

/// How well one feature alone separates two groups, as ROC-AUC.
///
/// 0.5 is a coin flip. The value is symmetric around 0.5 by design — a feature that predicts the
/// wrong way is just as useful to an adversary, so the caller sees `max(auc, 1 - auc)` as
/// `separation`.
pub fn auc(group_a: &[f64], group_b: &[f64]) -> f64 {
    if group_a.is_empty() || group_b.is_empty() {
        return 0.5;
    }
    let mut wins = 0.0;
    for &a in group_a {
        for &b in group_b {
            wins += match a.partial_cmp(&b) {
                Some(std::cmp::Ordering::Greater) => 1.0,
                Some(std::cmp::Ordering::Equal) => 0.5,
                _ => 0.0,
            };
        }
    }
    wins / (group_a.len() * group_b.len()) as f64
}

/// What one feature achieves against the two sets of connections.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeatureSeparation {
    pub feature: &'static str,
    /// `max(auc, 1 - auc)`: 0.5 = useless to an adversary, 1.0 = perfect.
    pub separation: f64,
}

/// Ranks every feature by how well it separates the two sets, best first.
///
/// Read the top row, not the average: an adversary uses the feature that works, and a mean over
/// features would hide it behind the ones that do not.
pub fn separations(a: &[ConnectionFeatures], b: &[ConnectionFeatures]) -> Vec<FeatureSeparation> {
    let names: Vec<&'static str> = a
        .first()
        .or(b.first())
        .map(|f| f.named().into_iter().map(|(n, _)| n).collect())
        .unwrap_or_default();

    let mut out: Vec<FeatureSeparation> = names
        .into_iter()
        .enumerate()
        .map(|(i, feature)| {
            let xs: Vec<f64> = a.iter().map(|f| f.named()[i].1).collect();
            let ys: Vec<f64> = b.iter().map(|f| f.named()[i].1).collect();
            let raw = auc(&xs, &ys);
            FeatureSeparation { feature, separation: raw.max(1.0 - raw) }
        })
        .collect();
    out.sort_by(|x, y| y.separation.partial_cmp(&x.separation).expect("no NaN"));
    out
}

/// How many connections a claim rests on. Printed next to every separation so a result from three
/// captures cannot be read as a result from three hundred.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Support {
    pub connections_a: usize,
    pub connections_b: usize,
}

impl Support {
    /// Whether there are enough connections for the numbers to mean anything at all.
    ///
    /// Not a power calculation — a tripwire. With a handful of connections per side the best
    /// feature's AUC is dominated by which captures happened to be taken.
    pub fn is_suggestive_only(&self) -> bool {
        self.connections_a < 20 || self.connections_b < 20
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::CT_APPLICATION_DATA;

    fn rec(t: f64, len: usize, dir: Direction) -> Record {
        Record { t, dir, len, ct: CT_APPLICATION_DATA }
    }

    #[test]
    fn a_metronome_has_no_spread_in_its_gaps() {
        let records: Vec<Record> =
            (0..20).map(|i| rec(i as f64 * 0.5, 261, Direction::Up)).collect();

        let f = ConnectionFeatures::from_records(&records).unwrap();

        assert_eq!(f.median_gap, 0.5);
        assert_eq!(f.gap_iqr, 0.0, "a fixed cadence is exactly this");
        assert_eq!(f.distinct_sizes, 1);
        assert_eq!(f.modal_size_share, 1.0);
    }

    /// The shape the rig is meant to catch: bucketed sizes concentrate, ordinary traffic spreads.
    #[test]
    fn bucketing_shows_up_as_few_distinct_sizes() {
        let bucketed: Vec<Record> = (0..30)
            .map(|i| rec(i as f64, [261, 1029][i % 2], Direction::Up))
            .collect();
        let web: Vec<Record> =
            (0..30).map(|i| rec(i as f64, 200 + i * 37, Direction::Up)).collect();

        let b = ConnectionFeatures::from_records(&bucketed).unwrap();
        let w = ConnectionFeatures::from_records(&web).unwrap();

        assert_eq!(b.distinct_sizes, 2);
        assert_eq!(w.distinct_sizes, 30);
        assert!(b.modal_size_share > w.modal_size_share);
    }

    /// One record is not a connection — no gaps exist, so no timing feature does either.
    #[test]
    fn a_connection_with_one_record_yields_nothing() {
        assert!(ConnectionFeatures::from_records(&[rec(1.0, 261, Direction::Up)]).is_none());
    }

    /// Handshake records must not be mixed in: a large certificate would dominate the size
    /// distribution of an otherwise tiny session.
    #[test]
    fn handshake_records_are_left_out_of_the_shape() {
        let records = vec![
            Record { t: 0.0, dir: Direction::Down, len: 4000, ct: 22 },
            rec(1.0, 261, Direction::Up),
            rec(2.0, 261, Direction::Up),
        ];

        let f = ConnectionFeatures::from_records(&records).unwrap();

        assert_eq!(f.records, 2);
        assert_eq!(f.bytes, 522, "the certificate is not part of the session's shape");
    }

    #[test]
    fn perfectly_separated_groups_score_one_and_overlapping_ones_score_half() {
        assert_eq!(auc(&[3.0, 4.0, 5.0], &[0.0, 1.0, 2.0]), 1.0);
        assert_eq!(auc(&[0.0, 1.0, 2.0], &[3.0, 4.0, 5.0]), 0.0);
        assert_eq!(auc(&[1.0, 2.0], &[1.0, 2.0]), 0.5);
    }

    /// A feature that predicts backwards is just as useful to an adversary, so separation folds
    /// the AUC around 0.5 rather than rewarding the direction we happened to label.
    #[test]
    fn separation_is_symmetric_so_a_backwards_feature_still_counts() {
        let quiet: Vec<ConnectionFeatures> = (0..5)
            .map(|i| {
                ConnectionFeatures::from_records(
                    &(0..10).map(|j| rec(j as f64, 261 + i, Direction::Up)).collect::<Vec<_>>(),
                )
                .unwrap()
            })
            .collect();
        let loud: Vec<ConnectionFeatures> = (0..5)
            .map(|i| {
                ConnectionFeatures::from_records(
                    &(0..10)
                        .map(|j| rec(j as f64 * 0.01, 9000 + i * 11, Direction::Up))
                        .collect::<Vec<_>>(),
                )
                .unwrap()
            })
            .collect();

        let ranked = separations(&quiet, &loud);

        assert!(ranked[0].separation > 0.99, "these two are trivially separable");
        assert!(ranked.iter().all(|f| f.separation >= 0.5 - 1e-9));
    }

    /// A handful of captures must announce itself as a handful.
    #[test]
    fn a_small_sample_is_flagged_as_suggestive() {
        assert!(Support { connections_a: 4, connections_b: 400 }.is_suggestive_only());
        assert!(!Support { connections_a: 20, connections_b: 20 }.is_suggestive_only());
    }

    #[test]
    fn quantiles_interpolate_and_survive_degenerate_input() {
        assert_eq!(quantile(&[], 0.5), 0.0);
        assert_eq!(quantile(&[7.0], 0.9), 7.0);
        assert_eq!(quantile(&[0.0, 1.0, 2.0, 3.0], 0.5), 1.5);
    }
}
