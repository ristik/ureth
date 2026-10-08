//! The weight quantization rule (bft-core `briefs/leader-lookup.md` as amended by
//! `leader-lookup-review.md`, F2).
//!
//! The committed voting, leader, reward and threshold weight `q` of a committee is derived from the
//! raw bonded weights `x` so that the committed total never exceeds the profile cap `B`:
//!
//! ```text
//! X = sum(x);  if X <= B:  q = x;  else  s = ceil(X / (B - n)),  q_i = max(1, floor(x_i / s)).
//! ```
//!
//! `Σq <= X/s + n <= B` and `1 <= q_i <= x_i`. The election (unicity-pos-contracts `Quantize.sol`),
//! the root (`evmassign.Quantize`) and this module evaluate the same pure function;
//! `testdata/quant-vectors.json` is the shared vector set.
//!
//! Security premise: BFT safety assumes the Byzantine committed `q`-weight is below one third, not
//! the raw stake. For any member subset `S`, `|q(S)/Q - x(S)/X| < 2n/Q` with `Q = Σq`; with `Q >
//! (B+1)/2 - n` (about 32,700 at `n = 64`) the shift is under 0.4%.

/// The profile cap on the total committed weight of a committee: the one constant of the bounded
/// weighted leader lookup. Every admission point refuses a committed total above it.
pub const WEIGHT_CAP_B: u64 = 65_536;

/// Raw weights the rule is not defined for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuantError {
    /// No members, or `n >= B`.
    Committee,
    /// A weight is zero.
    ZeroWeight,
    /// The raw total exceeds `u64::MAX`.
    Overflow,
}

/// `q = quant(x, n, b)` and the divisor `s` the rule used (1 when `X <= b`).
pub fn quantize(x: &[u64], b: u64) -> Result<(Vec<u64>, u64), QuantError> {
    let n = x.len() as u64;
    if n == 0 || n >= b {
        return Err(QuantError::Committee);
    }
    let mut total = 0u64;
    for &v in x {
        if v == 0 {
            return Err(QuantError::ZeroWeight);
        }
        total = total.checked_add(v).ok_or(QuantError::Overflow)?;
    }
    if total <= b {
        return Ok((x.to_vec(), 1));
    }
    let room = b - n;
    let s = total.div_ceil(room);
    Ok((x.iter().map(|&v| (v / s).max(1)).collect(), s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Case {
        name: String,
        b: u64,
        x: Vec<String>,
        q: Option<Vec<String>>,
        s: Option<String>,
        error: Option<bool>,
    }

    #[derive(Deserialize)]
    struct Vectors {
        b: u64,
        cases: Vec<Case>,
    }

    fn nums(v: &[String]) -> Vec<u64> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn the_shared_vectors() {
        let raw = include_str!("../testdata/quant-vectors.json");
        let vectors: Vectors = serde_json::from_str(raw).unwrap();
        assert_eq!(vectors.b, WEIGHT_CAP_B);
        assert!(vectors.cases.len() > 30);
        for c in &vectors.cases {
            let got = quantize(&nums(&c.x), c.b);
            if c.error == Some(true) {
                assert!(got.is_err(), "{}", c.name);
                continue;
            }
            let (q, s) = got.unwrap_or_else(|e| panic!("{}: {e:?}", c.name));
            assert_eq!(q, nums(c.q.as_ref().unwrap()), "{}", c.name);
            assert_eq!(s, c.s.as_ref().unwrap().parse::<u64>().unwrap(), "{}", c.name);
        }
    }

    #[test]
    fn refusals_differ_from_a_valid_input_in_one_thing() {
        assert!(quantize(&[1, 2, 3], 100).is_ok());
        assert_eq!(quantize(&[], 100), Err(QuantError::Committee));
        assert_eq!(quantize(&[1, 1], 2), Err(QuantError::Committee));
        assert_eq!(quantize(&[1, 0, 3], 100), Err(QuantError::ZeroWeight));
        assert_eq!(quantize(&[u64::MAX, 1], 100), Err(QuantError::Overflow));
    }

    #[test]
    fn invariants_hold_over_many_inputs() {
        for seed in 1u64..=300 {
            let n = 1 + (seed * 7919 % 100) as usize;
            let mag = 1u64 << (1 + seed % 40);
            let x: Vec<u64> =
                (0..n).map(|i| (seed * 2654435761 + i as u64 * 40503) % mag + 1).collect();
            let total: u64 = x.iter().sum();
            let (q, _) = quantize(&x, WEIGHT_CAP_B).unwrap();
            assert!(q.iter().sum::<u64>() <= WEIGHT_CAP_B);
            for i in 0..n {
                assert!(q[i] >= 1 && q[i] <= x[i]);
                for j in 0..n {
                    if x[i] >= x[j] {
                        assert!(q[i] >= q[j], "the raw order is preserved weakly");
                    }
                }
                if total <= WEIGHT_CAP_B {
                    assert_eq!(q[i], x[i]);
                }
            }
        }
    }
}
