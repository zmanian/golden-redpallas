//! Deterministic Pallas proof-skeleton benchmark harness.

use std::time::Instant;

use golden_core::{FieldElement, ParticipantId, Polynomial};
use golden_pallas::{
    DkgFixture, HelperSecretKey, PallasPoint, PallasScalar, SimulationDealer,
    SimulationParticipant, VestaScalar, commit_polynomial, derive_mask,
};
use golden_proofs::{
    PallasProofSkeleton, ProofBatchItem, ProofPublicInputs, ProofSystem, ProofWitness,
    ProofedDkgSimulation,
};

const BENCH_SIZES: [u64; 4] = [4, 8, 16, 32];
const CSV_HEADER: &str = "n,threshold,dealers,proofs,proof_bytes,prove_micros,prove_rss_bytes,verify_one_micros,verify_batch_micros,verify_all_micros";
const SINGLE_PROOF_CSV_HEADER: &str =
    "scenario,proofs,proof_bytes,prove_micros,prove_rss_bytes,verify_micros";
const CIRCUIT_PROFILE_CSV_HEADER: &str = "scenario,circuit,committed_vars,internal_vars,constraints,columns,padded_vars,ipa_log_len,total_constraints";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DkgProgress {
    SizeStart {
        n: u64,
        threshold: usize,
        dealers: usize,
    },
    ProofGenerationStart {
        n: u64,
    },
    ProofGenerationEnd {
        n: u64,
        proofs: usize,
        proof_bytes: usize,
    },
    VerifyOneStart {
        n: u64,
    },
    VerifyBatchStart {
        n: u64,
    },
    VerifyAllStart {
        n: u64,
    },
    SizeEnd {
        n: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum BenchmarkCommand {
    Dkg { sizes: Vec<u64> },
    SingleProof,
    CircuitProfile,
}

fn main() {
    let command = parse_command(std::env::args().skip(1)).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(2);
    });

    match command {
        BenchmarkCommand::Dkg { sizes } => run_dkg_benchmarks(&sizes),
        BenchmarkCommand::SingleProof => run_single_proof_benchmark(),
        BenchmarkCommand::CircuitProfile => run_circuit_profile_benchmark(),
    }
}

fn run_dkg_benchmarks(sizes: &[u64]) {
    println!("{CSV_HEADER}");

    for &n in sizes {
        let fixture = bench_fixture(n);
        let threshold = fixture.threshold;
        emit_dkg_progress(DkgProgress::SizeStart {
            n,
            threshold,
            dealers: fixture.dealers.len(),
        });

        emit_dkg_progress(DkgProgress::ProofGenerationStart { n });
        let prove_start = Instant::now();
        let proofed =
            ProofedDkgSimulation::<PallasProofSkeleton>::from_fixture(&fixture).expect("proofed");
        let prove_micros = prove_start.elapsed().as_micros();
        let prove_rss_bytes = rss_bytes();
        let proof_count = proofed
            .proofed_transcripts
            .iter()
            .map(|transcript| transcript.proofs.len())
            .sum::<usize>();
        let proof_bytes = proofed
            .proofed_transcripts
            .iter()
            .flat_map(|transcript| &transcript.proofs)
            .map(|entry| entry.proof.bytes.len())
            .sum::<usize>();
        emit_dkg_progress(DkgProgress::ProofGenerationEnd {
            n,
            proofs: proof_count,
            proof_bytes,
        });

        let first_participant = proofed.simulation.participants[0].id;
        emit_dkg_progress(DkgProgress::VerifyOneStart { n });
        let verify_one_start = Instant::now();
        proofed
            .recover_participant(first_participant)
            .expect("first participant recovers");
        let verify_one_micros = verify_one_start.elapsed().as_micros();

        let first_batch = batch_for_participant(&proofed, first_participant);
        emit_dkg_progress(DkgProgress::VerifyBatchStart { n });
        let verify_batch_start = Instant::now();
        PallasProofSkeleton::verify_batch(&first_batch).expect("first participant batch verifies");
        let verify_batch_micros = verify_batch_start.elapsed().as_micros();

        emit_dkg_progress(DkgProgress::VerifyAllStart { n });
        let verify_all_start = Instant::now();
        for participant in &proofed.simulation.participants {
            proofed
                .recover_participant(participant.id)
                .expect("participant recovers");
        }
        let verify_all_micros = verify_all_start.elapsed().as_micros();

        println!(
            "{n},{threshold},{dealers},{proof_count},{proof_bytes},{prove_micros},{prove_rss_bytes},{verify_one_micros},{verify_batch_micros},{verify_all_micros}",
            dealers = proofed.simulation.dealers.len(),
        );
        emit_dkg_progress(DkgProgress::SizeEnd { n });
    }
}

fn emit_dkg_progress(progress: DkgProgress) {
    eprintln!("{}", format_dkg_progress(progress));
}

fn format_dkg_progress(progress: DkgProgress) -> String {
    match progress {
        DkgProgress::SizeStart {
            n,
            threshold,
            dealers,
        } => format!(
            "pallas_bench: n={n} starting DKG benchmark, threshold={threshold}, dealers={dealers}"
        ),
        DkgProgress::ProofGenerationStart { n } => {
            format!("pallas_bench: n={n} proving proofs")
        }
        DkgProgress::ProofGenerationEnd {
            n,
            proofs,
            proof_bytes,
        } => format!("pallas_bench: n={n} proved {proofs} proofs, {proof_bytes} proof bytes"),
        DkgProgress::VerifyOneStart { n } => {
            format!("pallas_bench: n={n} verifying first participant recovery")
        }
        DkgProgress::VerifyBatchStart { n } => {
            format!("pallas_bench: n={n} verifying first participant batch")
        }
        DkgProgress::VerifyAllStart { n } => {
            format!("pallas_bench: n={n} verifying all participant recoveries")
        }
        DkgProgress::SizeEnd { n } => format!("pallas_bench: n={n} complete"),
    }
}

fn run_single_proof_benchmark() {
    println!("{SINGLE_PROOF_CSV_HEADER}");

    let (public_inputs, witness) = single_proof_case();
    let prove_start = Instant::now();
    let proof = PallasProofSkeleton::prove(&public_inputs, &witness).expect("proof");
    let prove_micros = prove_start.elapsed().as_micros();
    let prove_rss_bytes = rss_bytes();

    let verify_start = Instant::now();
    PallasProofSkeleton::verify(&public_inputs, &proof).expect("proof verifies");
    let verify_micros = verify_start.elapsed().as_micros();

    println!(
        "single-proof,1,{proof_bytes},{prove_micros},{prove_rss_bytes},{verify_micros}",
        proof_bytes = proof.bytes.len(),
    );
}

fn run_circuit_profile_benchmark() {
    println!("{CIRCUIT_PROFILE_CSV_HEADER}");

    let (public_inputs, _) = single_proof_case();
    let profile = PallasProofSkeleton::circuit_profile(&public_inputs).expect("profile");
    print_circuit_profile_row(
        "single-proof",
        "mask",
        profile.mask,
        profile.total_constraints(),
    );
    print_circuit_profile_row(
        "single-proof",
        "vesta-dh",
        profile.vesta_dh,
        profile.total_constraints(),
    );
}

fn print_circuit_profile_row(
    scenario: &str,
    circuit: &str,
    profile: golden_proofs::PallasCircuitProfile,
    total_constraints: usize,
) {
    println!(
        "{scenario},{circuit},{committed_vars},{internal_vars},{constraints},{columns},{padded_vars},{ipa_log_len},{total_constraints}",
        committed_vars = profile.committed_vars,
        internal_vars = profile.internal_vars,
        constraints = profile.constraints,
        columns = profile.columns,
        padded_vars = profile.padded_vars,
        ipa_log_len = profile.ipa_log_len,
    );
}

fn parse_command(
    args: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<BenchmarkCommand, String> {
    let args = args
        .into_iter()
        .map(|arg| arg.as_ref().to_string())
        .collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == "--single-proof") {
        if args.len() != 1 {
            return Err(
                "usage: pallas_bench [--sizes 4,8,16,32] [--single-proof] [--circuit-profile]"
                    .to_string(),
            );
        }
        return Ok(BenchmarkCommand::SingleProof);
    }
    if args.first().is_some_and(|arg| arg == "--circuit-profile") {
        if args.len() != 1 {
            return Err(
                "usage: pallas_bench [--sizes 4,8,16,32] [--single-proof] [--circuit-profile]"
                    .to_string(),
            );
        }
        return Ok(BenchmarkCommand::CircuitProfile);
    }

    parse_sizes(args).map(|sizes| BenchmarkCommand::Dkg { sizes })
}

fn parse_sizes(args: impl IntoIterator<Item = impl AsRef<str>>) -> Result<Vec<u64>, String> {
    let mut args = args.into_iter();
    let Some(first) = args.next() else {
        return Ok(BENCH_SIZES.to_vec());
    };

    if first.as_ref() != "--sizes" {
        return Err("usage: pallas_bench [--sizes 4,8,16,32]".to_string());
    }

    let Some(raw_sizes) = args.next() else {
        return Err("--sizes requires a comma-separated value".to_string());
    };
    if args.next().is_some() {
        return Err("usage: pallas_bench [--sizes 4,8,16,32]".to_string());
    }

    let mut sizes = Vec::new();
    for raw in raw_sizes.as_ref().split(',') {
        let size = raw
            .parse::<u64>()
            .map_err(|_| format!("invalid benchmark size: {raw}"))?;
        if !BENCH_SIZES.contains(&size) {
            return Err(format!("unsupported benchmark size: {size}"));
        }
        sizes.push(size);
    }
    if sizes.is_empty() {
        return Err("--sizes requires at least one size".to_string());
    }

    Ok(sizes)
}

#[cfg(target_os = "linux")]
fn rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| parse_status_rss_bytes(&status))
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn rss_bytes() -> u64 {
    std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|stdout| parse_ps_rss_bytes(&stdout))
        .unwrap_or(0)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const fn rss_bytes() -> u64 {
    0
}

#[cfg(target_os = "linux")]
fn parse_status_rss_bytes(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(parse_kib_rss_bytes)
}

#[cfg(any(test, target_os = "macos"))]
fn parse_ps_rss_bytes(output: &str) -> Option<u64> {
    output
        .split_whitespace()
        .next()
        .and_then(parse_kib_rss_bytes)
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn parse_kib_rss_bytes(value: &str) -> Option<u64> {
    value
        .parse::<u64>()
        .ok()
        .map(|kib| kib.saturating_mul(1024))
}

fn batch_for_participant(
    proofed: &ProofedDkgSimulation<PallasProofSkeleton>,
    participant: ParticipantId,
) -> Vec<ProofBatchItem<'_>> {
    proofed
        .proofed_transcripts
        .iter()
        .map(|transcript| {
            let proof = transcript
                .proofs
                .iter()
                .find(|entry| entry.participant == participant)
                .expect("proofed simulation includes every participant proof");
            ProofBatchItem {
                public_inputs: &proof.public_inputs,
                proof: &proof.proof,
            }
        })
        .collect()
}

fn bench_fixture(n: u64) -> DkgFixture {
    let threshold = usize::try_from((n / 2) + 1).expect("benchmark threshold fits usize");
    let participants = (1..=n)
        .map(|id| {
            SimulationParticipant::from_u64(id, 10_000 + id)
                .expect("benchmark participant ids are valid")
        })
        .collect();
    let dealers = (1..=n)
        .map(|dealer_index| {
            let dealer_id = 1_000 + dealer_index;
            let coefficients = coefficients_for(dealer_index, threshold);
            SimulationDealer::from_u64(dealer_id, 20_000 + dealer_index, &coefficients)
                .expect("benchmark dealer ids are valid")
        })
        .collect();

    DkgFixture {
        threshold,
        session_id: format!("golden-pallas-proof-bench-n-{n}").into_bytes(),
        participants,
        dealers,
    }
}

fn coefficients_for(dealer_index: u64, threshold: usize) -> Vec<u64> {
    (0..threshold)
        .map(|coefficient_index| {
            100_000 + (dealer_index * 1_000) + u64::try_from(coefficient_index).expect("fits u64")
        })
        .collect()
}

fn single_proof_case() -> (ProofPublicInputs, ProofWitness) {
    let dealer_secret = HelperSecretKey::from_scalar(VestaScalar::from_u64(13));
    let participant_secret = HelperSecretKey::from_scalar(VestaScalar::from_u64(29));
    let public_polynomial = commit_polynomial(&Polynomial::new(vec![
        PallasScalar::from_u64(5),
        PallasScalar::from_u64(7),
    ]));
    let shared_point = dealer_secret.diffie_hellman(participant_secret.public_key());
    let mask = derive_mask(shared_point, &{
        let inputs = ProofPublicInputs {
            session_id: b"proof-smoke-bench-session".to_vec(),
            dealer_id: benchmark_id(10),
            participant_id: benchmark_id(1),
            dealer_public: dealer_secret.public_key(),
            participant_public: participant_secret.public_key(),
            mask_commitment: PallasPoint::identity(),
            public_polynomial: public_polynomial.clone(),
        };
        inputs.mask_transcript()
    });
    let public_inputs = ProofPublicInputs {
        session_id: b"proof-smoke-bench-session".to_vec(),
        dealer_id: benchmark_id(10),
        participant_id: benchmark_id(1),
        dealer_public: dealer_secret.public_key(),
        participant_public: participant_secret.public_key(),
        mask_commitment: PallasPoint::generator_mul(mask),
        public_polynomial,
    };
    let witness = ProofWitness {
        dealer_secret: dealer_secret.scalar(),
        shared_point: shared_point.point(),
        mask,
    };
    (public_inputs, witness)
}

fn benchmark_id(value: u64) -> ParticipantId {
    ParticipantId::new(value).expect("benchmark participant id is non-zero")
}

#[cfg(test)]
mod tests {
    use super::{BENCH_SIZES, CIRCUIT_PROFILE_CSV_HEADER, CSV_HEADER, SINGLE_PROOF_CSV_HEADER};

    #[test]
    fn benchmark_sizes_cover_small_and_roadmap_configurations() {
        assert_eq!(BENCH_SIZES.as_slice(), &[4, 8, 16, 32]);
    }

    #[test]
    fn benchmark_schema_reports_size_and_batch_verifier_columns() {
        assert!(CSV_HEADER.contains("proof_bytes"));
        assert!(CSV_HEADER.contains("prove_rss_bytes"));
        assert!(CSV_HEADER.contains("verify_batch_micros"));
    }

    #[test]
    fn single_proof_schema_reports_proof_size_and_verifier_columns() {
        assert!(SINGLE_PROOF_CSV_HEADER.contains("proof_bytes"));
        assert!(SINGLE_PROOF_CSV_HEADER.contains("prove_rss_bytes"));
        assert!(SINGLE_PROOF_CSV_HEADER.contains("verify_micros"));
    }

    #[test]
    fn circuit_profile_schema_reports_linked_circuit_columns() {
        assert!(CIRCUIT_PROFILE_CSV_HEADER.contains("circuit"));
        assert!(CIRCUIT_PROFILE_CSV_HEADER.contains("constraints"));
        assert!(CIRCUIT_PROFILE_CSV_HEADER.contains("ipa_log_len"));
    }

    #[test]
    fn dkg_progress_messages_identify_size_and_phase() {
        assert_eq!(
            super::format_dkg_progress(super::DkgProgress::ProofGenerationStart { n: 16 }),
            "pallas_bench: n=16 proving proofs"
        );
        assert_eq!(
            super::format_dkg_progress(super::DkgProgress::ProofGenerationEnd {
                n: 16,
                proofs: 256,
                proof_bytes: 752_384,
            }),
            "pallas_bench: n=16 proved 256 proofs, 752384 proof bytes"
        );
        assert_eq!(
            super::format_dkg_progress(super::DkgProgress::VerifyAllStart { n: 16 }),
            "pallas_bench: n=16 verifying all participant recoveries"
        );
    }

    #[test]
    fn parses_ps_rss_output_as_bytes() {
        assert_eq!(super::parse_ps_rss_bytes("  12345\n"), Some(12_641_280));
    }

    #[test]
    fn parses_explicit_benchmark_sizes() {
        assert_eq!(super::parse_sizes(["--sizes", "4,8"]), Ok(vec![4, 8]));
    }

    #[test]
    fn rejects_unsupported_benchmark_sizes() {
        assert!(super::parse_sizes(["--sizes", "5"]).is_err());
    }

    #[test]
    fn parses_single_proof_benchmark_mode() {
        assert_eq!(
            super::parse_command(["--single-proof"]),
            Ok(super::BenchmarkCommand::SingleProof)
        );
    }

    #[test]
    fn parses_circuit_profile_benchmark_mode() {
        assert_eq!(
            super::parse_command(["--circuit-profile"]),
            Ok(super::BenchmarkCommand::CircuitProfile)
        );
    }
}
