//! Pallas-field Bulletproofs circuit shape.
//!
//! This module is the R1CS-facing layer that feeds the Pallas IPA proof
//! primitive. It pins the committed-value/internal-wire layout and emits the
//! auditable circuit proof object used by the feature-gated Pallas backend.

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::{Index, IndexMut},
};

use blake2b_simd::Params;
use golden_core::FieldElement;
use golden_pallas::{PallasPoint, PallasScalar};
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;

use super::{
    PallasIpaClaim, PallasIpaProof, PallasIpaSetup, PallasIpaWitness, derive_pallas_generator,
};
use crate::ProofError;

const CIRCUIT_TRANSCRIPT_DOMAIN: &[u8] = b"GoldenRedPallas/PallasCircuitTranscript/v1";
const CIRCUIT_BLINDING_GENERATOR_LABEL: &[u8] = b"circuit-blinding";
const CIRCUIT_PROOF_MAGIC: &[u8; 4] = b"GPCB";
const CIRCUIT_PROOF_VERSION: u8 = 0;

/// Sparse Pallas scalar matrix indexed by `(row, column)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PallasSparseMatrix {
    width: usize,
    height: usize,
    weights: BTreeMap<(usize, usize), PallasScalar>,
    zero: PallasScalar,
}

impl PallasSparseMatrix {
    /// Create an empty sparse matrix with explicit dimensions.
    #[must_use]
    pub fn with_dimensions(width: usize, height: usize) -> Self {
        let mut matrix = Self::default();
        matrix.pad(width, height);
        matrix
    }

    /// Matrix width inferred from the largest populated column.
    #[must_use]
    pub const fn width(&self) -> usize {
        self.width
    }

    /// Matrix height inferred from the largest populated row.
    #[must_use]
    pub const fn height(&self) -> usize {
        self.height
    }

    fn pad(&mut self, width: usize, height: usize) {
        self.width = self.width.max(width);
        self.height = self.height.max(height);
    }
}

impl Default for PallasSparseMatrix {
    fn default() -> Self {
        Self {
            width: 0,
            height: 0,
            weights: BTreeMap::new(),
            zero: PallasScalar::ZERO,
        }
    }
}

impl Index<(usize, usize)> for PallasSparseMatrix {
    type Output = PallasScalar;

    fn index(&self, index: (usize, usize)) -> &Self::Output {
        self.weights.get(&index).unwrap_or(&self.zero)
    }
}

impl IndexMut<(usize, usize)> for PallasSparseMatrix {
    fn index_mut(&mut self, index: (usize, usize)) -> &mut Self::Output {
        self.height = self
            .height
            .max(index.0.checked_add(1).expect("row index fits in usize"));
        self.width = self
            .width
            .max(index.1.checked_add(1).expect("column index fits in usize"));
        self.weights.entry(index).or_insert(PallasScalar::ZERO)
    }
}

/// Circuit constraints over the layout `1 | committed | left | right | output`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PallasCircuit {
    committed_vars: usize,
    internal_vars: usize,
    weights: PallasSparseMatrix,
    transcript_digest: [u8; 32],
}

impl PallasCircuit {
    /// Create a circuit for a sparse linear constraint matrix.
    ///
    /// Returns `None` when the matrix width is incompatible with the fixed
    /// `1 | committed | left | right | output` layout.
    #[must_use]
    pub fn new(committed_vars: usize, weights: PallasSparseMatrix) -> Option<Self> {
        let remaining_vars = weights.width.checked_sub(committed_vars.checked_add(1)?)?;
        if remaining_vars % 3 != 0 {
            return None;
        }

        let internal_vars = remaining_vars / 3;
        let transcript_digest = circuit_transcript_digest(committed_vars, internal_vars, &weights);

        Some(Self {
            committed_vars,
            internal_vars,
            weights,
            transcript_digest,
        })
    }

    /// Number of committed variables.
    #[must_use]
    pub const fn committed_vars(&self) -> usize {
        self.committed_vars
    }

    /// Number of left/right/output internal wires.
    #[must_use]
    pub const fn internal_vars(&self) -> usize {
        self.internal_vars
    }

    /// Number of R1CS constraint rows in this circuit.
    #[must_use]
    pub const fn constraint_count(&self) -> usize {
        self.weights.height()
    }

    /// Number of columns in the committed/internal/output assignment layout.
    #[must_use]
    pub const fn column_count(&self) -> usize {
        self.weights.width()
    }

    /// Check whether an assignment satisfies this circuit.
    #[must_use]
    pub fn is_satisfied(
        &self,
        committed_values: &[PallasScalar],
        left_values: &[PallasScalar],
        right_values: &[PallasScalar],
    ) -> bool {
        if committed_values.len() != self.committed_vars
            || left_values.len() != self.internal_vars
            || right_values.len() != self.internal_vars
        {
            return false;
        }

        let mut assignment = Vec::with_capacity(1 + self.committed_vars + 3 * self.internal_vars);
        assignment.push(PallasScalar::ONE);
        assignment.extend_from_slice(committed_values);
        assignment.extend_from_slice(left_values);
        assignment.extend_from_slice(right_values);
        assignment.extend(
            left_values
                .iter()
                .zip(right_values)
                .map(|(&left, &right)| left * right),
        );

        let mut row_sums = vec![PallasScalar::ZERO; self.weights.height];
        for (&(row, column), &weight) in &self.weights.weights {
            let Some(&value) = assignment.get(column) else {
                continue;
            };
            row_sums[row] += weight * value;
        }
        row_sums.iter().all(|sum| sum.is_zero())
    }
}

/// Prover-side assignment for a Pallas circuit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PallasCircuitWitness {
    values: Vec<PallasScalar>,
    blinding: Vec<PallasScalar>,
    left: Vec<PallasScalar>,
    right: Vec<PallasScalar>,
    output: Vec<PallasScalar>,
}

impl PallasCircuitWitness {
    /// Create a circuit witness with matching left/right/output wire lengths.
    #[must_use]
    pub fn new(
        values: Vec<PallasScalar>,
        left: Vec<PallasScalar>,
        right: Vec<PallasScalar>,
        output: Vec<PallasScalar>,
    ) -> Option<Self> {
        let blinding = vec![PallasScalar::ZERO; values.len()];
        Self::new_with_blinding(values, blinding, left, right, output)
    }

    /// Create a circuit witness with committed-value blindings.
    #[must_use]
    pub fn new_with_blinding(
        values: Vec<PallasScalar>,
        blinding: Vec<PallasScalar>,
        left: Vec<PallasScalar>,
        right: Vec<PallasScalar>,
        output: Vec<PallasScalar>,
    ) -> Option<Self> {
        if values.len() != blinding.len() {
            return None;
        }
        if left.len() != right.len() || right.len() != output.len() {
            return None;
        }

        Some(Self {
            values,
            blinding,
            left,
            right,
            output,
        })
    }

    /// Check whether this witness satisfies the circuit.
    #[must_use]
    pub fn is_satisfied(&self, circuit: &PallasCircuit) -> bool {
        self.output
            .iter()
            .zip(self.left.iter().zip(&self.right))
            .all(|(&output, (&left, &right))| output == left * right)
            && circuit.is_satisfied(&self.values, &self.left, &self.right)
    }

    /// Build the public Pedersen commitment claim for this witness.
    #[must_use]
    pub fn claim(&self, setup: &PallasCircuitSetup) -> PallasCircuitClaim {
        PallasCircuitClaim {
            commitments: self
                .values
                .iter()
                .zip(&self.blinding)
                .map(|(&value, &blinding)| setup.commit_value(value, blinding))
                .collect(),
        }
    }
}

/// Generator setup for a Pallas Bulletproofs circuit proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PallasCircuitSetup {
    ipa: PallasIpaSetup,
    value_generator: PallasPoint,
    blinding_generator: PallasPoint,
    transcript_digest: [u8; 32],
}

impl PallasCircuitSetup {
    /// Build deterministic circuit generators for `2^log_len` internal wires.
    #[must_use]
    pub fn deterministic(domain: &[u8], log_len: u8, value_generator: PallasPoint) -> Self {
        let ipa = PallasIpaSetup::deterministic(domain, log_len);
        let blinding_generator = derive_circuit_generator(domain, CIRCUIT_BLINDING_GENERATOR_LABEL);
        let transcript_digest =
            setup_transcript_digest(ipa.transcript_digest(), value_generator, blinding_generator);
        Self {
            ipa,
            value_generator,
            blinding_generator,
            transcript_digest,
        }
    }

    /// Commit to a circuit value with this setup's Pedersen generators.
    #[must_use]
    pub fn commit_value(&self, value: PallasScalar, blinding: PallasScalar) -> PallasPoint {
        self.value_generator.mul_scalar(value) + self.blinding_generator.mul_scalar(blinding)
    }

    fn supports(&self, len: usize) -> bool {
        self.ipa.g().len() >= len && self.ipa.h().len() >= len
    }
}

/// Public commitments for a Pallas circuit proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PallasCircuitClaim {
    /// Pedersen commitments to committed witness values.
    pub commitments: Vec<PallasPoint>,
}

/// Pallas Bulletproofs circuit proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PallasCircuitProof {
    m_big: PallasPoint,
    o_big: PallasPoint,
    m_big_tilde: PallasPoint,
    t_big: [PallasPoint; 5],
    s_tilde: PallasScalar,
    t_x: PallasScalar,
    t_tilde_x: PallasScalar,
    p_big: PallasPoint,
    ipa_proof: PallasIpaProof,
}

impl PallasCircuitProof {
    /// Prove that `witness` satisfies `circuit` and opens `claim`.
    pub fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        setup: &PallasCircuitSetup,
        circuit: &PallasCircuit,
        claim: &PallasCircuitClaim,
        witness: &PallasCircuitWitness,
    ) -> Result<Self, ProofError> {
        if !witness.is_satisfied(circuit)
            || witness.values.len() != circuit.committed_vars
            || claim != &witness.claim(setup)
        {
            return Err(ProofError::InvalidWitness);
        }

        let padded_vars = padded_vars(circuit);
        if !setup.supports(padded_vars) {
            return Err(ProofError::InvalidWitness);
        }

        let wire_commitments = WireCommitments::new(rng, setup, circuit, witness);

        let mut transcript = PallasCircuitTranscript::new();
        transcript.commit_setup(setup);
        transcript.commit_circuit(circuit);
        transcript.commit_claim(claim);
        transcript.commit_point(b"M", wire_commitments.m_big);
        transcript.commit_point(b"O", wire_commitments.o_big);
        transcript.commit_point(b"M-tilde", wire_commitments.m_big_tilde);

        let y = transcript.challenge(b"y");
        let y_inv = y.invert().ok_or(ProofError::InvalidProof)?;
        let z = transcript.challenge(b"z");
        let reduced = ReducedCircuit::new(circuit, y, z);
        let polynomial = polynomial_state(
            setup,
            circuit,
            witness,
            &reduced,
            &wire_commitments.left_blinding,
            &wire_commitments.right_blinding,
            rng,
        );

        let t_big = std::array::from_fn(|index| {
            let t_index = if index >= 1 { index + 1 } else { index };
            setup.value_generator.mul_scalar(polynomial.t[t_index])
                + setup
                    .blinding_generator
                    .mul_scalar(polynomial.t_tilde[t_index])
        });
        for (index, point) in t_big.iter().enumerate() {
            transcript.commit_point(format_label(b"T", index), *point);
        }
        let x = powers_from_base(transcript.challenge(b"x"), 6);
        let s_tilde = (wire_commitments.m_blinding * x[0])
            + (wire_commitments.output_blinding * x[1])
            + (wire_commitments.m_tilde_blinding * x[2]);
        let p_big = setup.blinding_generator.mul_scalar(-s_tilde)
            + polynomial.p_0
            + (polynomial.p_1 + wire_commitments.m_big).mul_scalar(x[0])
            + wire_commitments.o_big.mul_scalar(x[1])
            + wire_commitments.m_big_tilde.mul_scalar(x[2]);
        let t_x = inner_product(&polynomial.t, &x);
        let t_tilde_x = inner_product(&polynomial.t_tilde, &x);

        let ipa_claim = PallasIpaClaim {
            commitment: p_big,
            product: t_x,
            y: y_inv,
            log_len: log_len(padded_vars),
        };
        let (f_x, g_x) = ipa_witness_vectors(
            circuit,
            witness,
            &reduced,
            &wire_commitments,
            &polynomial,
            &x,
            padded_vars,
        );
        let (ipa_witness, derived_ipa_claim) =
            PallasIpaWitness::new_with_claim(&setup.ipa, y_inv, f_x.into_iter().zip(g_x))
                .ok_or(ProofError::InvalidWitness)?;
        if derived_ipa_claim != ipa_claim {
            return Err(ProofError::InvalidWitness);
        }
        let ipa_proof = PallasIpaProof::prove(&setup.ipa, &ipa_claim, ipa_witness)?;

        Ok(Self {
            m_big: wire_commitments.m_big,
            o_big: wire_commitments.o_big,
            m_big_tilde: wire_commitments.m_big_tilde,
            t_big,
            s_tilde,
            t_x,
            t_tilde_x,
            p_big,
            ipa_proof,
        })
    }

    /// Verify this proof against a public circuit claim.
    pub fn verify(
        &self,
        setup: &PallasCircuitSetup,
        circuit: &PallasCircuit,
        claim: &PallasCircuitClaim,
    ) -> Result<(), ProofError> {
        if claim.commitments.len() != circuit.committed_vars {
            return Err(ProofError::InvalidProof);
        }

        let padded_vars = padded_vars(circuit);
        if !setup.supports(padded_vars) {
            return Err(ProofError::InvalidProof);
        }

        let mut transcript = PallasCircuitTranscript::new();
        transcript.commit_setup(setup);
        transcript.commit_circuit(circuit);
        transcript.commit_claim(claim);
        transcript.commit_point(b"M", self.m_big);
        transcript.commit_point(b"O", self.o_big);
        transcript.commit_point(b"M-tilde", self.m_big_tilde);
        let y = transcript.challenge(b"y");
        let y_inv = y.invert().ok_or(ProofError::InvalidProof)?;
        let z = transcript.challenge(b"z");
        let reduced = ReducedCircuit::new(circuit, y, z);

        for (index, point) in self.t_big.iter().enumerate() {
            transcript.commit_point(format_label(b"T", index), *point);
        }
        let x = powers_from_base(transcript.challenge(b"x"), 6);
        let y_inv_powers = powers_from_one(y_inv, padded_vars);
        let y_powers = powers_from_one(y, padded_vars);
        let mut omega_minus_y = reduced
            .omega
            .par_iter()
            .zip(y_powers.par_iter())
            .map(|(&omega, &y_power)| omega - y_power)
            .collect::<Vec<_>>();
        omega_minus_y.extend(
            y_powers
                .into_iter()
                .skip(circuit.internal_vars)
                .map(|y_power| -y_power),
        );
        let y_inv_rho = y_inv_powers
            .par_iter()
            .copied()
            .zip(reduced.rho.par_iter())
            .map(|(y_inv_power, &rho)| y_inv_power * rho)
            .collect::<Vec<_>>();
        let y_inv_lambda = y_inv_powers
            .par_iter()
            .copied()
            .zip(reduced.lambda.par_iter())
            .map(|(y_inv_power, &lambda)| y_inv_power * lambda)
            .collect::<Vec<_>>();
        let y_inv_omega_minus_y = y_inv_powers
            .par_iter()
            .copied()
            .zip(omega_minus_y.par_iter())
            .map(|(y_inv_power, &omega)| y_inv_power * omega)
            .collect::<Vec<_>>();
        let delta_y_z = inner_product(&y_inv_rho, &reduced.lambda);

        let t_left = setup.value_generator.mul_scalar(self.t_x)
            + setup.blinding_generator.mul_scalar(self.t_tilde_x);
        let theta_scaled = reduced
            .theta
            .par_iter()
            .map(|&theta| theta * x[1])
            .collect::<Vec<_>>();
        let t_terms = [x[0], x[2], x[3], x[4], x[5]];
        let t_right = setup
            .value_generator
            .mul_scalar((-reduced.kappa + delta_y_z) * x[1])
            - msm_points(&claim.commitments, &theta_scaled)
            + msm_points(&self.t_big, &t_terms);
        if t_left != t_right {
            return Err(ProofError::InvalidProof);
        }

        let p_0 = msm_points(&setup.ipa.h()[..padded_vars], &y_inv_omega_minus_y);
        let p_1 = msm_points(&setup.ipa.g()[..circuit.internal_vars], &y_inv_rho)
            + msm_points(&setup.ipa.h()[..circuit.internal_vars], &y_inv_lambda);
        let expected_p = setup.blinding_generator.mul_scalar(-self.s_tilde)
            + p_0
            + (p_1 + self.m_big).mul_scalar(x[0])
            + self.o_big.mul_scalar(x[1])
            + self.m_big_tilde.mul_scalar(x[2]);
        if self.p_big != expected_p {
            return Err(ProofError::InvalidProof);
        }

        let ipa_claim = PallasIpaClaim {
            commitment: self.p_big,
            product: self.t_x,
            y: y_inv,
            log_len: log_len(padded_vars),
        };
        self.ipa_proof.verify(&setup.ipa, &ipa_claim)
    }

    /// Serialize this circuit proof.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let ipa_bytes = self.ipa_proof.to_bytes();
        let mut bytes = Vec::with_capacity(5 + 96 + 160 + 96 + 32 + 8 + ipa_bytes.len());
        bytes.extend_from_slice(CIRCUIT_PROOF_MAGIC);
        bytes.push(CIRCUIT_PROOF_VERSION);
        bytes.extend_from_slice(&self.m_big.to_bytes());
        bytes.extend_from_slice(&self.o_big.to_bytes());
        bytes.extend_from_slice(&self.m_big_tilde.to_bytes());
        for point in &self.t_big {
            bytes.extend_from_slice(&point.to_bytes());
        }
        bytes.extend_from_slice(&self.s_tilde.to_bytes());
        bytes.extend_from_slice(&self.t_x.to_bytes());
        bytes.extend_from_slice(&self.t_tilde_x.to_bytes());
        bytes.extend_from_slice(&self.p_big.to_bytes());
        bytes.extend_from_slice(&(ipa_bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&ipa_bytes);
        bytes
    }

    /// Parse a circuit proof produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        if bytes.len() < 5
            || &bytes[..4] != CIRCUIT_PROOF_MAGIC
            || bytes[4] != CIRCUIT_PROOF_VERSION
        {
            return Err(ProofError::InvalidProof);
        }

        let mut offset = 5;
        let m_big = read_point(bytes, &mut offset)?;
        let o_big = read_point(bytes, &mut offset)?;
        let m_big_tilde = read_point(bytes, &mut offset)?;
        let t_big = [
            read_point(bytes, &mut offset)?,
            read_point(bytes, &mut offset)?,
            read_point(bytes, &mut offset)?,
            read_point(bytes, &mut offset)?,
            read_point(bytes, &mut offset)?,
        ];
        let s_tilde = read_scalar(bytes, &mut offset)?;
        let t_x = read_scalar(bytes, &mut offset)?;
        let t_tilde_x = read_scalar(bytes, &mut offset)?;
        let p_big = read_point(bytes, &mut offset)?;
        let ipa_len = usize::try_from(u64::from_le_bytes(read_array(bytes, &mut offset)?))
            .map_err(|_| ProofError::InvalidProof)?;
        let ipa_end = offset
            .checked_add(ipa_len)
            .ok_or(ProofError::InvalidProof)?;
        let ipa_bytes = bytes.get(offset..ipa_end).ok_or(ProofError::InvalidProof)?;
        let ipa_proof = PallasIpaProof::from_bytes(ipa_bytes)?;
        if ipa_end != bytes.len() {
            return Err(ProofError::InvalidProof);
        }

        Ok(Self {
            m_big,
            o_big,
            m_big_tilde,
            t_big,
            s_tilde,
            t_x,
            t_tilde_x,
            p_big,
            ipa_proof,
        })
    }
}

/// Rank-1 constraint system with `A z * B z = C z` rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PallasR1cs {
    /// Left linear combinations.
    pub a: PallasSparseMatrix,
    /// Right linear combinations.
    pub b: PallasSparseMatrix,
    /// Output linear combinations.
    pub c: PallasSparseMatrix,
}

impl PallasR1cs {
    /// Normalize matrix dimensions and convert to the Bulletproofs circuit
    /// layout, treating the listed R1CS columns as committed values.
    ///
    /// Returns `None` if the committed column list includes column 0, includes
    /// duplicates, or names columns outside the normalized R1CS width.
    #[must_use]
    pub fn to_circuit(mut self, committed_indices: &[usize]) -> Option<PallasCircuit> {
        self.normalize();

        R1csCircuitLayout::new(self.width(), self.height(), committed_indices)?.to_circuit(&self)
    }

    /// Normalize matrix dimensions and convert to a Bulletproofs circuit plus
    /// the witness that satisfies it.
    ///
    /// The `full_witness` vector must use R1CS column order, including the
    /// constant-one column at index 0. Committed values and blindings follow the
    /// sorted order of `committed_indices`, matching [`Self::to_circuit`].
    #[must_use]
    pub fn to_circuit_with_witness(
        mut self,
        full_witness: &[PallasScalar],
        committed_indices: &[usize],
        committed_blindings: Vec<PallasScalar>,
    ) -> Option<(PallasCircuit, PallasCircuitWitness)> {
        self.normalize();

        let layout = R1csCircuitLayout::new(self.width(), self.height(), committed_indices)?;
        let witness = layout.to_witness(&self, full_witness, committed_blindings)?;
        let circuit = layout.to_circuit(&self)?;
        Some((circuit, witness))
    }

    fn normalize(&mut self) {
        let width = self.width();
        let height = self.height();
        for matrix in [&mut self.a, &mut self.b, &mut self.c] {
            matrix.pad(width, height);
        }
    }

    fn width(&self) -> usize {
        self.a.width.max(self.b.width).max(self.c.width)
    }

    fn height(&self) -> usize {
        self.a.height.max(self.b.height).max(self.c.height)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct R1csCircuitLayout {
    committed_indices: BTreeSet<usize>,
    old_to_new: Vec<(bool, usize)>,
    committed_len: usize,
    non_constant_width: usize,
    row_count: usize,
    internal_len: usize,
    x_col_base: usize,
}

impl R1csCircuitLayout {
    fn new(width: usize, height: usize, committed_indices: &[usize]) -> Option<Self> {
        let committed_count = committed_indices.len();
        let committed_indices = committed_indices.iter().copied().collect::<BTreeSet<_>>();
        if committed_indices.len() != committed_count
            || committed_indices
                .iter()
                .any(|&index| index == 0 || index >= width)
        {
            return None;
        }

        let committed_len = committed_indices.len();
        let non_constant_width = width.saturating_sub(1);
        let internal_witness_len = non_constant_width.saturating_sub(committed_len);
        let row_count = height;
        let internal_len = row_count + internal_witness_len;

        let mut old_to_new = vec![(false, 0_usize); non_constant_width];
        let mut committed_position = 0_usize;
        let mut internal_position = 0_usize;
        for r1cs_index in 1..=non_constant_width {
            let slot = &mut old_to_new[r1cs_index - 1];
            if committed_indices.contains(&r1cs_index) {
                *slot = (true, committed_position);
                committed_position += 1;
            } else {
                *slot = (false, internal_position);
                internal_position += 1;
            }
        }

        Some(Self {
            committed_indices,
            old_to_new,
            committed_len,
            non_constant_width,
            row_count,
            internal_len,
            x_col_base: 1 + committed_len + row_count,
        })
    }

    fn to_circuit(&self, r1cs: &PallasR1cs) -> Option<PallasCircuit> {
        let mut weights = PallasSparseMatrix::default();
        weights.pad(
            1 + self.committed_len + 3 * self.internal_len,
            3 * self.row_count,
        );

        for (row_start, col_start, matrix) in [
            (0, 1 + self.committed_len, &r1cs.a),
            (
                self.row_count,
                1 + self.committed_len + self.internal_len,
                &r1cs.b,
            ),
            (
                2 * self.row_count,
                1 + self.committed_len + 2 * self.internal_len,
                &r1cs.c,
            ),
        ] {
            for (&(row, column), &scalar) in &matrix.weights {
                let new_column = if column == 0 {
                    0
                } else {
                    let (is_committed, position) = self.old_to_new[column - 1];
                    if is_committed {
                        1 + position
                    } else {
                        self.x_col_base + position
                    }
                };
                weights[(row_start + row, new_column)] = scalar;
            }

            for row in 0..self.row_count {
                weights[(row_start + row, col_start + row)] = -PallasScalar::ONE;
            }
        }

        PallasCircuit::new(self.committed_len, weights)
    }

    fn to_witness(
        &self,
        r1cs: &PallasR1cs,
        full_witness: &[PallasScalar],
        committed_blindings: Vec<PallasScalar>,
    ) -> Option<PallasCircuitWitness> {
        if full_witness.len() != self.non_constant_width.checked_add(1)?
            || full_witness.first().copied()? != PallasScalar::ONE
            || committed_blindings.len() != self.committed_len
        {
            return None;
        }

        let committed_values = self
            .committed_indices
            .iter()
            .map(|&index| full_witness[index])
            .collect::<Vec<_>>();
        let mut left = matrix_vector_product(&r1cs.a, full_witness)?;
        let mut right = matrix_vector_product(&r1cs.b, full_witness)?;
        let mut output = matrix_vector_product(&r1cs.c, full_witness)?;
        left.resize(self.internal_len, PallasScalar::ZERO);
        right.resize(self.internal_len, PallasScalar::ZERO);
        output.resize(self.internal_len, PallasScalar::ZERO);

        for (r1cs_index, &value) in full_witness
            .iter()
            .enumerate()
            .take(self.non_constant_width + 1)
            .skip(1)
        {
            let (is_committed, position) = self.old_to_new[r1cs_index - 1];
            if !is_committed {
                left[self.row_count + position] = value;
            }
        }

        PallasCircuitWitness::new_with_blinding(
            committed_values,
            committed_blindings,
            left,
            right,
            output,
        )
    }
}

fn matrix_vector_product(
    matrix: &PallasSparseMatrix,
    vector: &[PallasScalar],
) -> Option<Vec<PallasScalar>> {
    let mut out = vec![PallasScalar::ZERO; matrix.height()];
    for (&(row, column), &scalar) in &matrix.weights {
        out[row] += scalar * *vector.get(column)?;
    }
    Some(out)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WireCommitments {
    left_blinding: Vec<PallasScalar>,
    right_blinding: Vec<PallasScalar>,
    m_blinding: PallasScalar,
    output_blinding: PallasScalar,
    m_tilde_blinding: PallasScalar,
    m_big: PallasPoint,
    o_big: PallasPoint,
    m_big_tilde: PallasPoint,
}

impl WireCommitments {
    fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        setup: &PallasCircuitSetup,
        circuit: &PallasCircuit,
        witness: &PallasCircuitWitness,
    ) -> Self {
        let left_blinding = random_scalars(rng, circuit.internal_vars);
        let right_blinding = random_scalars(rng, circuit.internal_vars);
        let m_blinding = random_scalar(rng);
        let output_blinding = random_scalar(rng);
        let m_tilde_blinding = random_scalar(rng);

        let g_internal = &setup.ipa.g()[..circuit.internal_vars];
        let h_internal = &setup.ipa.h()[..circuit.internal_vars];
        let m_big = msm_points(g_internal, &witness.left)
            + msm_points(h_internal, &witness.right)
            + setup.blinding_generator.mul_scalar(m_blinding);
        let o_big = msm_points(g_internal, &witness.output)
            + setup.blinding_generator.mul_scalar(output_blinding);
        let m_big_tilde = msm_points(g_internal, &left_blinding)
            + msm_points(h_internal, &right_blinding)
            + setup.blinding_generator.mul_scalar(m_tilde_blinding);

        Self {
            left_blinding,
            right_blinding,
            m_blinding,
            output_blinding,
            m_tilde_blinding,
            m_big,
            o_big,
            m_big_tilde,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReducedCircuit {
    y: PallasScalar,
    y_inv: PallasScalar,
    kappa: PallasScalar,
    theta: Vec<PallasScalar>,
    lambda: Vec<PallasScalar>,
    rho: Vec<PallasScalar>,
    omega: Vec<PallasScalar>,
}

impl ReducedCircuit {
    fn new(circuit: &PallasCircuit, y: PallasScalar, z: PallasScalar) -> Self {
        let mut kappa = PallasScalar::ZERO;
        let mut theta = vec![PallasScalar::ZERO; circuit.committed_vars];
        let mut lambda = vec![PallasScalar::ZERO; circuit.internal_vars];
        let mut rho = vec![PallasScalar::ZERO; circuit.internal_vars];
        let mut omega = vec![PallasScalar::ZERO; circuit.internal_vars];
        let theta_start = 1;
        let lambda_start = theta_start + circuit.committed_vars;
        let rho_start = lambda_start + circuit.internal_vars;
        let omega_start = rho_start + circuit.internal_vars;
        let z_powers = powers_from_base(z, circuit.weights.height);

        for (&(row, column), &weight) in &circuit.weights.weights {
            let term = weight * z_powers[row];
            if column >= omega_start {
                omega[column - omega_start] += term;
            } else if column >= rho_start {
                rho[column - rho_start] += term;
            } else if column >= lambda_start {
                lambda[column - lambda_start] += term;
            } else if column >= theta_start {
                theta[column - theta_start] += term;
            } else {
                kappa += term;
            }
        }

        Self {
            y,
            y_inv: y.invert().expect("transcript challenges are nonzero"),
            kappa,
            theta,
            lambda,
            rho,
            omega,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PolynomialState {
    t: [PallasScalar; 6],
    t_tilde: [PallasScalar; 6],
    p_0: PallasPoint,
    p_1: PallasPoint,
    y_r: Vec<PallasScalar>,
    y_r_tilde: Vec<PallasScalar>,
    y_inv_rho: Vec<PallasScalar>,
    omega_minus_y: Vec<PallasScalar>,
}

fn polynomial_state<R: RngCore + CryptoRng>(
    setup: &PallasCircuitSetup,
    circuit: &PallasCircuit,
    witness: &PallasCircuitWitness,
    reduced: &ReducedCircuit,
    left_blinding: &[PallasScalar],
    right_blinding: &[PallasScalar],
    rng: &mut R,
) -> PolynomialState {
    let padded_vars = padded_vars(circuit);
    let y_powers = powers_from_one(reduced.y, padded_vars);
    let y_inv_powers = powers_from_one(reduced.y_inv, padded_vars);
    let mut omega_minus_y = reduced
        .omega
        .par_iter()
        .zip(y_powers.par_iter())
        .map(|(&omega, &y_power)| omega - y_power)
        .collect::<Vec<_>>();
    omega_minus_y.extend(
        y_powers
            .iter()
            .skip(circuit.internal_vars)
            .copied()
            .map(|y_power| -y_power),
    );
    let y_inv_rho = y_inv_powers
        .par_iter()
        .copied()
        .zip(reduced.rho.par_iter())
        .map(|(y_inv_power, &rho)| y_inv_power * rho)
        .collect::<Vec<_>>();
    let y_inv_lambda = y_inv_powers
        .par_iter()
        .copied()
        .zip(reduced.lambda.par_iter())
        .map(|(y_inv_power, &lambda)| y_inv_power * lambda)
        .collect::<Vec<_>>();
    let y_inv_omega_minus_y = y_inv_powers
        .par_iter()
        .copied()
        .zip(omega_minus_y.par_iter())
        .map(|(y_inv_power, &omega)| y_inv_power * omega)
        .collect::<Vec<_>>();
    let y_r = y_powers
        .par_iter()
        .copied()
        .zip(witness.right.par_iter())
        .map(|(y_power, &right)| y_power * right)
        .collect::<Vec<_>>();
    let y_r_tilde = y_powers
        .par_iter()
        .copied()
        .zip(right_blinding.par_iter())
        .map(|(y_power, &right)| y_power * right)
        .collect::<Vec<_>>();
    let delta_y_z = inner_product(&y_inv_rho, &reduced.lambda);

    let mut t = [PallasScalar::ZERO; 6];
    t[0] = (0..circuit.internal_vars)
        .into_par_iter()
        .map(|index| (witness.left[index] + y_inv_rho[index]) * omega_minus_y[index])
        .reduce(|| PallasScalar::ZERO, |acc, term| acc + term);
    t[1] = delta_y_z - reduced.kappa - inner_product(&reduced.theta, &witness.values);
    let (t_2, t_3) = (0..circuit.internal_vars)
        .into_par_iter()
        .map(|index| {
            let y_r_lambda = y_r[index] + reduced.lambda[index];
            (
                (left_blinding[index] * omega_minus_y[index])
                    + (witness.output[index] * y_r_lambda),
                (left_blinding[index] * y_r_lambda)
                    + ((witness.left[index] + y_inv_rho[index]) * y_r_tilde[index]),
            )
        })
        .reduce(
            || (PallasScalar::ZERO, PallasScalar::ZERO),
            |(lhs_2, lhs_3), (rhs_2, rhs_3)| (lhs_2 + rhs_2, lhs_3 + rhs_3),
        );
    t[2] = t_2;
    t[3] = t_3;
    t[4] = inner_product(&witness.output, &y_r_tilde);
    t[5] = inner_product(left_blinding, &y_r_tilde);

    let mut t_tilde = std::array::from_fn(|_| random_scalar(rng));
    t_tilde[1] = -inner_product(&reduced.theta, &witness.blinding);
    let p_0 = msm_points(&setup.ipa.h()[..padded_vars], &y_inv_omega_minus_y);
    let p_1 = msm_points(&setup.ipa.g()[..circuit.internal_vars], &y_inv_rho)
        + msm_points(&setup.ipa.h()[..circuit.internal_vars], &y_inv_lambda);

    PolynomialState {
        t,
        t_tilde,
        p_0,
        p_1,
        y_r,
        y_r_tilde,
        y_inv_rho,
        omega_minus_y,
    }
}

fn ipa_witness_vectors(
    circuit: &PallasCircuit,
    witness: &PallasCircuitWitness,
    reduced: &ReducedCircuit,
    wire_commitments: &WireCommitments,
    polynomial: &PolynomialState,
    x: &[PallasScalar],
    padded_vars: usize,
) -> (Vec<PallasScalar>, Vec<PallasScalar>) {
    let mut f_x = (0..circuit.internal_vars)
        .into_par_iter()
        .map(|index| {
            ((witness.left[index] + polynomial.y_inv_rho[index]) * x[0])
                + (witness.output[index] * x[1])
                + (wire_commitments.left_blinding[index] * x[2])
        })
        .collect::<Vec<_>>();
    f_x.resize(padded_vars, PallasScalar::ZERO);

    let mut g_x = (0..circuit.internal_vars)
        .into_par_iter()
        .map(|index| {
            ((polynomial.y_r[index] + reduced.lambda[index]) * x[0])
                + polynomial.omega_minus_y[index]
                + (polynomial.y_r_tilde[index] * x[2])
        })
        .collect::<Vec<_>>();
    g_x.extend_from_slice(&polynomial.omega_minus_y[circuit.internal_vars..]);

    (f_x, g_x)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PallasCircuitTranscript {
    bytes: Vec<u8>,
}

impl PallasCircuitTranscript {
    fn new() -> Self {
        let mut transcript = Self { bytes: Vec::new() };
        transcript.commit_bytes(b"domain", CIRCUIT_TRANSCRIPT_DOMAIN);
        transcript
    }

    fn commit_setup(&mut self, setup: &PallasCircuitSetup) {
        self.commit_bytes(b"setup-digest", &setup.transcript_digest);
    }

    fn commit_circuit(&mut self, circuit: &PallasCircuit) {
        self.commit_bytes(b"circuit-digest", &circuit.transcript_digest);
    }

    fn commit_claim(&mut self, claim: &PallasCircuitClaim) {
        self.commit_usize(b"commitments", claim.commitments.len());
        for commitment in &claim.commitments {
            self.commit_point(b"value-commitment", *commitment);
        }
    }

    fn commit_point(&mut self, label: impl AsRef<[u8]>, point: PallasPoint) {
        self.commit_bytes(label.as_ref(), &point.to_bytes());
    }

    fn commit_scalar(&mut self, label: &[u8], scalar: PallasScalar) {
        self.commit_bytes(label, &scalar.to_bytes());
    }

    fn commit_usize(&mut self, label: &[u8], value: usize) {
        self.commit_bytes(label, &(value as u64).to_le_bytes());
    }

    fn challenge(&mut self, label: &[u8]) -> PallasScalar {
        for counter in 0_u64.. {
            let mut state = Params::new().hash_length(64).to_state();
            state.update(CIRCUIT_TRANSCRIPT_DOMAIN);
            update_len_prefixed(&mut state, &self.bytes);
            update_len_prefixed(&mut state, label);
            state.update(&counter.to_le_bytes());

            let hash = state.finalize();
            let mut uniform = [0_u8; 64];
            uniform.copy_from_slice(hash.as_bytes());
            let scalar = PallasScalar::from_uniform_bytes(&uniform);
            if !scalar.is_zero() {
                self.commit_bytes(b"challenge", label);
                self.commit_scalar(b"challenge-value", scalar);
                return scalar;
            }
        }
        unreachable!("u64 challenge counter space exhausted");
    }

    fn commit_bytes(&mut self, label: &[u8], bytes: &[u8]) {
        self.bytes
            .extend_from_slice(&(label.len() as u64).to_le_bytes());
        self.bytes.extend_from_slice(label);
        self.bytes
            .extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        self.bytes.extend_from_slice(bytes);
    }
}

fn derive_circuit_generator(domain: &[u8], kind: &[u8]) -> PallasPoint {
    let mut label = Vec::with_capacity(domain.len() + kind.len() + 16);
    label.extend_from_slice(&(domain.len() as u64).to_le_bytes());
    label.extend_from_slice(domain);
    label.extend_from_slice(&(kind.len() as u64).to_le_bytes());
    label.extend_from_slice(kind);
    derive_pallas_generator(&label)
}

fn setup_transcript_digest(
    ipa_digest: [u8; 32],
    value_generator: PallasPoint,
    blinding_generator: PallasPoint,
) -> [u8; 32] {
    let mut state = Params::new().hash_length(32).to_state();
    state.update(CIRCUIT_TRANSCRIPT_DOMAIN);
    state.update(b"setup-digest/v0");
    state.update(&ipa_digest);
    state.update(&value_generator.to_bytes());
    state.update(&blinding_generator.to_bytes());
    let digest = state.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(digest.as_bytes());
    bytes
}

fn circuit_transcript_digest(
    committed_vars: usize,
    internal_vars: usize,
    weights: &PallasSparseMatrix,
) -> [u8; 32] {
    let mut state = Params::new().hash_length(32).to_state();
    state.update(CIRCUIT_TRANSCRIPT_DOMAIN);
    state.update(b"circuit-digest/v0");
    state.update(&(committed_vars as u64).to_le_bytes());
    state.update(&(internal_vars as u64).to_le_bytes());
    state.update(&(weights.width as u64).to_le_bytes());
    state.update(&(weights.height as u64).to_le_bytes());
    state.update(&(weights.weights.len() as u64).to_le_bytes());
    for (&(row, column), &scalar) in &weights.weights {
        state.update(&(row as u64).to_le_bytes());
        state.update(&(column as u64).to_le_bytes());
        state.update(&scalar.to_bytes());
    }
    let digest = state.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(digest.as_bytes());
    bytes
}

fn padded_vars(circuit: &PallasCircuit) -> usize {
    circuit.internal_vars.max(1).next_power_of_two()
}

fn log_len(len: usize) -> u8 {
    u8::try_from(len.trailing_zeros()).expect("power-of-two length log fits in u8")
}

fn random_scalar(rng: &mut impl RngCore) -> PallasScalar {
    let mut bytes = [0_u8; 64];
    rng.fill_bytes(&mut bytes);
    PallasScalar::from_uniform_bytes(&bytes)
}

fn random_scalars(rng: &mut impl RngCore, len: usize) -> Vec<PallasScalar> {
    (0..len).map(|_| random_scalar(rng)).collect()
}

fn powers_from_one(base: PallasScalar, len: usize) -> Vec<PallasScalar> {
    let mut powers = Vec::with_capacity(len);
    let mut current = PallasScalar::ONE;
    for _ in 0..len {
        powers.push(current);
        current *= base;
    }
    powers
}

fn powers_from_base(base: PallasScalar, len: usize) -> Vec<PallasScalar> {
    let mut powers = Vec::with_capacity(len);
    let mut current = base;
    for _ in 0..len {
        powers.push(current);
        current *= base;
    }
    powers
}

fn inner_product(left: &[PallasScalar], right: &[PallasScalar]) -> PallasScalar {
    left.par_iter()
        .zip(right.par_iter())
        .map(|(&lhs, &rhs)| lhs * rhs)
        .reduce(|| PallasScalar::ZERO, |acc, term| acc + term)
}

fn msm_points(points: &[PallasPoint], scalars: &[PallasScalar]) -> PallasPoint {
    points
        .par_iter()
        .zip(scalars.par_iter())
        .map(|(&point, &scalar)| point.mul_scalar(scalar))
        .reduce(PallasPoint::identity, |acc, point| acc + point)
}

fn format_label(prefix: &[u8], index: usize) -> Vec<u8> {
    let mut label = Vec::with_capacity(prefix.len() + 8);
    label.extend_from_slice(prefix);
    label.extend_from_slice(&(index as u64).to_le_bytes());
    label
}

fn update_len_prefixed(state: &mut blake2b_simd::State, bytes: &[u8]) {
    state.update(&(bytes.len() as u64).to_le_bytes());
    state.update(bytes);
}

fn read_point(bytes: &[u8], offset: &mut usize) -> Result<PallasPoint, ProofError> {
    PallasPoint::from_bytes(read_array(bytes, offset)?).ok_or(ProofError::InvalidProof)
}

fn read_scalar(bytes: &[u8], offset: &mut usize) -> Result<PallasScalar, ProofError> {
    PallasScalar::from_bytes(read_array(bytes, offset)?).ok_or(ProofError::InvalidProof)
}

fn read_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], ProofError> {
    let end = offset.checked_add(N).ok_or(ProofError::InvalidProof)?;
    let slice = bytes.get(*offset..end).ok_or(ProofError::InvalidProof)?;
    *offset = end;
    slice.try_into().map_err(|_| ProofError::InvalidProof)
}

#[cfg(test)]
mod tests {
    use golden_core::FieldElement;
    use golden_pallas::PallasScalar;

    use golden_pallas::PallasPoint;
    use rand_core::{CryptoRng, Error, RngCore};

    use super::{
        PallasCircuit, PallasCircuitProof, PallasCircuitSetup, PallasCircuitTranscript,
        PallasCircuitWitness, PallasR1cs, PallasSparseMatrix,
    };

    struct TestRng(u64);

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            let bytes = self.next_u64().to_le_bytes();
            u32::from_le_bytes(bytes[..4].try_into().expect("slice has four bytes"))
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            self.0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for TestRng {}

    fn quadratic_case() -> (PallasCircuitSetup, PallasCircuit, PallasCircuitWitness) {
        let setup = PallasCircuitSetup::deterministic(b"circuit-test", 0, PallasPoint::generator());
        let mut weights = PallasSparseMatrix::default();
        weights[(0, 1)] = PallasScalar::ONE;
        weights[(0, 3)] = -PallasScalar::ONE;
        weights[(1, 1)] = PallasScalar::ONE;
        weights[(1, 4)] = -PallasScalar::ONE;
        weights[(2, 0)] = PallasScalar::from_u64(1);
        weights[(2, 1)] = PallasScalar::from_u64(1);
        weights[(2, 2)] = -PallasScalar::ONE;
        weights[(2, 5)] = PallasScalar::ONE;
        let circuit = PallasCircuit::new(2, weights).expect("valid layout");
        let witness = PallasCircuitWitness::new_with_blinding(
            vec![PallasScalar::from_u64(3), PallasScalar::from_u64(13)],
            vec![PallasScalar::from_u64(17), PallasScalar::from_u64(19)],
            vec![PallasScalar::from_u64(3)],
            vec![PallasScalar::from_u64(3)],
            vec![PallasScalar::from_u64(9)],
        )
        .expect("matching witness lengths");
        (setup, circuit, witness)
    }

    #[test]
    fn circuit_accepts_quadratic_assignment() {
        let mut weights = PallasSparseMatrix::default();
        weights[(0, 1)] = PallasScalar::ONE;
        weights[(0, 3)] = -PallasScalar::ONE;
        weights[(1, 1)] = PallasScalar::ONE;
        weights[(1, 4)] = -PallasScalar::ONE;
        weights[(2, 0)] = PallasScalar::from_u64(1);
        weights[(2, 1)] = PallasScalar::from_u64(1);
        weights[(2, 2)] = -PallasScalar::ONE;
        weights[(2, 5)] = PallasScalar::ONE;
        let circuit = PallasCircuit::new(2, weights).expect("valid layout");

        let witness = PallasCircuitWitness::new(
            vec![PallasScalar::from_u64(3), PallasScalar::from_u64(13)],
            vec![PallasScalar::from_u64(3)],
            vec![PallasScalar::from_u64(3)],
            vec![PallasScalar::from_u64(9)],
        )
        .expect("matching witness lengths");

        assert!(witness.is_satisfied(&circuit));
    }

    #[test]
    fn circuit_rejects_wrong_assignment() {
        let mut weights = PallasSparseMatrix::default();
        weights[(0, 1)] = PallasScalar::ONE;
        weights[(0, 3)] = -PallasScalar::ONE;
        weights[(1, 1)] = PallasScalar::ONE;
        weights[(1, 4)] = -PallasScalar::ONE;
        weights[(2, 0)] = PallasScalar::from_u64(1);
        weights[(2, 1)] = PallasScalar::from_u64(1);
        weights[(2, 2)] = -PallasScalar::ONE;
        weights[(2, 5)] = PallasScalar::ONE;
        let circuit = PallasCircuit::new(2, weights).expect("valid layout");

        let witness = PallasCircuitWitness::new(
            vec![PallasScalar::from_u64(3), PallasScalar::from_u64(12)],
            vec![PallasScalar::from_u64(3)],
            vec![PallasScalar::from_u64(3)],
            vec![PallasScalar::from_u64(9)],
        )
        .expect("matching witness lengths");

        assert!(!witness.is_satisfied(&circuit));
    }

    #[test]
    fn r1cs_to_circuit_enforces_constant_column() {
        let mut a = PallasSparseMatrix::default();
        a[(0, 0)] = PallasScalar::ONE;
        a[(0, 1)] = PallasScalar::ONE;
        let mut b = PallasSparseMatrix::default();
        b[(0, 0)] = PallasScalar::ONE;
        let mut c = PallasSparseMatrix::default();
        c[(0, 0)] = PallasScalar::from_u64(4);
        let r1cs = PallasR1cs { a, b, c };
        let circuit = r1cs.to_circuit(&[1]).expect("valid R1CS conversion");

        let malicious = PallasCircuitWitness::new(
            vec![PallasScalar::ZERO],
            vec![PallasScalar::ZERO],
            vec![PallasScalar::ZERO],
            vec![PallasScalar::ZERO],
        )
        .expect("matching witness lengths");

        assert!(!malicious.is_satisfied(&circuit));
    }

    #[test]
    fn r1cs_to_circuit_with_witness_maps_committed_and_internal_columns() {
        let mut a = PallasSparseMatrix::default();
        a[(0, 1)] = PallasScalar::ONE;
        let mut b = PallasSparseMatrix::default();
        b[(0, 2)] = PallasScalar::ONE;
        let mut c = PallasSparseMatrix::default();
        c[(0, 3)] = PallasScalar::ONE;
        let r1cs = PallasR1cs { a, b, c };
        let (circuit, witness) = r1cs
            .to_circuit_with_witness(
                &[
                    PallasScalar::ONE,
                    PallasScalar::from_u64(3),
                    PallasScalar::from_u64(5),
                    PallasScalar::from_u64(15),
                ],
                &[1, 3],
                vec![PallasScalar::from_u64(7), PallasScalar::from_u64(11)],
            )
            .expect("valid R1CS witness conversion");

        let setup =
            PallasCircuitSetup::deterministic(b"r1cs-witness-test", 1, PallasPoint::generator());
        let claim = witness.claim(&setup);

        assert_eq!(circuit.committed_vars(), 2);
        assert!(witness.is_satisfied(&circuit));
        assert_eq!(
            claim.commitments,
            vec![
                setup.commit_value(PallasScalar::from_u64(3), PallasScalar::from_u64(7)),
                setup.commit_value(PallasScalar::from_u64(15), PallasScalar::from_u64(11)),
            ]
        );
    }

    #[test]
    fn circuit_proof_verifies_valid_quadratic_assignment() {
        let (setup, circuit, witness) = quadratic_case();
        let claim = witness.claim(&setup);
        let proof = PallasCircuitProof::prove(&mut TestRng(7), &setup, &circuit, &claim, &witness)
            .expect("proof");

        assert_eq!(proof.verify(&setup, &circuit, &claim), Ok(()));
    }

    #[test]
    fn circuit_proof_rejects_wrong_claim_commitment() {
        let (setup, circuit, witness) = quadratic_case();
        let mut claim = witness.claim(&setup);
        let proof = PallasCircuitProof::prove(&mut TestRng(7), &setup, &circuit, &claim, &witness)
            .expect("proof");
        claim.commitments[0] += PallasPoint::generator();

        assert_eq!(
            proof.verify(&setup, &circuit, &claim),
            Err(crate::ProofError::InvalidProof)
        );
    }

    #[test]
    fn circuit_proof_roundtrips_through_bytes() {
        let (setup, circuit, witness) = quadratic_case();
        let claim = witness.claim(&setup);
        let proof = PallasCircuitProof::prove(&mut TestRng(7), &setup, &circuit, &claim, &witness)
            .expect("proof");
        let decoded = PallasCircuitProof::from_bytes(&proof.to_bytes()).expect("decode");

        assert_eq!(decoded, proof);
        assert_eq!(decoded.verify(&setup, &circuit, &claim), Ok(()));
    }

    #[test]
    fn circuit_transcript_commits_setup_and_circuit_by_digest() {
        let setup =
            PallasCircuitSetup::deterministic(b"large-circuit-test", 6, PallasPoint::generator());
        let mut weights = PallasSparseMatrix::with_dimensions(1 + 1 + (3 * 64), 64);
        for row in 0..64 {
            weights[(row, 1)] = PallasScalar::from_u64(3);
            weights[(row, 2 + row)] = -PallasScalar::ONE;
        }
        let circuit = PallasCircuit::new(1, weights).expect("valid layout");

        let mut transcript = PallasCircuitTranscript::new();
        transcript.commit_setup(&setup);
        transcript.commit_circuit(&circuit);

        assert!(
            transcript.bytes.len() < 256,
            "transcript prefix should commit setup and circuit digests, got {} bytes",
            transcript.bytes.len()
        );
    }
}
