//! Minimal CLI entry point for the Golden `RedPallas` workspace.

use std::{env, fmt, fs, path::Path, process::ExitCode};

use golden_core::ParticipantId;
use golden_pallas::{DkgFixture, DkgSimulation, PallasPoint};

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match run(&args) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<String, CliError> {
    match parse_command(args)? {
        Command::Status => Ok(status_json()),
        Command::Create { fixture, output } => create_session(&fixture, &output),
        Command::Post { session } => post_session(&session),
        Command::Verify { session } => verify_session(&session),
        Command::Recover {
            session,
            participant,
        } => recover_share_backup(&session, participant),
    }
}

fn parse_command(args: &[String]) -> Result<Command, CliError> {
    match args {
        [] => Ok(Command::Status),
        [command, fixture, output] if command == "create" => Ok(Command::Create {
            fixture: fixture.clone(),
            output: output.clone(),
        }),
        [command, session] if command == "post" => Ok(Command::Post {
            session: session.clone(),
        }),
        [command, session] if command == "verify" => Ok(Command::Verify {
            session: session.clone(),
        }),
        [command, session, participant] if command == "recover" => {
            let participant = participant
                .parse::<u64>()
                .ok()
                .and_then(ParticipantId::new)
                .ok_or(CliError::InvalidParticipant)?;
            Ok(Command::Recover {
                session: session.clone(),
                participant,
            })
        }
        _ => Err(CliError::Usage),
    }
}

fn status_json() -> String {
    format!(
        concat!(
            "{{\n",
            "  \"workspace\": \"golden-redpallas\",\n",
            "  \"pallas_evrf\": \"{}\",\n",
            "  \"frost_redpallas\": \"{}\"\n",
            "}}"
        ),
        golden_pallas::PallasVestaEvrf::status(),
        frost_redpallas::Zip312RerandomizedFrost::status()
    )
}

fn create_session(fixture_path: &str, output_path: &str) -> Result<String, CliError> {
    let input = fs::read_to_string(fixture_path)?;
    let fixture = DkgFixture::parse(&input)?;
    let simulation = fixture.run()?;
    validate_simulation(&simulation)?;
    fs::write(output_path, ensure_trailing_newline(&input))?;

    Ok(format!(
        concat!(
            "{{\n",
            "  \"status\": \"created\",\n",
            "  \"format\": \"golden-dkg-session-v0\",\n",
            "  \"path\": \"{}\"\n",
            "}}"
        ),
        json_escape(output_path)
    ))
}

fn post_session(session_path: &str) -> Result<String, CliError> {
    let simulation = load_session(session_path)?;
    Ok(format!(
        concat!(
            "{{\n",
            "  \"status\": \"posted\",\n",
            "  \"format\": \"golden-dkg-session-v0\",\n",
            "  \"session_id\": \"{}\",\n",
            "  \"participants\": {},\n",
            "  \"dealers\": {},\n",
            "  \"transcripts\": {}\n",
            "}}"
        ),
        json_escape(&session_id_string(&simulation)),
        simulation.participants.len(),
        simulation.dealers.len(),
        simulation.transcripts.len()
    ))
}

fn verify_session(session_path: &str) -> Result<String, CliError> {
    let simulation = load_session(session_path)?;
    validate_simulation(&simulation)?;

    Ok(format!(
        concat!(
            "{{\n",
            "  \"status\": \"verified\",\n",
            "  \"format\": \"golden-dkg-session-v0\",\n",
            "  \"threshold\": {},\n",
            "  \"participants\": {},\n",
            "  \"dealers\": {},\n",
            "  \"transcripts\": {}\n",
            "}}"
        ),
        simulation.config.threshold(),
        simulation.participants.len(),
        simulation.dealers.len(),
        simulation.transcripts.len()
    ))
}

fn recover_share_backup(
    session_path: &str,
    participant: ParticipantId,
) -> Result<String, CliError> {
    let simulation = load_session(session_path)?;
    validate_simulation(&simulation)?;
    let share = simulation.recover_participant(participant)?;
    let group_public_key = simulation.aggregate_public_key()?;

    Ok(format!(
        concat!(
            "{{\n",
            "  \"version\": 0,\n",
            "  \"scheme\": \"golden-redpallas-wallet-backup\",\n",
            "  \"session_format\": \"golden-dkg-session-v0\",\n",
            "  \"session_id\": \"{}\",\n",
            "  \"participant_id\": {},\n",
            "  \"dealer_count\": {},\n",
            "  \"share_hex\": \"{}\",\n",
            "  \"group_public_key_hex\": \"{}\"\n",
            "}}"
        ),
        json_escape(&session_id_string(&simulation)),
        share.participant.get(),
        share.dealer_count,
        hex(&share.value.to_bytes()),
        hex(&group_public_key.to_bytes())
    ))
}

fn load_session(path: &str) -> Result<DkgSimulation, CliError> {
    let input = fs::read_to_string(Path::new(path))?;
    let fixture = DkgFixture::parse(&input)?;
    Ok(fixture.run()?)
}

fn validate_simulation(simulation: &DkgSimulation) -> Result<(), CliError> {
    let aggregate_secret = simulation
        .aggregate_secret()
        .ok_or(CliError::VerificationFailed)?;
    let aggregate_public_key = simulation.aggregate_public_key()?;
    if aggregate_public_key == PallasPoint::generator_mul(aggregate_secret) {
        Ok(())
    } else {
        Err(CliError::VerificationFailed)
    }
}

fn ensure_trailing_newline(input: &str) -> String {
    if input.ends_with('\n') {
        input.to_owned()
    } else {
        format!("{input}\n")
    }
}

fn session_id_string(simulation: &DkgSimulation) -> String {
    String::from_utf8_lossy(&simulation.session_id).into_owned()
}

fn json_escape(input: &str) -> String {
    input
        .chars()
        .flat_map(|character| match character {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect(),
            '\n' => "\\n".chars().collect(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            _ => vec![character],
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    const CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(CHARS[usize::from(byte >> 4)]));
        output.push(char::from(CHARS[usize::from(byte & 0x0f)]));
    }
    output
}

enum Command {
    Status,
    Create {
        fixture: String,
        output: String,
    },
    Post {
        session: String,
    },
    Verify {
        session: String,
    },
    Recover {
        session: String,
        participant: ParticipantId,
    },
}

#[derive(Debug)]
enum CliError {
    Io(std::io::Error),
    Simulation(golden_pallas::SimulationError),
    InvalidParticipant,
    Usage,
    VerificationFailed,
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Simulation(error) => write!(formatter, "simulation failed: {error:?}"),
            Self::InvalidParticipant => write!(formatter, "participant id must be 1..=65535"),
            Self::Usage => write!(
                formatter,
                "usage: golden [status] | create <fixture> <session-out> | post <session> | verify <session> | recover <session> <participant-id>"
            ),
            Self::VerificationFailed => write!(formatter, "aggregate public key mismatch"),
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<golden_pallas::SimulationError> for CliError {
    fn from(value: golden_pallas::SimulationError) -> Self {
        Self::Simulation(value)
    }
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn verify_command_accepts_session_transcript() {
        let output = run(&[
            "verify".to_owned(),
            fixture_path().to_string_lossy().into_owned(),
        ])
        .expect("verify");

        assert!(output.contains("\"status\": \"verified\""));
        assert!(output.contains("\"transcripts\": 3"));
    }

    #[test]
    fn recover_command_emits_wallet_backup_json() {
        let output = run(&[
            "recover".to_owned(),
            fixture_path().to_string_lossy().into_owned(),
            "1".to_owned(),
        ])
        .expect("recover");

        assert!(output.contains("\"scheme\": \"golden-redpallas-wallet-backup\""));
        assert!(output.contains("\"participant_id\": 1"));
        assert!(output.contains("\"share_hex\": \""));
        assert!(output.contains("\"group_public_key_hex\": \""));
    }

    fn fixture_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../test-vectors/golden-pallas/dkg-v0.txt")
    }
}
