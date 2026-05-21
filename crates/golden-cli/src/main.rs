//! Minimal CLI entry point for the Golden `RedPallas` workspace.

fn main() {
    println!("golden-redpallas workspace");
    println!("pallas/evrf: {}", golden_pallas::PallasVestaEvrf::status());
    println!(
        "frost/redpallas: {}",
        frost_redpallas::Zip312RerandomizedFrost::status()
    );
}
