use std::path::PathBuf;

use clap::Parser;
use ronova_core::{
    analysis::{AnalysisReport, AnalysisState},
    capture::{CaptureCompletion, CaptureProcessError, CaptureReader},
    packet::PacketParser,
};

// Command-line arguments accepted by ronova-cli.
//
// Der CLI bekommt zunächst nur einen Capture-Pfad.
// Weitere Optionen können später ergänzt werden, sobald die
// eigentliche Analyse-Pipeline stable ist.
#[derive(Debug, Parser)]
#[command(name = "ronova")]
#[command(about = "Passive network traffic analysis")]
struct Cli {
    // Path to the PCAP capture that should be analysed.
    capture: PathBuf,
}

// Maximum number of sample packet shown in the human-readable CLI output.
const SAMPLE_SIZE: usize = 10;

fn main() {
    // Parse command-line arguments before starting the analysis pipeline.
    let cli = Cli::parse();

    if let Err(error) = run(cli) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

// Runs the complete Ronova analysis pipeline for one capture.
//
// Der CLI orchestriert nur die Komponenten.
// Die eigentliche Parsing- und Flow-Logik bleibt im ronova-core.
fn run(cli: Cli) -> Result<(), String> {
    // Open the capture source through the core capture abstraction.
    let reader = CaptureReader::open(&cli.capture)
        .map_err(|error| format!("failed to open capture: {error:?}"))?;

    // The parser itself is stateless, so one instance can be reused
    // for every packet processed by the capture reader.
    let parser = PacketParser::new();

    // AnalysisState owns the accumulated analysis results.
    let mut state = AnalysisState::new();

    // Process every capture packet while borrowing packet data only
    // for the duration of the callback.
    let completion = reader
        .process(|record| state.process_packet(&parser, &record))
        .map_err(|error| match error {
            // Capture failures originate from the capture source itself.
            CaptureProcessError::Capture(error) => {
                format!("capture processing failed: {error:?}")
            }

            // Packet analysis failures originate from the downstream
            // analysis handler.
            CaptureProcessError::Handler(error) => {
                format!("packet analysis failed: {error:?}")
            }
        })?;

    // Consume the analysis state into its final report representation
    //
    // This moves the accumulated flow state instead of cloning it.
    let report = state.into_report();

    // Display the final analysis result.
    print_report(&report);

    // A partial capture is still a valid analysis result, but the CLI
    // should make the incomplete capture explicit to the user.
    if let CaptureCompletion::Partial { reason } = completion {
        println!();
        println!("Capture completed partially: {reason:?}");
    };

    Ok(())
}

// Prints the human-readable analysis report.
//
// Presentation stays in the CLI so ronova-core does not need to know
// anything about terminal formatting.
fn print_report(report: &AnalysisReport) {
    println!("Ronova Analysis");
    println!("===============");
    println!();

    println!("Flows: {}", report.flows().len());

    if !report.unsupported_packets().is_empty() {
        println!();
        println!("Unsupported packets");

        print_unsupported(report);
    }

    if !report.defects().is_empty() {
        println!();
        println!("Packet defects");

        print_defects(report);
    }

    for (index, flow) in report.flows().iter().enumerate() {
        println!();
        println!("Flow #{}", index + 1);

        println!(
            "  Endpoint A : {}:{}",
            flow.endpoint_a().ip,
            flow.endpoint_a().port
        );

        println!(
            "  Endpoint B : {}:{}",
            flow.endpoint_b().ip,
            flow.endpoint_b().port
        );

        println!("  Protocol   : {:?}", flow.protocol());
        println!("  Packets    : {}", flow.packet_count());
        println!("  Bytes      : {}", flow.byte_count());

        println!();
        println!("  A -> B");
        println!("    Packets  : {}", flow.a_to_b_packets());
        println!("    Bytes    : {}", flow.a_to_b_bytes());

        println!();
        println!("  B -> A");
        println!("    Packets  : {}", flow.b_to_a_packets());
        println!("    Bytes    : {}", flow.b_to_a_bytes());
    }
}

// Print a bounded sample so a large capture cannot flood the terminal.
fn print_defects(report: &AnalysisReport) {
    let defects = report.defects();

    println!("Packet defects: {}", defects.len());

    if defects.is_empty() {
        return;
    }

    println!();
    println!(
        "Showing first {} defect(s):",
        defects.len().min(SAMPLE_SIZE)
    );

    for defect in defects.iter().take(SAMPLE_SIZE) {
        println!("  #{}: {:?}", defect.packet_number(), defect.reason());
    }

    // Tell the user how many defects were intentionally omitted.
    let omitted = defects.len().saturating_sub(SAMPLE_SIZE);

    if omitted > 0 {
        println!("  ... {} more defect(s)", omitted);
    }
}

// Print a bounded sample so a large capture cannot flood the terminal.
fn print_unsupported(report: &AnalysisReport) {
    let unsupported = report.unsupported_packets();

    println!("Unsupported packets: {}", unsupported.len());

    if unsupported.is_empty() {
        return;
    }

    println!();
    println!(
        "Showing first {} unsupported(s):",
        unsupported.len().min(SAMPLE_SIZE)
    );

    for unsupported in unsupported.iter().take(SAMPLE_SIZE) {
        println!(
            "  #{}: {:?}",
            unsupported.packet_number(),
            unsupported.reason()
        );
    }

    // Tell the user how many unsupported were intentionally omitted.
    let omitted = unsupported.len().saturating_sub(SAMPLE_SIZE);

    if omitted > 0 {
        println!("  ... {} more unsupported(s)", omitted);
    }
}
