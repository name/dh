use clap::Parser;
use prettytable::{Table, row, format};

mod checks;

use checks::mail_provider::check_mail_provider;
use checks::spf::check_spf;
use checks::dmarc::check_dmarc;
use checks::dkim::check_dkim;
use checks::health_score::calculate_health_score;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    domain: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    let mail_provider = check_mail_provider(&cli.domain)?;
    let (spf_result, spf_trusted_senders, spf_records) = check_spf(&cli.domain)?;
    let (dmarc_result, dmarc_tags) = check_dmarc(&cli.domain)?;
    let (dkim_result, dkim_records) = check_dkim(&cli.domain)?;

    let health_score = calculate_health_score(
        &spf_result,
        &dmarc_result,
        &dkim_result,
        &spf_records,
        &dmarc_tags
    );

    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

    table.set_titles(row!["Domain Health Check", cli.domain]);
    table.add_row(row!["Mail Provider", mail_provider]);
    table.add_row(row!["SPF Check", spf_result]);
    table.add_row(row!["DMARC Check", dmarc_result]);
    table.add_row(row!["DKIM Check", dkim_result]);
    
    table.add_row(row!["Health Score", format!("{}/{} ({}%)", 
        health_score.score, 
        health_score.max_score,
        (health_score.score as f32 / health_score.max_score as f32 * 100.0).round()
    )]);
    
    if !spf_records.is_empty() {
        let first_record = spf_trusted_senders[0].clone();
        table.add_row(row!["SPF Trusted Senders", first_record]);
        for record in spf_trusted_senders.into_iter().skip(1) {
            table.add_row(row!["", record]);
        }
    } else {
        table.add_row(row!["SPF Trusted Senders", "None"]);
    }

    if !dmarc_tags.is_empty() {
        let first_tag = dmarc_tags[0].clone();
        table.add_row(row!["DMARC Tags", first_tag]);
        for tag in dmarc_tags.into_iter().skip(1) {
            table.add_row(row!["", tag]);
        }
    } else {
        table.add_row(row!["DMARC Tags", "None"]);
    }

    if !dkim_records.is_empty() {
        let first_record = dkim_records[0].clone();
        table.add_row(row!["DKIM Records", first_record]);
        for record in dkim_records.into_iter().skip(1) {
            table.add_row(row!["", record]);
        }
    } else {
        table.add_row(row!["DKIM Records", "None"]);
    }

    let (first_name, first_score): (String, u32) = health_score.breakdown[0].clone();
    table.add_row(row!["Score Breakdown", format!("{}: {}", first_name, first_score)]);
    for (name, score) in health_score.breakdown.into_iter().skip(1) {
        table.add_row(row!["", format!("{}: {}", name, score)]);
    }

    // Add suggestions
    if !health_score.suggestions.is_empty() {
        let first_suggestion = health_score.suggestions[0].clone();
        table.add_row(row!["Suggestions", first_suggestion]);
        for suggestion in health_score.suggestions.into_iter().skip(1) {
            table.add_row(row!["", suggestion]);
        }
    } else {
        table.add_row(row!["Suggestions", "None"]);
    }

    table.printstd();
    Ok(())
}
