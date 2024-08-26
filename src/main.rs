use clap::Parser;
use prettytable::{Table, row, format};

mod checks;

use checks::mail_provider::check_mail_provider;
use checks::spf::check_spf;
use checks::dmarc::check_dmarc;
use checks::dkim::check_dkim;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    domain: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    let mail_provider = check_mail_provider(&cli.domain)?;
    let (spf_result, spf_records) = check_spf(&cli.domain)?;
    let (dmarc_result, dmarc_tags) = check_dmarc(&cli.domain)?;
    let (dkim_result, dkim_records) = check_dkim(&cli.domain)?;

    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);

    table.set_titles(row!["Domain Health Check", cli.domain]);
    table.add_row(row!["Mail Provider", mail_provider]);
    table.add_row(row!["SPF Check", spf_result]);
    table.add_row(row!["DMARC Check", dmarc_result]);
    table.add_row(row!["DKIM Check", dkim_result]);
    
    if !spf_records.is_empty() {
        let first_record = spf_records[0].clone();
        table.add_row(row!["SPF Trusted Senders", first_record]);
        for record in spf_records.into_iter().skip(1) {
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

    table.printstd();
    Ok(())
}
