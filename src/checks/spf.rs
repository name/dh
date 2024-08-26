use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;
use trust_dns_resolver::error::ResolveErrorKind;

pub fn check_spf(domain: &str) -> Result<(String, Vec<String>), Box<dyn std::error::Error>> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    
    match resolver.txt_lookup(domain) {
        Ok(response) => {
            let mut spf_records = Vec::new();
            let mut trusted_senders = Vec::new();
            
            for record in response.iter() {
                if let Some(txt_data) = record.txt_data().first() {
                    let txt = String::from_utf8_lossy(txt_data);
                    if txt.starts_with("v=spf1") {
                        spf_records.push(txt.to_string());
                        trusted_senders.extend(parse_trusted_senders(&txt));
                    }
                }
            }

            let result = if spf_records.is_empty() {
                "No SPF records found".to_string()
            } else if spf_records.iter().all(|record| record.starts_with("v=spf1")) {
                "Valid SPF records".to_string()
            } else {
                format!("Invalid SPF records, but found: {}", spf_records.join(", "))
            };

            Ok((result, trusted_senders))
        },
        Err(e) => match e.kind() {
            ResolveErrorKind::NoRecordsFound { .. } => Ok(("No SPF records found".to_string(), Vec::new())),
            _ => Err(Box::new(e)),
        },
    }
}

fn parse_trusted_senders(spf_record: &str) -> Vec<String> {
    spf_record
        .split_whitespace()
        .filter_map(|mechanism| {
            if mechanism.starts_with("ip4:") || mechanism.starts_with("ip6:") {
                Some(mechanism.to_string())
            } else if mechanism.starts_with("include:") || mechanism.starts_with("a:") || mechanism.starts_with("mx:") {
                Some(mechanism.to_string())
            } else {
                None
            }
        })
        .collect()
}
