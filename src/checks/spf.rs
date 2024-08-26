use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::error::ResolveErrorKind;

pub fn check_spf(domain: &str) -> Result<(String, Vec<String>, Vec<String>), Box<dyn std::error::Error>> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    
    match resolver.txt_lookup(domain) {
        Ok(response) => {
            let mut spf_records = Vec::new();
            let mut trusted_senders = Vec::new();
            
            for record in response.iter() {
                let txt_data: String = record.txt_data().iter()
                    .map(|bytes| String::from_utf8_lossy(bytes))
                    .collect::<Vec<_>>()
                    .join("");
                
                if txt_data.starts_with("v=spf1") {
                    spf_records.push(txt_data.clone());
                    trusted_senders.extend(parse_trusted_senders(&txt_data));
                }
            }

            let result = if spf_records.is_empty() {
                "No SPF records found".to_string()
            } else {
                format!("Valid SPF record found")
            };

            Ok((result, trusted_senders, spf_records))
        },
        Err(e) => match e.kind() {
            ResolveErrorKind::NoRecordsFound { .. } => Ok(("No SPF records found".to_string(), Vec::new(), Vec::new())),
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
            } else if mechanism == "~all" || mechanism == "-all" || mechanism == "?all" {
                Some(mechanism.to_string())
            } else {
                None
            }
        })
        .collect()
}
