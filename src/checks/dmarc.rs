use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;

pub fn check_dmarc(domain: &str) -> Result<(String, Vec<String>), Box<dyn std::error::Error>> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    let dmarc_domain = format!("_dmarc.{}", domain);
    
    match resolver.txt_lookup(dmarc_domain) {
        Ok(response) => {
            let mut dmarc_records = Vec::new();
            let mut dmarc_tags = Vec::new();
            
            for record in response.iter() {
                if let Some(txt_data) = record.txt_data().first() {
                    let txt = String::from_utf8_lossy(txt_data);
                    if txt.starts_with("v=DMARC1") {
                        dmarc_records.push(txt.to_string());
                        dmarc_tags.extend(parse_dmarc_tags(&txt));
                    }
                }
            }

            let result = if dmarc_records.is_empty() {
                "No valid DMARC records found".to_string()
            } else if dmarc_records.len() > 1 {
                "Multiple DMARC records found (invalid)".to_string()
            } else {
                "Valid DMARC record found".to_string()
            };

            Ok((result, dmarc_tags))
        },
        Err(e) => match e.kind() {
            trust_dns_resolver::error::ResolveErrorKind::NoRecordsFound { .. } => {
                Ok(("No DMARC record found".to_string(), Vec::new()))
            },
            _ => Err(Box::new(e)),
        },
    }
}

fn parse_dmarc_tags(dmarc_record: &str) -> Vec<String> {
    dmarc_record
        .split(';')
        .map(str::trim)
        .filter(|&tag| !tag.is_empty())
        .map(String::from)
        .collect()
}
