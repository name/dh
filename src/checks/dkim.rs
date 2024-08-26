use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;
use trust_dns_resolver::error::ResolveErrorKind;

pub fn check_dkim(domain: &str) -> Result<(String, Vec<String>), Box<dyn std::error::Error>> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    let common_selectors = ["default", "google", "dkim", "k1", "selector1", "selector2", "microsoft", "sendgrid"];
    
    let mut found_selectors = Vec::new();
    
    for selector in common_selectors.iter() {
        let dkim_domain = format!("{}._domainkey.{}", selector, domain);
        match resolver.txt_lookup(dkim_domain) {
            Ok(response) => {
                for record in response.iter() {
                    if let Some(txt_data) = record.txt_data().first() {
                        let txt = String::from_utf8_lossy(txt_data);
                        if txt.contains("v=DKIM1") {
                            found_selectors.push(format!("{}: {}", selector, trim_dkim_record(&txt)));
                        }
                    }
                }
            },
            Err(e) => {
                if !matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) {
                    return Err(Box::new(e));
                }
            },
        }
    }
    
    let result = if found_selectors.is_empty() {
        "No DKIM records found for common selectors".to_string()
    } else {
        format!("DKIM records found for {} selector(s)", found_selectors.len())
    };
    
    Ok((result, found_selectors))
}

fn trim_dkim_record(record: &str) -> String {
  let parts: Vec<&str> = record.split(';').collect();
  let trimmed_parts: Vec<String> = parts.iter().map(|&part| {
      if part.trim().starts_with("p=") {
          let key = part.trim().split('=').nth(1).unwrap_or("");
          if key.len() > 20 {
              format!(" p={}...{}", &key[..8], &key[key.len()-8..])
          } else {
              part.to_string()
          }
      } else {
          part.to_string()
      }
  }).collect();

  if trimmed_parts.len() <= 8 {
      return trimmed_parts.join(";");
  }
  
  let first_four = &trimmed_parts[..4].join(";");
  let last_four = &trimmed_parts[trimmed_parts.len() - 4..].join(";");
  format!("{}; ... ;{}", first_four, last_four)
}
