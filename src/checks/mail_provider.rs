use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;
use trust_dns_resolver::error::ResolveErrorKind;

pub fn check_mail_provider(domain: &str) -> Result<String, Box<dyn std::error::Error>> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    
    match resolver.mx_lookup(domain) {
        Ok(response) => {
            let records = response.iter().next();
            match records {
                Some(record) => {
                    let exchange = record.exchange().to_ascii().to_lowercase();
                    if exchange.contains("google") {
                        Ok("Google".to_string())
                    } else if exchange.contains("outlook") || exchange.contains("microsoft") {
                        Ok("Microsoft".to_string())
                    } else if exchange.contains("amazonses") {
                        Ok("Amazon SES".to_string())
                    } else if exchange.contains("mimecast") {
                        Ok("Mimecast".to_string())
                    } else if exchange.contains("mailgun") {
                        Ok("Mailgun".to_string())
                    } else if exchange.contains("sendgrid") {
                        Ok("SendGrid".to_string())
                    } else if exchange.contains("protonmail") {
                        Ok("ProtonMail".to_string())
                    } else if exchange.contains("zoho") {
                        Ok("Zoho".to_string())
                    } else if exchange.contains("cloudflare") {
                        Ok("Cloudflare Email Routing".to_string())
                    } else if exchange.contains("pphosted") || exchange.contains("proofpoint") {
                        Ok("Proofpoint".to_string())
                    } else if exchange.contains("barracuda") {
                        Ok("Barracuda".to_string())
                    } else if exchange.contains("mailprotector") {
                        Ok("Mailprotector".to_string())
                    } else if exchange.contains("spamhero") {
                        Ok("SpamHero".to_string())
                    } else {
                        Ok(format!("Unknown ({})", exchange))
                    }
                },
                None => Ok("No MX records found".to_string()),
            }
        },
        Err(e) => match e.kind() {
            ResolveErrorKind::NoRecordsFound { .. } => Ok("No MX records found".to_string()),
            _ => Err(Box::new(e)),
        },
    }
}
