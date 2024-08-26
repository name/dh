pub struct HealthScore {
    pub score: u32,
    pub max_score: u32,
    pub breakdown: Vec<(String, u32)>,
    pub suggestions: Vec<String>,
}

pub fn calculate_health_score(
    spf_result: &str,
    dmarc_result: &str,
    dkim_result: &str,
    spf_records: &[String],
    dmarc_tags: &[String],
) -> HealthScore {
    let mut score = 0;
    let mut breakdown = Vec::new();
    let mut suggestions = Vec::new();
    let max_score = 100;

    // SPF (33 points)
    let spf_score = if spf_result.contains("Valid") {
        if spf_records.iter().any(|record| record.contains("-all")) {
            33 // Full points for valid SPF with hard fail
        } else {
            suggestions.push("Consider adding a hard fail (-all) to your SPF record for stronger protection.".to_string());
            25 // Partial points for valid SPF without hard fail
        }
    } else {
        suggestions.push("Implement a valid SPF record to improve email authentication.".to_string());
        0
    };
    score += spf_score;
    breakdown.push(("SPF".to_string(), spf_score));

    // DMARC (34 points)
    let dmarc_score = if dmarc_result.contains("Valid") {
        if dmarc_tags.iter().any(|tag| tag.contains("p=reject")) {
            34 // Full points for p=reject
        } else if dmarc_tags.iter().any(|tag| tag.contains("p=quarantine")) {
            suggestions.push("Consider upgrading your DMARC policy to 'p=reject' for maximum security.".to_string());
            25 // Partial points for p=quarantine
        } else {
            suggestions.push("Strengthen your DMARC policy by setting it to 'p=quarantine' or 'p=reject'.".to_string());
            20 // Fewer points for p=none or no policy specified
        }
    } else {
        suggestions.push("Implement a DMARC record to enhance email security and reduce the risk of email spoofing.".to_string());
        0
    };
    score += dmarc_score;
    breakdown.push(("DMARC".to_string(), dmarc_score));

    // DKIM (33 points)
    let dkim_score = if !dkim_result.contains("No DKIM records found for") {
        33 // Full points if any DKIM record is found
    } else {
        suggestions.push("Set up DKIM for your domain to improve email authentication and deliverability.".to_string());
        0
    };
    score += dkim_score;
    breakdown.push(("DKIM".to_string(), dkim_score));

    HealthScore {
        score,
        max_score,
        breakdown,
        suggestions,
    }
}
