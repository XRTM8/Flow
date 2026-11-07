//! تطهير الروابط من وسوم التتبع الرقمي (Smart Link Cleaner)
//! يقوم بإزالة وسوم التتبع التسويقي والمراقبة مثل ?utm_source=... و ?si=... دون لمس مسار الرابط الأصلي،
//! مع الحفاظ الصارم على فواصل الأسطر ومسافات التنسيق البرمجي والتبويبات.

const TRACKING_PARAMS: &[&str] = &[
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "si",     // YouTube share ID tracking
    "fbclid", // Facebook Click Identifier
    "gclid",  // Google Click Identifier
    "igshid", // Instagram Share ID
    "mc_cid", // Mailchimp
    "mc_eid",
    "_hsenc", // HubSpot
    "_hsmi",
    "ref",
    "ref_src",
    "spm", // AliExpress
];

fn clean_single_url(url: &str) -> (String, bool) {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return (url.to_string(), false);
    }

    if let Some((base, rest)) = url.split_once('?') {
        let (query, fragment) = match rest.split_once('#') {
            Some((q, f)) => (q, Some(f)),
            None => (rest, None),
        };

        // حماية الروابط البرمجية من حذف المتغير ref الشرعي
        let is_code_repo = base.contains("github.com") || base.contains("gitlab.com");

        let mut kept_params = Vec::new();
        let mut cleaned_any = false;

        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let key = pair.split('=').next().unwrap_or(pair);
            if key == "ref" && is_code_repo {
                kept_params.push(pair);
                continue;
            }

            if TRACKING_PARAMS.contains(&key) {
                cleaned_any = true;
            } else {
                kept_params.push(pair);
            }
        }

        if cleaned_any {
            let mut result = base.to_string();
            if !kept_params.is_empty() {
                result.push('?');
                result.push_str(&kept_params.join("&"));
            }
            if let Some(f) = fragment {
                result.push('#');
                result.push_str(f);
            }
            return (result, true);
        }
    }

    (url.to_string(), false)
}

/// استكشاف موقع الرابط التالي مع استبعاد علامات الترقيم والأقواس المحيطة
fn find_next_url(s: &str, start_idx: usize) -> Option<(usize, usize)> {
    if start_idx >= s.len() {
        return None;
    }
    let sub = &s[start_idx..];
    let http_pos = sub.find("http://");
    let https_pos = sub.find("https://");

    let rel_pos = match (http_pos, https_pos) {
        (Some(h), Some(hs)) => Some(std::cmp::min(h, hs)),
        (Some(h), None) => Some(h),
        (None, Some(hs)) => Some(hs),
        (None, None) => None,
    }?;

    let url_start = start_idx + rel_pos;
    let remainder = &s[url_start..];

    // تحديد نهاية الرابط عند أول مسافة أو محرف تحكم
    let end_offset = remainder
        .find(|c: char| c.is_whitespace() || c.is_control())
        .unwrap_or(remainder.len());

    let mut candidate = &remainder[..end_offset];
    let mut actual_len = candidate.len();

    // إزالة علامات الترقيم والأقواس اللاحقة إذا لم تكن جزءاً من مسار الرابط
    while actual_len > 0 {
        let last_char = candidate.chars().last().unwrap();
        if last_char == '.'
            || last_char == ','
            || last_char == ';'
            || last_char == '!'
            || last_char == '?'
            || last_char == ')'
            || last_char == ']'
            || last_char == '>'
            || last_char == '"'
            || last_char == '\''
        {
            // استثناء الأقواس المتطابقة كروابط ويكيبيديا
            if last_char == ')' {
                let open_count = candidate.chars().filter(|&c| c == '(').count();
                let close_count = candidate.chars().filter(|&c| c == ')').count();
                if open_count >= close_count {
                    break;
                }
            }
            actual_len -= last_char.len_utf8();
            candidate = &candidate[..actual_len];
        } else {
            break;
        }
    }

    if actual_len == 0 {
        return None;
    }

    Some((url_start, url_start + actual_len))
}

/// تطهير النصوص مع الحفاظ الصارم على الأسطر المتعددة ومسافات الأكواد والتبويبات
pub fn clean_text(input: &str) -> (String, bool) {
    if !input.contains("http://") && !input.contains("https://") {
        return (input.to_string(), false);
    }

    let mut result = String::with_capacity(input.len());
    let mut last_idx = 0;
    let mut any_cleaned = false;

    while let Some((start, end)) = find_next_url(input, last_idx) {
        result.push_str(&input[last_idx..start]);
        let raw_url = &input[start..end];
        let (cleaned_url, was_cleaned) = clean_single_url(raw_url);
        if was_cleaned {
            any_cleaned = true;
            result.push_str(&cleaned_url);
        } else {
            result.push_str(raw_url);
        }
        last_idx = end;
    }

    result.push_str(&input[last_idx..]);

    if any_cleaned {
        (result, true)
    } else {
        (input.to_string(), false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_youtube_url() {
        let raw = "https://youtu.be/dQw4w9WgXcQ?si=abcdef123456";
        let (cleaned, was_cleaned) = clean_text(raw);
        assert!(was_cleaned);
        assert_eq!(cleaned, "https://youtu.be/dQw4w9WgXcQ");
    }

    #[test]
    fn test_clean_utm_params() {
        let raw = "https://example.com/article?utm_source=twitter&id=42";
        let (cleaned, was_cleaned) = clean_text(raw);
        assert!(was_cleaned);
        assert_eq!(cleaned, "https://example.com/article?id=42");
    }

    #[test]
    fn test_plain_text_untouched() {
        let raw = "Hello Otium Flow";
        let (cleaned, was_cleaned) = clean_text(raw);
        assert!(!was_cleaned);
        assert_eq!(cleaned, raw);
    }

    #[test]
    fn test_embedded_url_in_sentence() {
        let text = "Check out this link: https://youtu.be/dQw4w9WgXcQ?si=999888&t=10s it is great";
        let (cleaned, was_cleaned) = clean_text(text);
        assert!(was_cleaned);
        assert_eq!(
            cleaned,
            "Check out this link: https://youtu.be/dQw4w9WgXcQ?t=10s it is great"
        );
    }

    #[test]
    fn test_preserve_github_ref_branch() {
        let url = "https://github.com/rust-lang/rust/tree/master?ref=main";
        let (cleaned, was_cleaned) = clean_text(url);
        assert!(!was_cleaned);
        assert_eq!(cleaned, url);
    }

    #[test]
    fn test_multiline_code_whitespace_and_tabs_preserved() {
        let code = "def process_data():\n\t# Source: https://example.com/api?utm_source=docs&key=abc\n\treturn 42\n";
        let (cleaned, was_cleaned) = clean_text(code);
        assert!(was_cleaned);
        assert_eq!(
            cleaned,
            "def process_data():\n\t# Source: https://example.com/api?key=abc\n\treturn 42\n"
        );
    }

    #[test]
    fn test_parenthesized_url_cleaned_with_delimiters() {
        let text = "Visit (https://store.example.com/item?id=99&fbclid=123) for details.";
        let (cleaned, was_cleaned) = clean_text(text);
        assert!(was_cleaned);
        assert_eq!(
            cleaned,
            "Visit (https://store.example.com/item?id=99) for details."
        );
    }
}
