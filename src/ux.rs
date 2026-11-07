//! Presentation rules kept independent from the renderer and network tasks.
use crate::settings::tr;

pub fn connection_failure(error: &str, arabic: bool) -> String {
    let error = error.to_ascii_lowercase();
    if error.contains("pair")
        || error.contains("auth")
        || error.contains("decrypt")
        || error.contains("permission denied")
    {
        tr(
            arabic,
            "Pairing could not be confirmed. Paste the other device’s code on both devices.",
            "تعذّر تأكيد الاقتران. الصق رمز الجهاز الآخر على كلا الجهازين.",
        )
        .into()
    } else if error.contains("time")
        || error.contains("respond")
        || error.contains("refused")
        || error.contains("unreachable")
    {
        tr(
            arabic,
            "This device is not responding. Open Flow on it and check the local network.",
            "الجهاز لا يستجيب. افتح Flow عليه وتأكد من الشبكة المحلية.",
        )
        .into()
    } else {
        tr(
            arabic,
            "Connection failed. Try again, or set up pairing again.",
            "تعذّر الاتصال. أعد المحاولة أو أعد إعداد الاقتران.",
        )
        .into()
    }
}

pub fn may_clear_draft(current: &str, submitted: &str) -> bool {
    current == submitted
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn acknowledged_text_does_not_erase_edits_made_during_send() {
        assert!(may_clear_draft(
            "https://example.com/?utm_source=mail",
            "https://example.com/?utm_source=mail"
        ));
        assert!(!may_clear_draft("a new message", "the submitted message"));
    }
    #[test]
    fn failed_pairing_is_actionable_in_both_languages() {
        assert!(connection_failure("Pairing could not be verified", false).contains("code"));
        assert!(connection_failure("Timed out", true).contains("لا يستجيب"));
        assert!(!connection_failure("unexpected socket error", false).contains("Verifying"));
    }
}
