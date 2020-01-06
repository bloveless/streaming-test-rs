pub fn percent_encode(s: &str) -> String {
    let mut output: Vec<String> = Vec::new();
    for sb in s.as_bytes().iter() {
        if (*sb >= b'0' && *sb <= b'9') ||
            (*sb >= b'A' && *sb <= b'Z') ||
            (*sb >= b'a' && *sb <= b'z') ||
            (*sb == b'-') || (*sb == b'.') || (*sb == b'_') || (*sb == b'~')
        {
            let s = match String::from_utf8(vec![*sb]) {
                Ok(v) => v,
                Err(e) => panic!("Invalid utf8 sequence: {}", e),
            };

            output.push(s);
        } else {
            output.push(format!("%{:X}", sb));
        }
    }

    output.join("")
}

#[test]
fn test_spaces_and_plus() {
    assert_eq!(percent_encode("Ladies + Gentlemen"), "Ladies%20%2B%20Gentlemen");
}

#[test]
fn test_exclaimation() {
    assert_eq!(percent_encode("An encoded string!"), "An%20encoded%20string%21");
}

#[test]
fn test_comma_and_ampersand() {
    assert_eq!(percent_encode("Dogs, Cats & Mice"), "Dogs%2C%20Cats%20%26%20Mice");
}

#[test]
fn test_emoji() {
    assert_eq!(percent_encode("☃"), "%E2%98%83");
}