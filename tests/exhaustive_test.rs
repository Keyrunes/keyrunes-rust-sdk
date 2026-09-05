//! Exhaustive enumeration of the SDK's public parsing and normalisation rules.
//!
//! Every model here decodes something a server sent, and the interesting cases
//! are the ones that come from a server behaving slightly differently than the
//! one the SDK was written against: a field that is present but `null`, an ID
//! that is the empty string, a token response in the format the previous
//! Keyrunes release used. Those combinations are not sampled — they are walked
//! in full, so a rule stated in a doc comment is checked against every input it
//! claims to cover.
//!
//! The `exhaustive` crate does not enumerate numbers (the spaces grow too
//! fast), so numeric fields are modelled by the cases that behave differently:
//! absent, null, zero, positive, negative.

use exhaustive::{exhaustive_test, Exhaustive};
use keyrunes_rust_sdk::models::*;
use keyrunes_rust_sdk::KeyrunesClient;

// ---------------------------------------------------------------------------
// User: which field becomes the ID
// ---------------------------------------------------------------------------

/// The state of a string-shaped ID field in the JSON a server sent.
#[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
enum StringId {
    /// The key is not in the payload at all.
    Absent,
    /// The key is present with a JSON `null`, which serde reads as absent.
    Null,
    /// The key carries a value.
    Value,
    /// The key carries the empty string, which is a value like any other.
    Empty,
}

impl StringId {
    fn fragment(self, key: &str) -> Option<String> {
        match self {
            StringId::Absent => None,
            StringId::Null => Some(format!("\"{key}\":null")),
            StringId::Value => Some(format!("\"{key}\":\"{key}-value\"")),
            StringId::Empty => Some(format!("\"{key}\":\"\"")),
        }
    }

    /// What the conversion has to work with once serde is done.
    fn value(self, key: &str) -> Option<String> {
        match self {
            StringId::Absent | StringId::Null => None,
            StringId::Value => Some(format!("{key}-value")),
            StringId::Empty => Some(String::new()),
        }
    }
}

/// The state of the numeric `user_id` field.
#[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
enum NumericId {
    Absent,
    Null,
    Zero,
    Positive,
    Negative,
}

impl NumericId {
    fn fragment(self) -> Option<String> {
        self.value().map(|n| format!("\"user_id\":{n}"))
    }

    fn value(self) -> Option<i64> {
        match self {
            NumericId::Absent | NumericId::Null => None,
            NumericId::Zero => Some(0),
            NumericId::Positive => Some(42),
            NumericId::Negative => Some(-7),
        }
    }
}

fn user_json(id: StringId, external: StringId, numeric: NumericId) -> String {
    let mut fields = vec![
        "\"username\":\"jo\"".to_string(),
        "\"email\":\"jo@example.com\"".to_string(),
    ];
    fields.extend(id.fragment("id"));
    fields.extend(external.fragment("external_id"));
    // `Null` has no fragment of its own above, so spell it out here.
    if numeric == NumericId::Null {
        fields.push("\"user_id\":null".to_string());
    } else {
        fields.extend(numeric.fragment());
    }
    format!("{{{}}}", fields.join(","))
}

fn parse_user(json: &str) -> User {
    serde_json::from_str(json).unwrap_or_else(|e| panic!("{json} did not parse: {e}"))
}

/// 4 x 4 x 5 = 80 combinations.
///
/// Three different Keyrunes endpoints name the same thing differently, so the
/// SDK picks the first one that is there: `id`, then `external_id`, then a
/// numeric `user_id` rendered as text, and only then the placeholder.
#[exhaustive_test]
fn the_user_id_comes_from_the_first_field_that_carries_one(
    id: StringId,
    external: StringId,
    numeric: NumericId,
) {
    let json = user_json(id, external, numeric);
    let user = parse_user(&json);

    let expected = if let Some(value) = id.value("id") {
        value
    } else if let Some(value) = external.value("external_id") {
        value
    } else if let Some(number) = numeric.value() {
        number.to_string()
    } else {
        "unknown".to_string()
    };

    assert_eq!(user.id, expected, "for {json}");
}

/// 4 x 5 = 20 combinations.
///
/// Precedence stated as a property rather than as a formula: once `id` is
/// there, nothing else in the payload can change the answer.
#[exhaustive_test]
fn a_present_id_makes_the_lower_priority_fields_irrelevant(external: StringId, numeric: NumericId) {
    let alone = parse_user(&user_json(
        StringId::Value,
        StringId::Absent,
        NumericId::Absent,
    ));
    let crowded = parse_user(&user_json(StringId::Value, external, numeric));

    assert_eq!(
        alone.id, crowded.id,
        "{external:?}/{numeric:?} changed an ID that `id` had already decided"
    );
}

/// 4 x 5 = 20 combinations.
///
/// The same property one level down: with `id` out of the way, `external_id`
/// settles it and the numeric field cannot interfere.
#[exhaustive_test]
fn a_present_external_id_outranks_the_numeric_id(external: StringId, numeric: NumericId) {
    if external.value("external_id").is_none() {
        return; // nothing to outrank with
    }

    let user = parse_user(&user_json(StringId::Absent, external, numeric));
    assert_eq!(user.id, external.value("external_id").unwrap());
}

/// 4 x 4 x 5 = 80 combinations.
///
/// The placeholder is a last resort, never something a real payload produces:
/// if the server named the user at all, that name is what comes back.
#[exhaustive_test]
fn the_placeholder_appears_only_when_no_field_named_the_user(
    id: StringId,
    external: StringId,
    numeric: NumericId,
) {
    let named_it = id.value("id").is_some()
        || external.value("external_id").is_some()
        || numeric.value().is_some();

    let user = parse_user(&user_json(id, external, numeric));

    assert_eq!(
        user.id == "unknown",
        !named_it,
        "for {}",
        user_json(id, external, numeric)
    );
}

/// 4 x 4 x 5 = 80 combinations.
///
/// The fields that are not part of the ID rule survive it untouched, and the
/// collections default to empty rather than to a parse failure.
#[exhaustive_test]
fn the_rest_of_the_user_survives_the_id_rule(id: StringId, external: StringId, numeric: NumericId) {
    let user = parse_user(&user_json(id, external, numeric));

    assert_eq!(user.username, "jo");
    assert_eq!(user.email, "jo@example.com");
    assert!(user.groups.is_empty());
    assert!(user.created_at.is_none());
    assert!(user.updated_at.is_none());
}

// ---------------------------------------------------------------------------
// Token: two wire formats, one type
// ---------------------------------------------------------------------------

/// Which key the server used to name the token.
#[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
enum TokenKey {
    /// Current Keyrunes: `token`.
    Current,
    /// Pre-0.3 Keyrunes: `access_token`.
    Legacy,
    /// Both, which a server behind a translating proxy can produce.
    Both,
    /// Neither, which is not a token response at all.
    Neither,
}

/// The state of one of the optional fields around the token.
#[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
enum OptionalField {
    Absent,
    Null,
    Present,
}

impl OptionalField {
    fn fragment(self, key: &str, value: &str) -> Option<String> {
        match self {
            OptionalField::Absent => None,
            OptionalField::Null => Some(format!("\"{key}\":null")),
            OptionalField::Present => Some(format!("\"{key}\":{value}")),
        }
    }

    fn is_present(self) -> bool {
        self == OptionalField::Present
    }
}

const CURRENT_TOKEN: &str = "current-token";
const LEGACY_TOKEN: &str = "legacy-token";

fn token_json(
    key: TokenKey,
    token_type: OptionalField,
    expires_in: OptionalField,
    refresh_token: OptionalField,
    expires_at: OptionalField,
) -> String {
    let mut fields: Vec<String> = Vec::new();
    if matches!(key, TokenKey::Current | TokenKey::Both) {
        fields.push(format!("\"token\":\"{CURRENT_TOKEN}\""));
    }
    if matches!(key, TokenKey::Legacy | TokenKey::Both) {
        fields.push(format!("\"access_token\":\"{LEGACY_TOKEN}\""));
    }
    fields.extend(token_type.fragment("token_type", "\"bearer\""));
    fields.extend(expires_in.fragment("expires_in", "3600"));
    fields.extend(refresh_token.fragment("refresh_token", "\"refresh\""));
    fields.extend(expires_at.fragment("expires_at", "\"2030-01-01T00:00:00Z\""));
    format!("{{{}}}", fields.join(","))
}

/// 4 x 3 x 3 x 3 x 3 = 324 combinations.
///
/// The token itself: a response naming it either way is understood, a response
/// naming it both ways prefers the current field, and a response naming it
/// neither way is rejected instead of yielding an empty token.
#[exhaustive_test]
fn a_token_is_read_from_whichever_field_the_server_used(
    key: TokenKey,
    token_type: OptionalField,
    expires_in: OptionalField,
    refresh_token: OptionalField,
    expires_at: OptionalField,
) {
    let json = token_json(key, token_type, expires_in, refresh_token, expires_at);
    let parsed = serde_json::from_str::<Token>(&json);

    match key {
        TokenKey::Neither => {
            assert!(parsed.is_err(), "{json} must not produce a token");
        }
        TokenKey::Current | TokenKey::Both => {
            assert_eq!(parsed.unwrap().token, CURRENT_TOKEN, "for {json}");
        }
        TokenKey::Legacy => {
            assert_eq!(parsed.unwrap().token, LEGACY_TOKEN, "for {json}");
        }
    }
}

/// 4 x 3 x 3 x 3 x 3 = 324 combinations.
///
/// A field the server omitted and a field it sent as `null` mean the same
/// thing to the caller: absent. Neither may become an empty string or a zero.
#[exhaustive_test]
fn an_omitted_field_and_a_null_field_are_both_absent(
    key: TokenKey,
    token_type: OptionalField,
    expires_in: OptionalField,
    refresh_token: OptionalField,
    expires_at: OptionalField,
) {
    if key == TokenKey::Neither {
        return; // no token to inspect
    }

    let json = token_json(key, token_type, expires_in, refresh_token, expires_at);
    let token: Token = serde_json::from_str(&json).unwrap_or_else(|e| panic!("{json}: {e}"));

    assert_eq!(
        token.token_type.is_some(),
        token_type.is_present(),
        "{json}"
    );
    assert_eq!(
        token.expires_in.is_some(),
        expires_in.is_present(),
        "{json}"
    );
    assert_eq!(
        token.refresh_token.is_some(),
        refresh_token.is_present(),
        "{json}"
    );
}

/// 3 x 3 x 3 = 27 combinations.
///
/// `expires_at` exists only in the current format. A legacy response has no
/// place to put one, so the SDK must report none — even when the payload
/// carries the key, which a proxy bolting the two formats together would do.
#[exhaustive_test]
fn a_legacy_response_never_reports_an_expiry_date(
    token_type: OptionalField,
    expires_in: OptionalField,
    refresh_token: OptionalField,
) {
    for expires_at in [
        OptionalField::Absent,
        OptionalField::Null,
        OptionalField::Present,
    ] {
        let json = token_json(
            TokenKey::Legacy,
            token_type,
            expires_in,
            refresh_token,
            expires_at,
        );
        let token: Token = serde_json::from_str(&json).unwrap_or_else(|e| panic!("{json}: {e}"));
        assert!(token.expires_at.is_none(), "{json} produced an expiry");
    }
}

/// 3 x 3 x 3 = 27 combinations.
///
/// The current format does carry the expiry through, so the previous test is
/// pinning a real difference rather than a parser that drops the field.
#[exhaustive_test]
fn the_current_format_carries_the_expiry_date_through(
    token_type: OptionalField,
    expires_in: OptionalField,
    refresh_token: OptionalField,
) {
    let json = token_json(
        TokenKey::Current,
        token_type,
        expires_in,
        refresh_token,
        OptionalField::Present,
    );
    let token: Token = serde_json::from_str(&json).unwrap_or_else(|e| panic!("{json}: {e}"));
    assert!(token.expires_at.is_some(), "{json} dropped the expiry");
}

// ---------------------------------------------------------------------------
// Namespace: always sent, defaulted when absent
// ---------------------------------------------------------------------------

/// A payload type carrying a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
enum Payload {
    UserRegistration,
    AdminRegistration,
    LoginCredentials,
}

/// The state of the `namespace` key in a payload being read back.
#[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
enum NamespaceField {
    Absent,
    Custom,
    /// The empty string, which is a choice the caller made, not an absence.
    Empty,
}

impl NamespaceField {
    fn fragment(self) -> Option<&'static str> {
        match self {
            NamespaceField::Absent => None,
            NamespaceField::Custom => Some("\"namespace\":\"tenant-7\""),
            NamespaceField::Empty => Some("\"namespace\":\"\""),
        }
    }

    fn expected(self) -> &'static str {
        match self {
            NamespaceField::Absent => DEFAULT_NAMESPACE,
            NamespaceField::Custom => "tenant-7",
            NamespaceField::Empty => "",
        }
    }
}

fn payload_json(payload: Payload, namespace: NamespaceField) -> String {
    let mut fields = vec![
        "\"password\":\"password123\"".to_string(),
        match payload {
            Payload::LoginCredentials => "\"identity\":\"jo\"".to_string(),
            _ => "\"username\":\"jo\"".to_string(),
        },
    ];
    if payload != Payload::LoginCredentials {
        fields.push("\"email\":\"jo@example.com\"".to_string());
    }
    if payload == Payload::AdminRegistration {
        fields.push("\"admin_key\":\"secret\"".to_string());
    }
    fields.extend(namespace.fragment().map(str::to_string));
    format!("{{{}}}", fields.join(","))
}

/// Reads the payload back and returns the namespace it ended up with, plus the
/// JSON it produces when serialised again.
fn round_trip(payload: Payload, namespace: NamespaceField) -> (String, String) {
    let json = payload_json(payload, namespace);
    match payload {
        Payload::UserRegistration => {
            let value: UserRegistration =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("{json}: {e}"));
            (
                value.namespace.clone(),
                serde_json::to_string(&value).unwrap(),
            )
        }
        Payload::AdminRegistration => {
            let value: AdminRegistration =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("{json}: {e}"));
            (
                value.namespace.clone(),
                serde_json::to_string(&value).unwrap(),
            )
        }
        Payload::LoginCredentials => {
            let value: LoginCredentials =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("{json}: {e}"));
            (
                value.namespace.clone(),
                serde_json::to_string(&value).unwrap(),
            )
        }
    }
}

/// 3 x 3 = 9 combinations.
///
/// The server rejects a payload without `namespace` with 422, so the field is
/// filled in when absent and never dropped on the way out. An explicit empty
/// string is the caller's choice and is preserved, not overwritten.
#[exhaustive_test]
fn a_namespace_is_defaulted_when_absent_and_always_serialised(
    payload: Payload,
    namespace: NamespaceField,
) {
    let (value, serialised) = round_trip(payload, namespace);

    assert_eq!(value, namespace.expected(), "{payload:?}/{namespace:?}");
    assert!(
        serialised.contains("\"namespace\":"),
        "{payload:?} dropped the namespace: {serialised}"
    );
}

/// The default is the literal the server expects, not merely non-empty.
#[test]
fn the_default_namespace_is_public() {
    assert_eq!(DEFAULT_NAMESPACE, "public");
}

// ---------------------------------------------------------------------------
// GroupCheck: one answer under two names
// ---------------------------------------------------------------------------

/// Which key the server used for the membership answer.
#[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
enum CheckKey {
    HasGroup,
    HasAccess,
}

/// 2 x 2 = 4 combinations.
///
/// The endpoint has answered under both names across releases; either must be
/// read, and the answer must come back unflipped.
#[exhaustive_test]
fn a_membership_answer_is_read_under_either_name(key: CheckKey, answer: bool) {
    let name = match key {
        CheckKey::HasGroup => "has_group",
        CheckKey::HasAccess => "has_access",
    };
    let json = format!("{{\"{name}\":{answer}}}");

    let check: GroupCheck = serde_json::from_str(&json).unwrap_or_else(|e| panic!("{json}: {e}"));
    assert_eq!(check.has_group, answer, "for {json}");
}

/// An answer the SDK cannot find is an error, never a silent `false`: this
/// value gates access.
#[test]
fn a_missing_membership_answer_is_rejected() {
    assert!(serde_json::from_str::<GroupCheck>("{}").is_err());
}

// ---------------------------------------------------------------------------
// Base URL normalisation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
enum Scheme {
    Http,
    Https,
}

#[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
enum Authority {
    Host,
    HostWithPort,
}

#[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
enum BasePath {
    None,
    Nested,
    Deep,
}

/// How many trailing slashes the caller left on the URL.
#[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
enum Trailing {
    Zero,
    One,
    Two,
    Several,
}

impl Trailing {
    fn count(self) -> usize {
        match self {
            Trailing::Zero => 0,
            Trailing::One => 1,
            Trailing::Two => 2,
            Trailing::Several => 5,
        }
    }
}

fn base_url_of(scheme: Scheme, authority: Authority, path: BasePath, trailing: Trailing) -> String {
    let scheme = match scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    };
    let authority = match authority {
        Authority::Host => "keyrunes.example.com",
        Authority::HostWithPort => "keyrunes.example.com:8443",
    };
    let path = match path {
        BasePath::None => "",
        BasePath::Nested => "/auth",
        BasePath::Deep => "/services/auth/v1",
    };
    format!(
        "{scheme}://{authority}{path}{}",
        "/".repeat(trailing.count())
    )
}

/// 2 x 2 x 3 x 4 = 48 combinations.
///
/// Every endpoint path in the client starts with `/`, so the base URL must not
/// end with one. Configuration arrives from environment variables and copied
/// dashboard fields, which is exactly where stray trailing slashes come from.
#[exhaustive_test]
fn a_base_url_never_keeps_a_trailing_slash(
    scheme: Scheme,
    authority: Authority,
    path: BasePath,
    trailing: Trailing,
) {
    let input = base_url_of(scheme, authority, path, trailing);
    let client = KeyrunesClient::new(&input).unwrap_or_else(|e| panic!("{input} rejected: {e}"));

    assert!(
        !client.base_url().ends_with('/'),
        "{input} kept a trailing slash: {}",
        client.base_url()
    );
    assert!(
        input.starts_with(client.base_url()),
        "{input} was rewritten into {}",
        client.base_url()
    );
}

/// 2 x 2 x 3 x 4 = 48 combinations.
///
/// The point of the normalisation: concatenating an endpoint must produce the
/// same request URL whatever the caller typed.
#[exhaustive_test]
fn the_same_endpoint_is_reached_however_the_base_url_was_typed(
    scheme: Scheme,
    authority: Authority,
    path: BasePath,
    trailing: Trailing,
) {
    let plain = KeyrunesClient::new(base_url_of(scheme, authority, path, Trailing::Zero)).unwrap();
    let typed = KeyrunesClient::new(base_url_of(scheme, authority, path, trailing)).unwrap();

    let request_url = |client: &KeyrunesClient| format!("{}/api/login", client.base_url());
    assert_eq!(request_url(&plain), request_url(&typed));

    let parsed = url::Url::parse(&request_url(&typed)).expect("the joined URL must parse");
    assert!(
        parsed.path().ends_with("/api/login"),
        "{} lost the endpoint",
        parsed
    );
    assert!(
        !parsed.path().contains("//"),
        "{} has a doubled slash",
        parsed
    );
}

/// A string that is not a URL is refused at construction, not at the first
/// request.
#[test]
fn a_base_url_that_is_not_a_url_is_refused() {
    assert!(KeyrunesClient::new("keyrunes.example.com").is_err());
    assert!(KeyrunesClient::new("").is_err());
}
