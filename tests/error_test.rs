use keyrunes_rust_sdk::KeyrunesError;

#[test]
fn test_authentication_error() {
    // #setup
    let err = KeyrunesError::AuthenticationError("Invalid credentials".to_string());

    // #assert
    assert!(err.to_string().contains("Authentication error"));
    assert!(err.to_string().contains("Invalid credentials"));
}

#[test]
fn test_authorization_error() {
    // #setup
    let err = KeyrunesError::AuthorizationError("Access denied".to_string());

    // #assert
    assert!(err.to_string().contains("Authorization error"));
    assert!(err.to_string().contains("Access denied"));
}

#[test]
fn test_user_not_found_error() {
    // #setup
    let err = KeyrunesError::UserNotFoundError("User not found".to_string());

    // #assert
    assert!(err.to_string().contains("User not found"));
}

#[test]
fn test_group_not_found_error() {
    // #setup
    let err = KeyrunesError::GroupNotFoundError("Group not found".to_string());

    // #assert
    assert!(err.to_string().contains("Group not found"));
}

#[test]
fn test_network_error() {
    // #setup
    let err = KeyrunesError::NetworkError("Connection timeout".to_string());

    // #assert
    assert!(err.to_string().contains("Network error"));
    assert!(err.to_string().contains("Connection timeout"));
}

#[test]
fn test_invalid_token() {
    // #setup
    let err = KeyrunesError::InvalidToken;

    // #assert
    assert!(err.to_string().contains("Invalid or missing token"));
}

#[test]
fn test_from_url_parse_error() {
    // #setup
    let parse_err = url::ParseError::EmptyHost;
    let err: KeyrunesError = parse_err.into();

    // #assert
    match err {
        KeyrunesError::InvalidUrl(_) => {}
        _ => panic!("Expected InvalidUrl"),
    }
}
