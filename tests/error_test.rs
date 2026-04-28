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

#[test]
fn test_from_url_parse_error_invalid_port() {
    // #setup
    let parse_err = url::ParseError::InvalidPort;
    let err: KeyrunesError = parse_err.into();

    // #assert
    match err {
        KeyrunesError::InvalidUrl(_) => {}
        _ => panic!("Expected InvalidUrl"),
    }
}

#[test]
fn test_from_serde_json_error() {
    // #setup
    let json_result: Result<serde_json::Value, serde_json::Error> = serde_json::from_str("invalid json");
    let parse_err = json_result.unwrap_err();
    let err: KeyrunesError = parse_err.into();

    // #assert
    match err {
        KeyrunesError::SerializationError(_) => {}
        _ => panic!("Expected SerializationError"),
    }
}

#[tokio::test]
async fn test_from_reqwest_error_timeout() {
    // #setup
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(1))
        .build()
        .unwrap();

    // Use TEST-NET-1 address (192.0.2.0/24) which is reserved for documentation and won't respond
    let result = client
        .get("http://192.0.2.1:9999")
        .send()
        .await;

    // #act
    let err: KeyrunesError = result.unwrap_err().into();

    // #assert
    match err {
        KeyrunesError::NetworkError(_) => {}
        _ => panic!("Expected NetworkError for timeout/connect error, got {:?}", err),
    }
}

#[tokio::test]
async fn test_from_reqwest_error_http() {
    // #setup
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = stream.try_write(b"HTTP/1.1 ");
            drop(stream);
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = reqwest::Client::new();
    let result = client
        .get(format!("http://127.0.0.1:{}/", port))
        .send()
        .await;

    // #act
    let err: KeyrunesError = result.unwrap_err().into();

    // #assert
    match err {
        KeyrunesError::HttpError(_) => {}
        _ => panic!("Expected HttpError for non-timeout/connect error, got {:?}", err),
    }
}
