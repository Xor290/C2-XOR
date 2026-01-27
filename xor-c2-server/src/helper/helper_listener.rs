use axum::http::StatusCode;
use axum::response::Response;

pub fn empty_response(status: StatusCode) -> Response<String> {
    Response::builder()
        .status(status)
        .body(String::new())
        .unwrap()
}

pub fn text_response(status: StatusCode, body: String) -> Response<String> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(body)
        .unwrap()
}

pub fn json_response(status: StatusCode, body: String) -> Response<String> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(body)
        .unwrap()
}

pub fn json_error(status: StatusCode, message: &str) -> Response<String> {
    let json = serde_json::json!({
        "success": false,
        "message": message
    });
    json_response(status, json.to_string())
}

pub fn json_success() -> Response<String> {
    let json = serde_json::json!({ "success": true });
    json_response(StatusCode::OK, json.to_string())
}
