import base64
import json
import os
import urllib.error
import urllib.request

EC2_URL = os.environ["EC2_URL"]


def lambda_handler(event, context):
    method = event.get("httpMethod", "GET")
    path = event.get("path", "/")
    qs = event.get("queryStringParameters") or {}
    is_b64 = event.get("isBase64Encoded", False)
    body = event.get("body") or ""
    headers = {
        k: v
        for k, v in (event.get("headers") or {}).items()
        if k.lower() not in ("host", "x-forwarded-for")
    }

    if qs:
        qs_str = "&".join(f"{k}={v}" for k, v in qs.items())
        target_url = f"{EC2_URL}{path}?{qs_str}"
    else:
        target_url = f"{EC2_URL}{path}"

    if is_b64 and body:
        data = base64.b64decode(body)
    elif isinstance(body, str) and body:
        data = body.encode()
    else:
        data = None

    req = urllib.request.Request(target_url, data=data, method=method)
    for k, v in headers.items():
        try:
            req.add_header(k, v)
        except Exception:
            pass
    if data:
        req.add_header("Content-Length", str(len(data)))

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp_bytes = resp.read()
            try:
                resp_body = resp_bytes.decode("utf-8")
                is_b64_response = False
            except UnicodeDecodeError:
                resp_body = base64.b64encode(resp_bytes).decode("ascii")
                is_b64_response = True

            return {
                "statusCode": resp.status,
                "headers": {"Content-Type": "application/octet-stream"},
                "isBase64Encoded": is_b64_response,
                "body": resp_body,
            }
    except urllib.error.HTTPError as e:
        return {
            "statusCode": e.code,
            "body": json.dumps({"error": str(e.reason)}),
        }
    except Exception as e:
        return {
            "statusCode": 502,
            "body": json.dumps({"error": str(e)}),
        }
