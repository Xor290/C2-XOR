data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_code"
  output_path = "${path.module}/.build/lambda.zip"
}

data "aws_iam_role" "lab" {
  name = "LabRole"
}

resource "aws_lambda_function" "proxy" {
  function_name    = "${var.project_name}-proxy"
  role             = data.aws_iam_role.lab.arn
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  runtime = "python3.12"
  handler = "index.lambda_handler"
  timeout = 15

  environment {
    variables = {
      EC2_URL = "http://${aws_instance.backend.public_ip}:80"
    }
  }

  tags = {
    Project = var.project_name
  }
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.proxy.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.api.execution_arn}/*/*"
}
