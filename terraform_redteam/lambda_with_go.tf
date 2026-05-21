resource "null_resource" "build_lambda" {
  triggers = {
    src = md5(file("${path.module}/lambda_code/index.go"))
  }

  provisioner "local-exec" {
    command = <<-EOT
      cd ${path.module}/lambda_code && \
      go mod tidy && \
      GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ${path.module}/.build/bootstrap .
    EOT
  }
}

data "archive_file" "lambda_zip" {
  depends_on  = [null_resource.build_lambda]
  type        = "zip"
  source_file = "${path.module}/.build/bootstrap"
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

  runtime = "provided.al2023"
  handler = "bootstrap"
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
