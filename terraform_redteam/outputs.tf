output "api_gateway_url" {
  description = "URL publique de l'API Gateway (point d'entrée)"
  value       = "${aws_api_gateway_stage.prod.invoke_url}/"
}

output "ec2_private_ip" {
  description = "IP privée de l'EC2 (accessible depuis Lambda uniquement)"
  value       = aws_instance.backend.private_ip
}

output "ec2_public_ip" {
  description = "IP publique de l'EC2 (SSH)"
  value       = aws_instance.backend.public_ip
}

output "lambda_function_name" {
  description = "Nom de la fonction Lambda"
  value       = aws_lambda_function.proxy.function_name
}
