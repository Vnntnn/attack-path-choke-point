variable "use_localstack" {
  description = "true = point at LocalStack (localhost:4566, dummy creds OK); false = real AWS"
  type        = bool
  default     = true
}

variable "aws_access_key" {
  description = "AWS access key id. LocalStack ignores the value (any string works) as long as use_localstack=true."
  type        = string
  sensitive   = true
}

variable "aws_secret_key" {
  description = "AWS secret access key. LocalStack ignores the value as long as use_localstack=true."
  type        = string
  sensitive   = true
}

variable "aws_session_token" {
  description = "STS session token, only needed for temporary/assumed-role credentials against real AWS. Leave empty otherwise."
  type        = string
  sensitive   = true
  default     = ""
}
