# Configure the AWS provider
provider "aws" {
  region = "us-west-2" # Change to your desired AWS region
}

# --- 1. IAM Role and Policy for the Lambda Function ---

# Define the IAM policy with required permissions
resource "aws_iam_policy" "lambda_policy" {
  name        = "LambdaALBLogAnalyzerPolicy"
  description = "IAM policy for the ALB Log Analyzer Lambda function"

  # JSON policy document. Replace the bucket names with your own.
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["s3:GetObject"],
        Resource = "arn:aws:s3:::SOURCE-BUCKET-NAME/*"
      },
      {
        Effect   = "Allow",
        Action   = ["s3:ListBucket"],
        Resource = "arn:aws:s3:::SOURCE-BUCKET-NAME"
      },
      {
        Effect   = "Allow",
        Action   = ["s3:PutObject"],
        Resource = "arn:aws:s3:::DESTINATION-BUCKET-NAME/*"
      },
      {
        Effect   = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Define the IAM role that the Lambda function will assume
resource "aws_iam_role" "lambda_exec_role" {
  name = "LambdaALBLogAnalyzerRole"

  # Trust policy allowing Lambda to assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action    = "sts:AssumeRole",
        Effect    = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Attach the policy to the role
resource "aws_iam_role_policy_attachment" "lambda_policy_attach" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}


# --- 2. Package and Deploy the Lambda Function ---

# Package the Python script into a ZIP file
data "archive_file" "zip_python_code" {
  type        = "zip"
  source_file = "analyzer.py"
  output_path = "analyzer.zip"
}

# Create the Lambda function resource
resource "aws_lambda_function" "alb_log_analyzer" {
  function_name = "ALB_Log_Analyzer"
  handler       = "analyzer.lambda_handler"
  runtime       = "python3.9"
  role          = aws_iam_role.lambda_exec_role.arn
  timeout       = 120 # Timeout in seconds

  filename         = data.archive_file.zip_python_code.output_path
  source_code_hash = data.archive_file.zip_python_code.output_base64sha256

  environment {
    variables = {
      # Set the destination bucket as an environment variable
      DESTINATION_BUCKET = "DESTINATION-BUCKET-NAME"
    }
  }

  # Add a dependency to ensure the role is created before the function
  depends_on = [
    aws_iam_role_policy_attachment.lambda_policy_attach
  ]
}