# Deployment Configuration

## Overview
This repository is configured for automated deployment of AWS Lambda functions using GitHub Actions and AWS SAM.

## Files Changed

### 1. `template.yaml`
- **Purpose**: SAM template defining all Lambda functions and API Gateway
- **Key Features**:
  - Creates a unified API Gateway for all endpoints
  - Defines 13 Lambda functions (one per module)
  - Includes CORS configuration
  - Outputs API Gateway URL and ID for reference

### 2. `.github/workflows/deploy.yml`
- **Purpose**: GitHub Actions workflow for automated deployment
- **Trigger**: Pushes to `main` branch affecting module folders
- **Process**:
  1. Detects which modules changed
  2. If any changes detected, deploys entire stack
  3. Uses AWS IAM role for authentication
  4. Builds and deploys using SAM
  5. Outputs the API Gateway URL

### 3. `requirements.txt`
- **Purpose**: Python dependencies for Lambda functions
- **Dependencies**: boto3, botocore

## Deployment Strategy

### Single Stack Approach
- All Lambda functions are deployed as one CloudFormation stack
- Stack name: `timesheets-api-stack`
- When any module changes, the entire stack is updated
- This ensures consistency and avoids API Gateway conflicts

### API Gateway Configuration
- SAM automatically creates an API Gateway
- Each function gets its own path (e.g., `/approvals`, `/contacts`)
- CORS is enabled for all endpoints
- API supports ANY method for all paths

## Module Structure
Each module (folder) contains:
- `lambda_function.py` with `lambda_handler` function
- Supporting files (handlers, models, services, utils)
- All modules follow the same structure pattern

## Environment Variables
The workflow uses:
- `arn:aws:iam::026090520154:role/aws_github` for AWS authentication
- `us-east-1` as the deployment region

## API Endpoints
After deployment, endpoints will be available at:
- `https://{api-id}.execute-api.us-east-1.amazonaws.com/Prod/approvals`
- `https://{api-id}.execute-api.us-east-1.amazonaws.com/Prod/client_table`
- `https://{api-id}.execute-api.us-east-1.amazonaws.com/Prod/contacts`
- ... (one for each module)

## Monitoring
- CloudWatch logs are automatically created for each Lambda function
- Function names follow pattern: `{module}-handler`
- Stack outputs provide API Gateway URL and ID for reference

## Security
- Functions use `AWSLambdaBasicExecutionRole` policy
- GitHub Actions uses OIDC with IAM role (no long-term credentials)
- CORS is configured for web application access

## Next Steps
1. Push changes to trigger first deployment
2. Note the API Gateway URL from the workflow output
3. Update any client applications with the new API endpoints
4. Monitor CloudWatch logs for any issues

## Troubleshooting
- Check GitHub Actions logs for deployment issues
- Use AWS CloudFormation console to monitor stack status
- CloudWatch logs contain Lambda execution details
- SAM CLI can be used locally for testing: `sam local start-api`