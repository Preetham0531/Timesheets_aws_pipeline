# -------------------- DYNAMODB TABLES --------------------
import os
import boto3

# Initialize DynamoDB resource
dynamodb = boto3.resource("dynamodb")

# Table configurations
PROJECTS_TABLE = dynamodb.Table(os.environ["PROJECTS_TABLE"])
CLIENTS_TABLE = dynamodb.Table(os.environ["CLIENTS_TABLE"])
CONTACTS_TABLE = dynamodb.Table(os.environ["CONTACTS_TABLE"])
USERS_TABLE = dynamodb.Table(os.environ["USERS_TABLE"])
ROLE_PRIVILEGES_TABLE = dynamodb.Table(os.environ["ROLE_PRIVILEGES_TABLE"])
SEQUENCES_TABLE = dynamodb.Table(os.environ["SEQUENCES_TABLE"])
ENTRIES_TABLE = dynamodb.Table(os.environ["ENTRIES_TABLE"])
ASSIGNMENTS_TABLE = dynamodb.Table(os.environ["ASSIGNMENTS_TABLE"])
APPROVALS_TABLE = dynamodb.Table(os.environ["APPROVALS_TABLE"])
TASKS_TABLE = dynamodb.Table(os.environ["TASKS_TABLE"])