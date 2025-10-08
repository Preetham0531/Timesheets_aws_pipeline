#!/usr/bin/env python3
import os
import sys
import json
import zipfile
from io import BytesIO
from typing import Dict, List

import boto3
from botocore.exceptions import ClientError


def zip_directory_to_bytes(dir_path: str) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(dir_path):
            for fname in files:
                file_path = os.path.join(root, fname)
                arcname = os.path.relpath(file_path, dir_path)
                zf.write(file_path, arcname)
    return buffer.getvalue()


def load_lambda_map(path: str) -> Dict[str, str]:
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("lambda_map.json must be a JSON object of {module: functionArn}")
    return {k: v for k, v in data.items() if isinstance(k, str)}


def update_function(lambda_client, module: str, function_identifier: str, code_bytes: bytes) -> None:
    resp = lambda_client.update_function_code(
        FunctionName=function_identifier,
        ZipFile=code_bytes,
        Publish=False,
    )
    last_modified = resp.get('LastModified', 'unknown')
    print(f"Updated {function_identifier} from module {module}. LastModified={last_modified}")


def main() -> None:
    changed_modules = os.getenv('CHANGED_MODULES', '').strip()
    if not changed_modules:
        print('No changed modules provided; nothing to do.')
        return

    modules: List[str] = [m for m in changed_modules.split(' ') if m]
    lambda_map_path = os.getenv('LAMBDA_MAP', 'lambda_map.json')
    region = os.getenv('AWS_REGION', 'us-east-1')

    try:
        mapping = load_lambda_map(lambda_map_path)
    except FileNotFoundError:
        print(f"Mapping file {lambda_map_path} not found. Create it with {{ 'module': 'functionArn' }} entries.")
        sys.exit(1)

    session = boto3.Session(region_name=region)
    lambda_client = session.client('lambda')

    for module in modules:
        fn_identifier = mapping.get(module)
        if not fn_identifier:
            print(f"Skipping {module}: no ARN/FunctionName mapping found in {lambda_map_path}")
            continue
        if not os.path.isdir(module):
            print(f"Skipping {module}: directory not found")
            continue
        code_bytes = zip_directory_to_bytes(module)
        try:
            update_function(lambda_client, module, fn_identifier, code_bytes)
        except ClientError as e:
            print(f"Failed updating {fn_identifier} for module {module}: {e}")
            continue

    print('Done.')


if __name__ == '__main__':
    main()


