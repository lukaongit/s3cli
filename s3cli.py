#!/usr/bin/env python3
import os
import sys
import json
import argparse
import datetime
import hmac
import hashlib
import requests
import urllib.parse
import re
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
import base64
import concurrent.futures

PROFILES_DIR = "profiles"

def load_profile(profile_name="default"):
    """Load S3 connection details from a profile."""
    profile_path = os.path.join(PROFILES_DIR, f"{profile_name}.json")
    try:
        with open(profile_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Profile {profile_name} not found at {profile_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Invalid JSON in profile {profile_name}")
        sys.exit(1)

def sign_request_v4(method, url, region, service, headers, data, access_key, secret_key):
    """Generate AWS Signature Version 4."""
    # Step 1: Create a canonical request
    parsed_url = urlparse(url)
    
    # Handle path correctly
    path = parsed_url.path
    if not path:
        path = '/'
    
    # Handle query parameters
    query_params = {}
    if parsed_url.query:
        for param in parsed_url.query.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                query_params[key] = value
            else:
                query_params[param] = ''
    
    canonical_query_string = '&'.join([
        f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(query_params[k], safe='')}"
        for k in sorted(query_params.keys())
    ])
    
    # Create canonical headers
    canonical_headers = ''
    signed_headers = ''
    
    # Make sure all header keys are lowercase
    normalized_headers = {k.lower(): v for k, v in headers.items()}
    headers = normalized_headers
    
    # Sort headers by key
    for key in sorted(headers.keys()):
        canonical_headers += f"{key}:{headers[key]}\n"
    signed_headers = ';'.join(sorted(headers.keys()))
    
    # Create payload hash
    if data is None:
        payload_hash = hashlib.sha256(b'').hexdigest()
    elif isinstance(data, bytes):
        payload_hash = hashlib.sha256(data).hexdigest()
    else:
        payload_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    # Construct the canonical request
    canonical_request = (
        f"{method}\n"
        f"{path}\n"
        f"{canonical_query_string}\n"
        f"{canonical_headers}\n"
        f"{signed_headers}\n"
        f"{payload_hash}"
    )
    
    # Step 2: Create a string to sign
    algorithm = 'AWS4-HMAC-SHA256'
    amz_date = headers['x-amz-date']
    credential_scope = f"{amz_date[:8]}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"{algorithm}\n"
        f"{amz_date}\n"
        f"{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )
    
    # Step 3: Calculate the signature
    k_date = hmac.new(
        f"AWS4{secret_key}".encode('utf-8'),
        amz_date[:8].encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    k_region = hmac.new(k_date, region.encode('utf-8'), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service.encode('utf-8'), hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b'aws4_request', hashlib.sha256).digest()
    
    signature = hmac.new(
        k_signing,
        string_to_sign.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    # Step 4: Add the signature to the headers
    auth_header = (
        f"{algorithm} "
        f"Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )
    
    return auth_header

def make_s3_request(method, bucket, key, profile, params=None, data=None, headers=None):
    """Make a signed request to S3."""
    endpoint_url = profile.get('endpoint_url', f"https://s3.{profile.get('region', 'us-east-1')}.amazonaws.com")
    region = profile.get('region', 'us-east-1')
    
    if headers is None:
        headers = {}
    
    # Construct the URL
    if bucket:
        if endpoint_url.endswith('/'):
            endpoint_url = endpoint_url[:-1]
        url = f"{endpoint_url}/{bucket}"
        if key:
            # URL encode the key
            encoded_key = '/'.join([urllib.parse.quote(part, safe='') for part in key.split('/')])
            url = f"{url}/{encoded_key}"
    else:
        url = endpoint_url
    
    # Add query parameters to URL
    if params:
        query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        url = f"{url}?{query_string}"
    
    # Add standard headers
    # Use timezone-aware approach instead of utcnow()
    try:
        # For Python 3.11+ with UTC attribute
        amz_date = datetime.datetime.now(datetime.UTC).strftime('%Y%m%dT%H%M%SZ')
    except AttributeError:
        # For Python versions without UTC attribute
        amz_date = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    
    headers['x-amz-date'] = amz_date
    headers['host'] = urlparse(url).netloc    
    # Add content hash
    if data is None:
        payload_hash = hashlib.sha256(b'').hexdigest()
    elif isinstance(data, bytes):
        payload_hash = hashlib.sha256(data).hexdigest()
    else:
        payload_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    headers['x-amz-content-sha256'] = payload_hash
    
    # Generate auth header
    auth_header = sign_request_v4(
        method,
        url,
        region,
        's3',
        headers,
        data,
        profile['aws_access_key_id'],
        profile['aws_secret_access_key']
    )
    
    headers['Authorization'] = auth_header
    
    # Make the request
    response = requests.request(
        method=method,
        url=url,
        data=data,
        headers=headers,
        verify=True
    )
    
    return response

def list_buckets(args):
    """List all S3 buckets."""
    profile = load_profile(args.profile)
    response = make_s3_request('GET', None, None, profile)
    
    if response.status_code == 200:
        root = ET.fromstring(response.content)
        buckets = []
        for bucket in root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}Bucket'):
            name = bucket.find('{http://s3.amazonaws.com/doc/2006-03-01/}Name').text
            buckets.append(name)
        
        if buckets:
            print("Available buckets:")
            for bucket in buckets:
                print(f"  {bucket}")
        else:
            print("No buckets found.")
    else:
        print(f"Error listing buckets: {response.status_code} - {response.text}")

def list_objects(args):
    """List objects in a bucket or folder."""
    profile = load_profile(args.profile)
    
    prefix = args.prefix or ''
    if prefix and not prefix.endswith('/'):
        prefix += '/'
    
    params = {
        'list-type': '2',
        'delimiter': '/'
    }
    
    if prefix:
        params['prefix'] = prefix
    
    response = make_s3_request('GET', args.bucket, None, profile, params=params)
    
    if response.status_code == 200:
        root = ET.fromstring(response.content)
        print(f"Contents of s3://{args.bucket}/{prefix}:")
        
        # List "folders" (CommonPrefixes)
        for common_prefix in root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}CommonPrefixes'):
            prefix_value = common_prefix.find('{http://s3.amazonaws.com/doc/2006-03-01/}Prefix').text
            print(f"  DIR  {prefix_value}")
        
        # List files
        for content in root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}Contents'):
            key = content.find('{http://s3.amazonaws.com/doc/2006-03-01/}Key').text
            size = content.find('{http://s3.amazonaws.com/doc/2006-03-01/}Size').text
            last_modified = content.find('{http://s3.amazonaws.com/doc/2006-03-01/}LastModified').text
            print(f"  FILE {key} ({size} bytes, last modified: {last_modified})")
    else:
        print(f"Error listing objects: {response.status_code} - {response.text}")
        print(f"Request URL: {response.request.url}")
        print(f"Request Headers: {response.request.headers}")

def upload_file(args):
    """Upload a file to S3, automatically using multipart for large files."""
    profile = load_profile(args.profile)
    file_path = args.local_path
    bucket = args.bucket
    key = args.s3_key
    
    # Check if file exists
    if not os.path.isfile(file_path):
        print(f"Error: Local file {file_path} not found")
        return
    
    # Get file size
    file_size = os.path.getsize(file_path)
    chunk_size = args.chunk_size * 1024 * 1024 if hasattr(args, 'chunk_size') else 5 * 1024 * 1024
    
    # Decide whether to use multipart upload
    use_multipart = file_size > chunk_size
    
    if hasattr(args, 'force_multipart') and args.force_multipart:
        use_multipart = True
    
    if hasattr(args, 'force_single') and args.force_single:
        use_multipart = False
    
    # Use appropriate upload method
    if use_multipart:
        print(f"File size ({file_size} bytes) exceeds threshold. Using multipart upload.")
        upload_file_multipart(profile, file_path, bucket, key, chunk_size)
    else:
        print(f"Using single-part upload for {file_path} ({file_size} bytes)")
        upload_file_single(profile, file_path, bucket, key)

def upload_file_single(profile, file_path, bucket, key):
    """Upload a file to S3 using single-part upload."""
    # Read file content
    try:
        with open(file_path, 'rb') as f:
            file_content = f.read()
    except FileNotFoundError:
        print(f"Local file {file_path} not found")
        return
    
    # Determine content type (simple version)
    content_type = 'application/octet-stream'
    if file_path.lower().endswith('.jpg') or file_path.lower().endswith('.jpeg'):
        content_type = 'image/jpeg'
    elif file_path.lower().endswith('.png'):
        content_type = 'image/png'
    elif file_path.lower().endswith('.txt'):
        content_type = 'text/plain'
    elif file_path.lower().endswith('.html'):
        content_type = 'text/html'
    elif file_path.lower().endswith('.pdf'):
        content_type = 'application/pdf'
    
    headers = {
        'Content-Type': content_type,
        'Content-Length': str(len(file_content))
    }
    
    response = make_s3_request('PUT', bucket, key, profile, data=file_content, headers=headers)
    
    if response.status_code == 200:
        print(f"File {file_path} successfully uploaded to s3://{bucket}/{key}")
    else:
        print(f"Error uploading file: {response.status_code} - {response.text}")

def upload_file_multipart(profile, file_path, bucket, key, chunk_size):
    """Upload a file to S3 using multipart upload."""
    print(f"Starting multipart upload for {file_path}")
    
    # Initiate multipart upload
    headers = {}
    params = {'uploads': ''}
    
    response = make_s3_request('POST', bucket, key, profile, params=params, headers=headers)
    
    if response.status_code != 200:
        print(f"Error initiating multipart upload: {response.status_code} - {response.text}")
        return
    
    # Parse upload ID from response
    root = ET.fromstring(response.content)
    upload_id = root.find('.//{http://s3.amazonaws.com/doc/2006-03-01/}UploadId').text
    
    print(f"Multipart upload initiated with ID: {upload_id}")
    
    # Upload parts
    part_info = []
    part_number = 1
    file_size = os.path.getsize(file_path)
    bytes_uploaded = 0
    
    with open(file_path, 'rb') as file:
        while True:
            data = file.read(chunk_size)
            if not data:
                break
            
            # Upload this part
            params = {
                'partNumber': str(part_number),
                'uploadId': upload_id
            }
            
            headers = {
                'Content-Length': str(len(data))
            }
            
            bytes_uploaded += len(data)
            progress = (bytes_uploaded / file_size) * 100
            print(f"Uploading part {part_number} ({len(data)} bytes, {progress:.2f}% complete)...")
            
            response = make_s3_request('PUT', bucket, key, profile, 
                                       params=params, data=data, headers=headers)
            
            if response.status_code != 200:
                print(f"Error uploading part {part_number}: {response.status_code} - {response.text}")
                # Abort multipart upload
                abort_params = {'uploadId': upload_id}
                make_s3_request('DELETE', bucket, key, profile, params=abort_params)
                return
            
            etag = response.headers['ETag']
            part_info.append({'PartNumber': part_number, 'ETag': etag})
            part_number += 1
    
    # Complete multipart upload
    completion_xml = '<CompleteMultipartUpload>'
    for part in part_info:
        completion_xml += f'<Part><PartNumber>{part["PartNumber"]}</PartNumber><ETag>{part["ETag"]}</ETag></Part>'
    completion_xml += '</CompleteMultipartUpload>'
    
    params = {'uploadId': upload_id}
    headers = {'Content-Type': 'application/xml'}
    
    print("Completing multipart upload...")
    response = make_s3_request('POST', bucket, key, profile, 
                              params=params, data=completion_xml, headers=headers)
    
    if response.status_code == 200:
        print(f"File {file_path} successfully uploaded to s3://{bucket}/{key}")
    else:
        print(f"Error completing multipart upload: {response.status_code} - {response.text}")

def download_file(args):
    """Download a file from S3, automatically using chunked download for large files."""
    profile = load_profile(args.profile)
    bucket = args.bucket
    key = args.s3_key
    local_path = args.local_path
    
    # First, get the file size
    head_response = make_s3_request('HEAD', bucket, key, profile)
    
    if head_response.status_code != 200:
        print(f"Error checking file: {head_response.status_code} - {head_response.text}")
        return
    
    file_size = int(head_response.headers.get('Content-Length', 0))
    chunk_size = args.chunk_size * 1024 * 1024 if hasattr(args, 'chunk_size') else 5 * 1024 * 1024
    
    # Decide whether to use chunked download
    use_chunked = file_size > chunk_size
    
    if hasattr(args, 'force_chunked') and args.force_chunked:
        use_chunked = True
    
    if hasattr(args, 'force_single') and args.force_single:
        use_chunked = False
    
    # Use appropriate download method
    if use_chunked:
        print(f"File size ({file_size} bytes) exceeds threshold. Using chunked download.")
        download_file_chunked(profile, bucket, key, local_path, file_size, chunk_size)
    else:
        print(f"Using single-part download for s3://{bucket}/{key} ({file_size} bytes)")
        download_file_single(profile, bucket, key, local_path)

def download_file_single(profile, bucket, key, local_path):
    """Download a file from S3 using single request."""
    response = make_s3_request('GET', bucket, key, profile)
    
    if response.status_code == 200:
        # Make sure the directory exists
        os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
        
        with open(local_path, 'wb') as f:
            f.write(response.content)
        print(f"File s3://{bucket}/{key} successfully downloaded to {local_path}")
    else:
        print(f"Error downloading file: {response.status_code} - {response.text}")

def download_file_chunked(profile, bucket, key, local_path, file_size, chunk_size):
    """Download a file from S3 using range requests."""
    print(f"Starting chunked download for s3://{bucket}/{key} ({file_size} bytes)")
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
    
    # Download file in chunks
    with open(local_path, 'wb') as output_file:
        start_byte = 0
        bytes_downloaded = 0
        
        while start_byte < file_size:
            end_byte = min(start_byte + chunk_size - 1, file_size - 1)
            
            # Calculate progress percentage
            bytes_downloaded = end_byte + 1
            progress = (bytes_downloaded / file_size) * 100
            print(f"Downloading bytes {start_byte}-{end_byte}/{file_size} ({progress:.2f}%)...")
            
            # Add range header
            headers = {
                'Range': f'bytes={start_byte}-{end_byte}'
            }
            
            response = make_s3_request('GET', bucket, key, profile, headers=headers)
            
            if response.status_code not in (200, 206):
                print(f"Error downloading chunk: {response.status_code} - {response.text}")
                return
            
            # Write chunk to file
            output_file.write(response.content)
            
            # Move to next chunk
            start_byte = end_byte + 1
    
    print(f"File s3://{bucket}/{key} successfully downloaded to {local_path}")

def delete_file(args):
    """Delete a file from S3."""
    profile = load_profile(args.profile)
    
    response = make_s3_request('DELETE', args.bucket, args.s3_key, profile)
    
    if response.status_code in (200, 204):
        print(f"File s3://{args.bucket}/{args.s3_key} successfully deleted")
    else:
        print(f"Error deleting file: {response.status_code} - {response.text}")

def create_folder(args):
    """Create a folder in S3 (actually creates a zero-byte object with a trailing slash)."""
    profile = load_profile(args.profile)
    
    # Ensure the folder name ends with a slash
    folder_key = args.folder
    if not folder_key.endswith('/'):
        folder_key += '/'
    
    headers = {
        'Content-Length': '0'
    }
    
    response = make_s3_request('PUT', args.bucket, folder_key, profile, headers=headers)
    
    if response.status_code in (200, 204):
        print(f"Folder s3://{args.bucket}/{folder_key} successfully created")
    else:
        print(f"Error creating folder: {response.status_code} - {response.text}")

def delete_folder(args):
    """Delete a folder and all its contents from S3."""
    profile = load_profile(args.profile)
    
    # Ensure the folder name ends with a slash
    folder_key = args.folder
    if not folder_key.endswith('/'):
        folder_key += '/'
    
    # First, list all objects with the folder prefix
    params = {
        'prefix': folder_key
    }
    
    response = make_s3_request('GET', args.bucket, None, profile, params=params)
    
    if response.status_code != 200:
        print(f"Error listing folder contents: {response.status_code} - {response.text}")
        return
    
    # Parse XML response to get all object keys
    root = ET.fromstring(response.content)
    keys = []
    for content in root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}Contents'):
        key = content.find('{http://s3.amazonaws.com/doc/2006-03-01/}Key').text
        keys.append(key)
    
    if not keys:
        print(f"Folder s3://{args.bucket}/{folder_key} is empty or does not exist")
        return
    
    # Delete each object
    for key in keys:
        delete_response = make_s3_request('DELETE', args.bucket, key, profile)
        if delete_response.status_code in (200, 204):
            print(f"Deleted s3://{args.bucket}/{key}")
        else:
            print(f"Error deleting {key}: {delete_response.status_code} - {delete_response.text}")
    
    print(f"Folder s3://{args.bucket}/{folder_key} and its contents successfully deleted")

def copy_file(args):
    """Copy a file within S3."""
    profile = load_profile(args.profile)
    
    # Source bucket/key may be different from destination
    source_bucket = args.source_bucket if args.source_bucket else args.bucket
    source_key = args.source_key
    
    headers = {
        'x-amz-copy-source': f"/{source_bucket}/{source_key}"
    }
    
    response = make_s3_request('PUT', args.bucket, args.dest_key, profile, headers=headers)
    
    if response.status_code == 200:
        print(f"File s3://{source_bucket}/{source_key} successfully copied to s3://{args.bucket}/{args.dest_key}")
    else:
        print(f"Error copying file: {response.status_code} - {response.text}")

def move_file(args):
    """Move a file within S3 (copy and then delete the original)."""
    profile = load_profile(args.profile)
    
    # Source bucket/key may be different from destination
    source_bucket = args.source_bucket if args.source_bucket else args.bucket
    source_key = args.source_key
    
    # First, copy the file
    headers = {
        'x-amz-copy-source': f"/{source_bucket}/{source_key}"
    }
    
    copy_response = make_s3_request('PUT', args.bucket, args.dest_key, profile, headers=headers)
    
    if copy_response.status_code != 200:
        print(f"Error copying file: {copy_response.status_code} - {copy_response.text}")
        return
    
    # Then, delete the original
    delete_response = make_s3_request('DELETE', source_bucket, source_key, profile)
    
    if delete_response.status_code in (200, 204):
        print(f"File s3://{source_bucket}/{source_key} successfully moved to s3://{args.bucket}/{args.dest_key}")
    else:
        print(f"File was copied but error deleting original: {delete_response.status_code} - {delete_response.text}")
        print(f"Copy exists at s3://{args.bucket}/{args.dest_key}")

def search_files(args):
    """Search for files in a bucket matching a pattern."""
    profile = load_profile(args.profile)
    
    # Initialize parameters
    params = {}
    if args.prefix:
        params['prefix'] = args.prefix
    
    # Make request to list objects
    response = make_s3_request('GET', args.bucket, None, profile, params=params)
    
    if response.status_code != 200:
        print(f"Error searching files: {response.status_code} - {response.text}")
        return
    
    # Parse XML response
    root = ET.fromstring(response.content)
    
    # Set up search pattern
    if args.regex:
        pattern = re.compile(args.pattern)
        match_func = lambda key: bool(pattern.search(key))
    else:
        match_func = lambda key: args.pattern.lower() in key.lower()
    
    # Find matching files
    matches = []
    for content in root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}Contents'):
        key = content.find('{http://s3.amazonaws.com/doc/2006-03-01/}Key').text
        
        if match_func(key):
            size = content.find('{http://s3.amazonaws.com/doc/2006-03-01/}Size').text
            last_modified = content.find('{http://s3.amazonaws.com/doc/2006-03-01/}LastModified').text
            matches.append((key, size, last_modified))
    
    # Display results
    if matches:
        print(f"Found {len(matches)} matching files in s3://{args.bucket}/:")
        for key, size, last_modified in matches:
            print(f"  {key} ({size} bytes, last modified: {last_modified})")
    else:
        print(f"No files matching '{args.pattern}' found in s3://{args.bucket}/")

def upload_large_file(args):
    """Upload a large file to S3 using multipart upload."""
    profile = load_profile(args.profile)
    file_path = args.local_path
    bucket = args.bucket
    key = args.s3_key
    
    # Check file size
    file_size = os.path.getsize(file_path)
    chunk_size = args.chunk_size * 1024 * 1024  # Convert MB to bytes
    
    if file_size <= chunk_size and not args.force_multipart:
        # Use regular upload for small files
        print(f"File size ({file_size} bytes) is small enough for regular upload")
        upload_file(args)
        return
    
    print(f"Starting multipart upload for {file_path} ({file_size} bytes)")
    
    # Initiate multipart upload
    headers = {}
    params = {'uploads': ''}
    
    response = make_s3_request('POST', bucket, key, profile, params=params, headers=headers)
    
    if response.status_code != 200:
        print(f"Error initiating multipart upload: {response.status_code} - {response.text}")
        return
    
    # Parse upload ID from response
    root = ET.fromstring(response.content)
    upload_id = root.find('.//{http://s3.amazonaws.com/doc/2006-03-01/}UploadId').text
    
    print(f"Multipart upload initiated with ID: {upload_id}")
    
    # Upload parts
    part_info = []
    part_number = 1
    
    with open(file_path, 'rb') as file:
        while True:
            data = file.read(chunk_size)
            if not data:
                break
            
            # Upload this part
            params = {
                'partNumber': str(part_number),
                'uploadId': upload_id
            }
            
            headers = {
                'Content-Length': str(len(data))
            }
            
            print(f"Uploading part {part_number} ({len(data)} bytes)...")
            response = make_s3_request('PUT', bucket, key, profile, 
                                       params=params, data=data, headers=headers)
            
            if response.status_code != 200:
                print(f"Error uploading part {part_number}: {response.status_code} - {response.text}")
                # Abort multipart upload
                abort_params = {'uploadId': upload_id}
                make_s3_request('DELETE', bucket, key, profile, params=abort_params)
                return
            
            etag = response.headers['ETag']
            part_info.append({'PartNumber': part_number, 'ETag': etag})
            part_number += 1
    
    # Complete multipart upload
    completion_xml = '<CompleteMultipartUpload>'
    for part in part_info:
        completion_xml += f'<Part><PartNumber>{part["PartNumber"]}</PartNumber><ETag>{part["ETag"]}</ETag></Part>'
    completion_xml += '</CompleteMultipartUpload>'
    
    params = {'uploadId': upload_id}
    headers = {'Content-Type': 'application/xml'}
    
    print("Completing multipart upload...")
    response = make_s3_request('POST', bucket, key, profile, 
                              params=params, data=completion_xml, headers=headers)
    
    if response.status_code == 200:
        print(f"File {file_path} successfully uploaded to s3://{bucket}/{key}")
    else:
        print(f"Error completing multipart upload: {response.status_code} - {response.text}")

def download_large_file(args):
    """Download a large file from S3 using range requests."""
    profile = load_profile(args.profile)
    bucket = args.bucket
    key = args.s3_key
    local_path = args.local_path
    chunk_size = args.chunk_size * 1024 * 1024  # Convert MB to bytes
    
    # First, get the file size
    head_response = make_s3_request('HEAD', bucket, key, profile)
    
    if head_response.status_code != 200:
        print(f"Error checking file: {head_response.status_code} - {head_response.text}")
        return
    
    file_size = int(head_response.headers.get('Content-Length', 0))
    
    if file_size <= chunk_size and not args.force_chunked:
        # Use regular download for small files
        print(f"File size ({file_size} bytes) is small enough for regular download")
        download_file(args)
        return
    
    print(f"Starting chunked download for s3://{bucket}/{key} ({file_size} bytes)")
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
    
    # Download file in chunks
    with open(local_path, 'wb') as output_file:
        start_byte = 0
        
        while start_byte < file_size:
            end_byte = min(start_byte + chunk_size - 1, file_size - 1)
            
            # Calculate progress percentage
            progress = (start_byte / file_size) * 100
            print(f"Downloading bytes {start_byte}-{end_byte}/{file_size} ({progress:.2f}%)...")
            
            # Add range header
            headers = {
                'Range': f'bytes={start_byte}-{end_byte}'
            }
            
            response = make_s3_request('GET', bucket, key, profile, headers=headers)
            
            if response.status_code not in (200, 206):
                print(f"Error downloading chunk: {response.status_code} - {response.text}")
                return
            
            # Write chunk to file
            output_file.write(response.content)
            
            # Move to next chunk
            start_byte = end_byte + 1
    
    print(f"File s3://{bucket}/{key} successfully downloaded to {local_path}")

# New Features - Versioning-Related Operations

def list_object_versions(args):
    """List all versions of objects in a bucket or with a specific prefix."""
    profile = load_profile(args.profile)
    
    params = {
        'versions': ''
    }
    
    if args.prefix:
        params['prefix'] = args.prefix
    
    response = make_s3_request('GET', args.bucket, None, profile, params=params)
    
    if response.status_code == 200:
        root = ET.fromstring(response.content)
        print(f"Versions in s3://{args.bucket}/{args.prefix or ''}:")
        
        # List versions
        for version in root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}Version'):
            key = version.find('{http://s3.amazonaws.com/doc/2006-03-01/}Key').text
            version_id = version.find('{http://s3.amazonaws.com/doc/2006-03-01/}VersionId').text
            is_latest = version.find('{http://s3.amazonaws.com/doc/2006-03-01/}IsLatest').text
            last_modified = version.find('{http://s3.amazonaws.com/doc/2006-03-01/}LastModified').text
            size = version.find('{http://s3.amazonaws.com/doc/2006-03-01/}Size').text
            
            latest_marker = " (Latest)" if is_latest.lower() == 'true' else ""
            print(f"  {key} - Version: {version_id}{latest_marker}, Size: {size} bytes, Modified: {last_modified}")
        
        # List delete markers
        for marker in root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}DeleteMarker'):
            key = marker.find('{http://s3.amazonaws.com/doc/2006-03-01/}Key').text
            version_id = marker.find('{http://s3.amazonaws.com/doc/2006-03-01/}VersionId').text
            is_latest = marker.find('{http://s3.amazonaws.com/doc/2006-03-01/}IsLatest').text
            last_modified = marker.find('{http://s3.amazonaws.com/doc/2006-03-01/}LastModified').text
            
            latest_marker = " (Latest)" if is_latest.lower() == 'true' else ""
            print(f"  {key} - Delete Marker: {version_id}{latest_marker}, Modified: {last_modified}")
    else:
        print(f"Error listing versions: {response.status_code} - {response.text}")

def get_specific_version(args):
    """Download a specific version of an object."""
    profile = load_profile(args.profile)
    
    params = {
        'versionId': args.version_id
    }
    
    # Make request to get the specific version
    response = make_s3_request('GET', args.bucket, args.s3_key, profile, params=params)
    
    if response.status_code == 200:
        # Make sure the directory exists
        os.makedirs(os.path.dirname(os.path.abspath(args.local_path)), exist_ok=True)
        
        with open(args.local_path, 'wb') as f:
            f.write(response.content)
        print(f"Version {args.version_id} of s3://{args.bucket}/{args.s3_key} downloaded to {args.local_path}")
    else:
        print(f"Error downloading version: {response.status_code} - {response.text}")

def delete_specific_version(args):
    """Delete a specific version of an object."""
    profile = load_profile(args.profile)
    
    params = {
        'versionId': args.version_id
    }
    
    response = make_s3_request('DELETE', args.bucket, args.s3_key, profile, params=params)
    
    if response.status_code in (200, 204):
        print(f"Version {args.version_id} of s3://{args.bucket}/{args.s3_key} successfully deleted")
    else:
        print(f"Error deleting version: {response.status_code} - {response.text}")

# New Features - Parallel Transfer Capability

def upload_file_parallel(profile, file_path, bucket, key, chunk_size, max_workers=4):
    """Upload a file to S3 using parallel multipart upload."""
    print(f"Starting parallel multipart upload for {file_path}")
    
    # Initiate multipart upload
    headers = {}
    params = {'uploads': ''}
    
    response = make_s3_request('POST', bucket, key, profile, params=params, headers=headers)
    
    if response.status_code != 200:
        print(f"Error initiating multipart upload: {response.status_code} - {response.text}")
        return
    
    # Parse upload ID from response
    root = ET.fromstring(response.content)
    upload_id = root.find('.//{http://s3.amazonaws.com/doc/2006-03-01/}UploadId').text
    
    print(f"Parallel multipart upload initiated with ID: {upload_id}")
    
    # Calculate file size and prepare chunks
    file_size = os.path.getsize(file_path)
    chunk_count = (file_size + chunk_size - 1) // chunk_size  # ceiling division
    
    # Function to upload a single part
    def upload_part(part_number):
        start_pos = (part_number - 1) * chunk_size
        with open(file_path, 'rb') as f:
            f.seek(start_pos)
            data = f.read(chunk_size)
        
        # Upload this part
        params = {
            'partNumber': str(part_number),
            'uploadId': upload_id
        }
        
        headers = {
            'Content-Length': str(len(data))
        }
        
        print(f"Uploading part {part_number}/{chunk_count} ({len(data)} bytes)...")
        response = make_s3_request('PUT', bucket, key, profile, 
                                  params=params, data=data, headers=headers)
        
        if response.status_code != 200:
            print(f"Error uploading part {part_number}: {response.status_code} - {response.text}")
            return None
        
        etag = response.headers['ETag']
        return {'PartNumber': part_number, 'ETag': etag}
    
    # Upload parts in parallel
    part_info = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_part = {executor.submit(upload_part, part_num): part_num for part_num in range(1, chunk_count + 1)}
        for future in concurrent.futures.as_completed(future_to_part):
            part_result = future.result()
            if part_result is None:
                # Abort multipart upload
                abort_params = {'uploadId': upload_id}
                make_s3_request('DELETE', bucket, key, profile, params=abort_params)
                print("Upload aborted due to part upload failure")
                return
            part_info.append(part_result)
    
    # Sort parts by part number
    part_info.sort(key=lambda x: x['PartNumber'])
    
    # Complete multipart upload
    completion_xml = '<CompleteMultipartUpload>'
    for part in part_info:
        completion_xml += f'<Part><PartNumber>{part["PartNumber"]}</PartNumber><ETag>{part["ETag"]}</ETag></Part>'
    completion_xml += '</CompleteMultipartUpload>'
    
    params = {'uploadId': upload_id}
    headers = {'Content-Type': 'application/xml'}
    
    print("Completing multipart upload...")
    response = make_s3_request('POST', bucket, key, profile, 
                              params=params, data=completion_xml, headers=headers)
    
    if response.status_code == 200:
        print(f"File {file_path} successfully uploaded to s3://{bucket}/{key}")
    else:
        print(f"Error completing multipart upload: {response.status_code} - {response.text}")

def download_file_parallel(profile, bucket, key, local_path, file_size, chunk_size, max_workers=4):
    """Download a file from S3 using parallel range requests."""
    print(f"Starting parallel download for s3://{bucket}/{key} ({file_size} bytes)")
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
    
    # Create empty file of the right size
    with open(local_path, 'wb') as f:
        f.truncate(file_size)
    
    # Function to download a chunk
    def download_chunk(chunk_index):
        start_byte = chunk_index * chunk_size
        end_byte = min(start_byte + chunk_size - 1, file_size - 1)
        
        # Add range header
        headers = {
            'Range': f'bytes={start_byte}-{end_byte}'
        }
        
        response = make_s3_request('GET', bucket, key, profile, headers=headers)
        
        if response.status_code not in (200, 206):
            print(f"Error downloading chunk {chunk_index}: {response.status_code} - {response.text}")
            return None
        
        return (start_byte, response.content)
    
    # Calculate number of chunks
    chunk_count = (file_size + chunk_size - 1) // chunk_size
    
    # Download chunks in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(download_chunk, i): i for i in range(chunk_count)}
        
        for future in concurrent.futures.as_completed(futures):
            chunk_index = futures[future]
            result = future.result()
            
            if result is None:
                print("Download failed")
                return False
            
            start_byte, data = result
            print(f"Writing chunk {chunk_index}/{chunk_count-1} (bytes {start_byte}-{start_byte+len(data)-1})")
            
            with open(local_path, 'r+b') as f:
                f.seek(start_byte)
                f.write(data)
    
    print(f"File s3://{bucket}/{key} successfully downloaded to {local_path}")
    return True

def parallel_upload(args):
    """Upload a file to S3 using parallel multipart upload."""
    profile = load_profile(args.profile)
    file_path = args.local_path
    bucket = args.bucket
    key = args.s3_key
    chunk_size = args.chunk_size * 1024 * 1024  # Convert MB to bytes
    max_workers = args.workers
    
    # Check if file exists
    if not os.path.isfile(file_path):
        print(f"Error: Local file {file_path} not found")
        return
    
    upload_file_parallel(profile, file_path, bucket, key, chunk_size, max_workers)

def parallel_download(args):
    """Download a file from S3 using parallel range requests."""
    profile = load_profile(args.profile)
    bucket = args.bucket
    key = args.s3_key
    local_path = args.local_path
    chunk_size = args.chunk_size * 1024 * 1024  # Convert MB to bytes
    max_workers = args.workers
    
    # First, get the file size
    head_response = make_s3_request('HEAD', bucket, key, profile)
    
    if head_response.status_code != 200:
        print(f"Error checking file: {head_response.status_code} - {head_response.text}")
        return
    
    file_size = int(head_response.headers.get('Content-Length', 0))
    
    download_file_parallel(profile, bucket, key, local_path, file_size, chunk_size, max_workers)

# New Features - Server-Side Encryption

def upload_with_encryption(args):
    """Upload a file with server-side encryption."""
    profile = load_profile(args.profile)
    local_path = args.local_path
    bucket = args.bucket
    key = args.s3_key
    
    # Check if file exists
    if not os.path.isfile(local_path):
        print(f"Error: Local file {local_path} not found")
        return
    
    # Read file content
    try:
        with open(local_path, 'rb') as f:
            file_content = f.read()
    except FileNotFoundError:
        print(f"Local file {local_path} not found")
        return
    
    # Determine content type (simple version)
    content_type = 'application/octet-stream'
    if local_path.lower().endswith('.jpg') or local_path.lower().endswith('.jpeg'):
        content_type = 'image/jpeg'
    elif local_path.lower().endswith('.png'):
        content_type = 'image/png'
    elif local_path.lower().endswith('.txt'):
        content_type = 'text/plain'
    elif local_path.lower().endswith('.html'):
        content_type = 'text/html'
    elif local_path.lower().endswith('.pdf'):
        content_type = 'application/pdf'
    
    headers = {
        'Content-Type': content_type,
        'Content-Length': str(len(file_content))
    }
    
    # Add encryption headers based on the chosen method
    if args.encryption == 'aes256':
        headers['x-amz-server-side-encryption'] = 'AES256'
    elif args.encryption == 'aws-kms':
        headers['x-amz-server-side-encryption'] = 'aws:kms'
        if args.kms_key_id:
            headers['x-amz-server-side-encryption-aws-kms-key-id'] = args.kms_key_id
    elif args.encryption == 'customer-key':
        if not args.customer_key:
            print("Customer key is required for customer-key encryption")
            return
        
        # Generate the MD5 hash of the encryption key
        key_bytes = args.customer_key.encode('utf-8')
        key_md5 = base64.b64encode(hashlib.md5(key_bytes).digest()).decode('ascii')
        
        # Base64 encode the encryption key
        key_b64 = base64.b64encode(key_bytes).decode('ascii')
        
        headers['x-amz-server-side-encryption-customer-algorithm'] = 'AES256'
        headers['x-amz-server-side-encryption-customer-key'] = key_b64
        headers['x-amz-server-side-encryption-customer-key-MD5'] = key_md5
    
    # Make the upload request
    response = make_s3_request('PUT', bucket, key, profile, data=file_content, headers=headers)
    
    if response.status_code == 200:
        encryption_info = ""
        if 'x-amz-server-side-encryption' in response.headers:
            encryption_info = f" (encrypted with {response.headers['x-amz-server-side-encryption']})"
        
        print(f"File {local_path} successfully uploaded to s3://{bucket}/{key}{encryption_info}")
    else:
        print(f"Error uploading file: {response.status_code} - {response.text}")

def download_with_encryption(args):
    """Download an encrypted file from S3."""
    profile = load_profile(args.profile)
    bucket = args.bucket
    key = args.s3_key
    local_path = args.local_path
    
    # Set up headers based on encryption type
    headers = {}
    
    if args.encryption == 'customer-key':
        if not args.customer_key:
            print("Customer key is required for customer-key encrypted files")
            return
        
        # Generate the MD5 hash of the encryption key
        key_bytes = args.customer_key.encode('utf-8')
        key_md5 = base64.b64encode(hashlib.md5(key_bytes).digest()).decode('ascii')
        
        # Base64 encode the encryption key
        key_b64 = base64.b64encode(key_bytes).decode('ascii')
        
        headers['x-amz-server-side-encryption-customer-algorithm'] = 'AES256'
        headers['x-amz-server-side-encryption-customer-key'] = key_b64
        headers['x-amz-server-side-encryption-customer-key-MD5'] = key_md5
    
    # Make request to get the encrypted file
    response = make_s3_request('GET', bucket, key, profile, headers=headers)
    
    if response.status_code == 200:
        # Make sure the directory exists
        os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
        
        with open(local_path, 'wb') as f:
            f.write(response.content)
        
        encryption_info = ""
        if 'x-amz-server-side-encryption' in response.headers:
            encryption_info = f" (encrypted with {response.headers['x-amz-server-side-encryption']})"
        
        print(f"File s3://{bucket}/{key}{encryption_info} downloaded to {local_path}")
    else:
        print(f"Error downloading file: {response.status_code} - {response.text}")

# New Feature - Improved Search with Pagination

def search_files_paginated(args):
    """Search for files in a bucket matching a pattern with pagination support."""
    profile = load_profile(args.profile)
    
    # Set up search pattern
    if args.regex:
        pattern = re.compile(args.pattern)
        match_func = lambda key: bool(pattern.search(key))
    else:
        match_func = lambda key: args.pattern.lower() in key.lower()
    
    # Initialize parameters
    params = {
        'max-keys': str(args.page_size)
    }
    
    if args.prefix:
        params['prefix'] = args.prefix
    
    continuation_token = None
    matches = []
    total_scanned = 0
    
    print(f"Searching s3://{args.bucket}/{'prefix=' + args.prefix if args.prefix else ''} for '{args.pattern}'...")
    
    # Paginate through results
    while True:
        # Add continuation token if we have one
        if continuation_token:
            params['continuation-token'] = continuation_token
        
        # Make request to list objects
        response = make_s3_request('GET', args.bucket, None, profile, params=params)
        
        if response.status_code != 200:
            print(f"Error searching files: {response.status_code} - {response.text}")
            return
        
        # Parse XML response
        root = ET.fromstring(response.content)
        
        # Find matching files in this page of results
        for content in root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}Contents'):
            key = content.find('{http://s3.amazonaws.com/doc/2006-03-01/}Key').text
            total_scanned += 1
            
            if match_func(key):
                size = content.find('{http://s3.amazonaws.com/doc/2006-03-01/}Size').text
                last_modified = content.find('{http://s3.amazonaws.com/doc/2006-03-01/}LastModified').text
                matches.append((key, size, last_modified))
                
                # If we've found enough matches, stop searching
                if args.max_results and len(matches) >= args.max_results:
                    break
        
        # Check if we need to stop due to reaching max_results
        if args.max_results and len(matches) >= args.max_results:
            print(f"Reached maximum results limit ({args.max_results})")
            break
        
        # Check if there are more pages
        is_truncated_elem = root.find('.//{http://s3.amazonaws.com/doc/2006-03-01/}IsTruncated')
        is_truncated = is_truncated_elem is not None and is_truncated_elem.text.lower() == 'true'
        
        if not is_truncated:
            break
        
        # Get next continuation token
        continuation_token_elem = root.find('.//{http://s3.amazonaws.com/doc/2006-03-01/}NextContinuationToken')
        if continuation_token_elem is None:
            break
        
        continuation_token = continuation_token_elem.text
        print(f"Continuing search... (scanned {total_scanned} objects so far, found {len(matches)} matches)")
    
    # Display results
    if matches:
        print(f"\nFound {len(matches)} matching files in s3://{args.bucket}/ (scanned {total_scanned} objects):")
        for key, size, last_modified in matches:
            print(f"  {key} ({size} bytes, last modified: {last_modified})")
    else:
        print(f"\nNo files matching '{args.pattern}' found in s3://{args.bucket}/ (scanned {total_scanned} objects)")

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description='S3 CLI Storage Tool')
    parser.add_argument('--profile', default='default', help='Profile name to use for S3 credentials')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # List buckets
    list_buckets_parser = subparsers.add_parser('list-buckets', help='List all S3 buckets')
    list_buckets_parser.set_defaults(func=list_buckets)
    
    # List objects
    list_objects_parser = subparsers.add_parser('ls', help='List objects in a bucket or folder')
    list_objects_parser.add_argument('bucket', help='Bucket name')
    list_objects_parser.add_argument('prefix', nargs='?', help='Prefix (folder path)')
    list_objects_parser.set_defaults(func=list_objects)
    
    # Upload file - single command with options
    upload_parser = subparsers.add_parser('upload', help='Upload a file to S3')
    upload_parser.add_argument('local_path', help='Local file path')
    upload_parser.add_argument('bucket', help='Destination bucket name')
    upload_parser.add_argument('s3_key', help='Destination S3 key (path)')
    upload_parser.add_argument('--chunk-size', type=int, default=5, help='Chunk size in MB (default: 5)')
    upload_parser.add_argument('--force-multipart', action='store_true', help='Force multipart upload')
    upload_parser.add_argument('--force-single', action='store_true', help='Force single-part upload')
    upload_parser.set_defaults(func=upload_file)
    
    # Download file - single command with options
    download_parser = subparsers.add_parser('download', help='Download a file from S3')
    download_parser.add_argument('bucket', help='Source bucket name')
    download_parser.add_argument('s3_key', help='Source S3 key (path)')
    download_parser.add_argument('local_path', help='Local destination path')
    download_parser.add_argument('--chunk-size', type=int, default=5, help='Chunk size in MB (default: 5)')
    download_parser.add_argument('--force-chunked', action='store_true', help='Force chunked download')
    download_parser.add_argument('--force-single', action='store_true', help='Force single-part download')
    download_parser.set_defaults(func=download_file)
    
    # Delete file
    delete_parser = subparsers.add_parser('delete', help='Delete a file from S3')
    delete_parser.add_argument('bucket', help='Bucket name')
    delete_parser.add_argument('s3_key', help='S3 key (path) to delete')
    delete_parser.set_defaults(func=delete_file)
    
    # Create folder
    mkdir_parser = subparsers.add_parser('mkdir', help='Create a folder in S3')
    mkdir_parser.add_argument('bucket', help='Bucket name')
    mkdir_parser.add_argument('folder', help='Folder path to create')
    mkdir_parser.set_defaults(func=create_folder)
    
    # Delete folder
    rmdir_parser = subparsers.add_parser('rmdir', help='Delete a folder and its contents from S3')
    rmdir_parser.add_argument('bucket', help='Bucket name')
    rmdir_parser.add_argument('folder', help='Folder path to delete')
    rmdir_parser.set_defaults(func=delete_folder)
    
    # Copy file
    copy_parser = subparsers.add_parser('cp', help='Copy a file within S3')
    copy_parser.add_argument('source_bucket', help='Source bucket name')
    copy_parser.add_argument('source_key', help='Source S3 key (path)')
    copy_parser.add_argument('bucket', help='Destination bucket name')
    copy_parser.add_argument('dest_key', help='Destination S3 key (path)')
    copy_parser.set_defaults(func=copy_file)
    
    # Move file
    move_parser = subparsers.add_parser('mv', help='Move a file within S3')
    move_parser.add_argument('source_bucket', help='Source bucket name')
    move_parser.add_argument('source_key', help='Source S3 key (path)')
    move_parser.add_argument('bucket', help='Destination bucket name')
    move_parser.add_argument('dest_key', help='Destination S3 key (path)')
    move_parser.set_defaults(func=move_file)
    
    # Versioning commands
    versions_parser = subparsers.add_parser('list-versions', help='List all versions of objects in a bucket')
    versions_parser.add_argument('bucket', help='Bucket name')
    versions_parser.add_argument('prefix', nargs='?', help='Prefix (folder path)')
    versions_parser.set_defaults(func=list_object_versions)
    
    get_version_parser = subparsers.add_parser('get-version', help='Download a specific version of an object')
    get_version_parser.add_argument('bucket', help='Bucket name')
    get_version_parser.add_argument('s3_key', help='S3 key (path)')
    get_version_parser.add_argument('version_id', help='Version ID')
    get_version_parser.add_argument('local_path', help='Local destination path')
    get_version_parser.set_defaults(func=get_specific_version)
    
    delete_version_parser = subparsers.add_parser('delete-version', help='Delete a specific version of an object')
    delete_version_parser.add_argument('bucket', help='Bucket name')
    delete_version_parser.add_argument('s3_key', help='S3 key (path)')
    delete_version_parser.add_argument('version_id', help='Version ID')
    delete_version_parser.set_defaults(func=delete_specific_version)
    
    # Parallel transfer commands
    parallel_upload_parser = subparsers.add_parser('parallel-upload', help='Upload a file using parallel transfers')
    parallel_upload_parser.add_argument('local_path', help='Local file path')
    parallel_upload_parser.add_argument('bucket', help='Destination bucket name')
    parallel_upload_parser.add_argument('s3_key', help='Destination S3 key (path)')
    parallel_upload_parser.add_argument('--chunk-size', type=int, default=5, help='Chunk size in MB (default: 5)')
    parallel_upload_parser.add_argument('--workers', type=int, default=4, help='Number of parallel workers (default: 4)')
    parallel_upload_parser.set_defaults(func=parallel_upload)
    
    parallel_download_parser = subparsers.add_parser('parallel-download', help='Download a file using parallel transfers')
    parallel_download_parser.add_argument('bucket', help='Source bucket name')
    parallel_download_parser.add_argument('s3_key', help='Source S3 key (path)')
    parallel_download_parser.add_argument('local_path', help='Local destination path')
    parallel_download_parser.add_argument('--chunk-size', type=int, default=5, help='Chunk size in MB (default: 5)')
    parallel_download_parser.add_argument('--workers', type=int, default=4, help='Number of parallel workers (default: 4)')
    parallel_download_parser.set_defaults(func=parallel_download)
    
    # Encrypted upload/download
    encrypt_upload_parser = subparsers.add_parser('encrypt-upload', help='Upload a file with server-side encryption')
    encrypt_upload_parser.add_argument('local_path', help='Local file path')
    encrypt_upload_parser.add_argument('bucket', help='Destination bucket name')
    encrypt_upload_parser.add_argument('s3_key', help='Destination S3 key (path)')
    encrypt_upload_parser.add_argument('--encryption', choices=['aes256', 'aws-kms', 'customer-key'], required=True,
                                      help='Type of encryption to use')
    encrypt_upload_parser.add_argument('--kms-key-id', help='KMS Key ID (for aws-kms encryption)')
    encrypt_upload_parser.add_argument('--customer-key', help='Customer encryption key (for customer-key encryption)')
    encrypt_upload_parser.set_defaults(func=upload_with_encryption)
    
    encrypt_download_parser = subparsers.add_parser('encrypt-download', help='Download an encrypted file')
    encrypt_download_parser.add_argument('bucket', help='Source bucket name')
    encrypt_download_parser.add_argument('s3_key', help='Source S3 key (path)')
    encrypt_download_parser.add_argument('local_path', help='Local destination path')
    encrypt_download_parser.add_argument('--encryption', choices=['customer-key'], default='customer-key',
                                        help='Type of encryption used')
    encrypt_download_parser.add_argument('--customer-key', help='Customer encryption key (for customer-key encryption)')
    encrypt_download_parser.set_defaults(func=download_with_encryption)
    
    # Improved search
    search_parser = subparsers.add_parser('search', help='Search for files in a bucket')
    search_parser.add_argument('bucket', help='Bucket name')
    search_parser.add_argument('pattern', help='Search pattern to match against file names')
    search_parser.add_argument('--prefix', help='Optional prefix to narrow down the search')
    search_parser.add_argument('--regex', action='store_true', help='Treat pattern as regular expression')
    search_parser.add_argument('--page-size', type=int, default=1000, help='Number of objects to list per page (default: 1000)')
    search_parser.add_argument('--max-results', type=int, help='Maximum number of matches to return')
    search_parser.set_defaults(func=search_files_paginated)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Execute the appropriate function
    args.func(args)

if __name__ == '__main__':
    main()




