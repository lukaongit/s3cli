# S3 CLI Storage Tool

A comprehensive command-line interface for working with Amazon S3 or compatible object storage services.

## Overview

This tool provides a powerful command-line interface for interacting with S3-compatible storage services. It supports standard operations like uploading, downloading, and managing files, as well as advanced features including versioning, parallel transfers, server-side encryption, and enhanced search capabilities.

## Installation

### Prerequisites

- Python 3.6 or higher
- Required Python packages: `requests`

### Setup

1. Clone this repository or download the `s3cli.py` script
2. Make the script executable:
   ```
   chmod +x s3cli.py
   ```
3. Optionally, create a symbolic link to use the tool from anywhere:
   ```
   sudo ln -s /path/to/s3cli.py /usr/local/bin/s3tool
   ```

## Configuration

The tool uses profile files stored in a `profiles` directory to manage S3 connection details.

### Creating a Profile

1. Create a `profiles` directory in the same location as the script:
   ```
   mkdir profiles
   ```

2. Create a profile JSON file (e.g., `default.json`) with your S3 credentials:
   ```json
   {
     "aws_access_key_id": "YOUR_ACCESS_KEY",
     "aws_secret_access_key": "YOUR_SECRET_KEY",
     "region": "us-east-1",
     "endpoint_url": "https://s3.amazonaws.com"
   }
   ```

   For S3-compatible services, update the `endpoint_url` to your provider's endpoint.

### Using Profiles

Use the `--profile` option with any command to specify which profile to use:
```
./s3cli.py --profile minio ls my-bucket
```

## Basic Commands

### List Buckets
```
./s3cli.py list-buckets
```

### List Objects in a Bucket
```
./s3cli.py ls my-bucket [prefix]
```

### Upload a File
```
./s3cli.py upload local-file.txt my-bucket destination/path/file.txt
```

### Download a File
```
./s3cli.py download my-bucket remote-file.txt local-file.txt
```

### Delete a File
```
./s3cli.py delete my-bucket path/to/file.txt
```

### Create a Folder
```
./s3cli.py mkdir my-bucket new-folder
```

### Delete a Folder
```
./s3cli.py rmdir my-bucket folder-to-delete
```

### Copy a File
```
./s3cli.py cp source-bucket source-key destination-bucket destination-key
```

### Move a File
```
./s3cli.py mv source-bucket source-key destination-bucket destination-key
```

### Search for Files
```
./s3cli.py search my-bucket "search-term" --prefix documents/
```

## Advanced Features

### Versioning Support

#### List Object Versions
```
./s3cli.py list-versions my-bucket [prefix]
```

#### Download a Specific Version
```
./s3cli.py get-version my-bucket file.txt VERSION_ID local-file.txt
```

#### Delete a Specific Version
```
./s3cli.py delete-version my-bucket file.txt VERSION_ID
```

### Parallel Transfer

#### Upload with Parallel Workers
```
./s3cli.py parallel-upload large-file.zip my-bucket large-file.zip --chunk-size 10 --workers 8
```

#### Download with Parallel Workers
```
./s3cli.py parallel-download my-bucket large-file.zip local-file.zip --chunk-size 10 --workers 8
```

### Server-Side Encryption

#### Upload with Encryption
```
# Using S3-managed keys (AES256)
./s3cli.py encrypt-upload secret.pdf my-bucket secret.pdf --encryption aes256

# Using AWS KMS
./s3cli.py encrypt-upload secret.pdf my-bucket secret.pdf --encryption aws-kms --kms-key-id YOUR_KMS_KEY_ID

# Using customer-provided keys
./s3cli.py encrypt-upload secret.pdf my-bucket secret.pdf --encryption customer-key --customer-key YOUR_ENCRYPTION_KEY
```

#### Download Encrypted Files
```
# For files encrypted with customer-provided keys
./s3cli.py encrypt-download my-bucket secret.pdf local-secret.pdf --encryption customer-key --customer-key YOUR_ENCRYPTION_KEY
```

### Advanced Search

#### Search with Pagination and Filtering
```
# Search with regex and limit results
./s3cli.py search my-bucket ".*\.pdf$" --regex --max-results 100

# Search with prefix and custom page size
./s3cli.py search my-bucket "report" --prefix "finance/2023/" --page-size 500
```

## Upload/Download Options

Both upload and download commands support options for handling large files:

- `--chunk-size`: Size in MB for each chunk in multipart operations (default: 5)
- `--force-multipart`: Force using multipart upload even for small files
- `--force-single`: Force using single-part upload/download
- `--force-chunked`: Force using chunked download

## Examples

### Basic Usage
```
# Upload a file
./s3cli.py upload document.pdf my-bucket reports/2023/document.pdf

# Download a file
./s3cli.py download my-bucket reports/2023/document.pdf ./downloaded-document.pdf

# List files in a folder
./s3cli.py ls my-bucket reports/2023/
```

### Working with Large Files
```
# Upload a large file with custom chunk size
./s3cli.py upload large-dataset.zip my-bucket datasets/large-dataset.zip --chunk-size 50

# Download a large file with chunked download
./s3cli.py download my-bucket videos/presentation.mp4 ./presentation.mp4 --chunk-size 20
```

### Encrypted Storage
```
# Upload with encryption
./s3cli.py encrypt-upload confidential.docx my-bucket legal/confidential.docx --encryption aes256

# Download customer-key encrypted file
./s3cli.py encrypt-download my-bucket secure/file.txt ./local-file.txt --encryption customer-key --customer-key "my-secret-key"
```

### Searching and Managing Files
```
# Find all PDF files
./s3cli.py search my-bucket ".pdf" --prefix documents/

# Find files matching a regex pattern
./s3cli.py search my-bucket "report-[0-9]{4}" --regex

# Copy multiple versions of a file
./s3cli.py list-versions my-bucket report.docx  # List all versions
./s3cli.py get-version my-bucket report.docx v1 ./report-v1.docx  # Download a specific version
```

## Error Handling

Most commands will provide descriptive error messages if something goes wrong. Common issues include:

- Profile not found or invalid
- S3 credentials are incorrect
- Bucket does not exist
- Insufficient permissions
- Network connectivity issues

Check the error message for details and ensure your credentials and configuration are correct.
