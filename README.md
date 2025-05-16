# Simple Storage Service console client that can run limited set of S3 commands

## Features:
- Copy from/to cloud or local file copy with optional file encryption
- List files in bucket
- List file versions in bucket
- Delete file version from cloud
- Build presigned URLs for get/put
- cleanup old file versions in bucket

## Usage:
&nbsp;&nbsp;&nbsp;&nbsp;s3cli<br>
&nbsp;&nbsp;&nbsp;&nbsp;[--dry-run][--decrypt][--from-part][--verbose]<br>
&nbsp;&nbsp;&nbsp;&nbsp;[cp source_file_name destination_file_name]<br>
&nbsp;&nbsp;&nbsp;&nbsp;[ls remote_name:path]<br>
&nbsp;&nbsp;&nbsp;&nbsp;[versions remote_name:path]<br>
&nbsp;&nbsp;&nbsp;&nbsp;[delete_version remote_name:remote_file versionId]<br>
&nbsp;&nbsp;&nbsp;&nbsp;[cleanup_versions remote_name:remote_file number_of_versions]<br>
&nbsp;&nbsp;&nbsp;&nbsp;[url_get remote_name:remote_file]<br>
&nbsp;&nbsp;&nbsp;&nbsp;[url_put remote_name:remote_file]<br>
&nbsp;&nbsp;&nbsp;&nbsp;[qcp source_file_name destination_file_name]<br>

## Configuration file
- Uses configuration file named **configuration.ini**
- Configuration file format: **option_name=option_value**
- Configuration file example:

max_file_size=100M<br>
oracle=s3key.txt<br>
local=local_s3key.txt

## Copy command:
  - cp source_file_name destination_file_name
    - where file name has the following format [cloud_provider_name:]file_name
    - example (copy from local to cloud): cp file1 oracle:bucket_name/file_name
    - example (copy from cloud to local): cp oracle:bucket_name/file_name file2
    - example (copy from local to local): cp file_name file2
  - copy command parameters (can be specified in the command line, in the configuration.ini, in the cloud provider configuration file):
    - --max_file_size xxx[K][M][G] - specifies maximum file size. Large files will be splitted to parts according to this setting.
    - --dry-run - skips commands that make changes in files
    - --from-part N - is used for interrupted transfets. Start file transfer from file part N
    - --decrypt - is used for local file copy. Means that file decrypt is requested. Default setting is to encrypt.

## Cloud provider configuration file format example:
source_type=[aws][gcp][custom][custom_noprefix]<br>
host=<br>
region=<br>
access_key=<br>
access_secret=<br>
encryption_key=this is an optional field with 32 byte key encoded with base64. When encryption_key is present - cloud files will automaticaly encrypted/decrypted during copy

