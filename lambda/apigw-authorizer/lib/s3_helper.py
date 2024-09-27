import io
import json
import zlib

import boto3

s3client = boto3.client('s3')


def get_object_etag(bucket, object_key):
    head_object = s3client.head_object(Bucket=bucket, Key=object_key)
    return head_object['ResponseMetadata']['HTTPHeaders']['etag']


def load_json(bucket, object_key, is_file_compressed):
    loaded_bytes = load_object_bytes(bucket, object_key)

    bytes_to_deserialize = decompress_bytes(loaded_bytes) if is_file_compressed else loaded_bytes
    return json.loads(bytes_to_deserialize)


def decompress_bytes(compressed_file_bytes):
    return zlib.decompress(compressed_file_bytes)


def s3_get_dictionary_file_compressed(bucket, key):
    decompressed_bytes = zlib.decompress(load_object_bytes(bucket, key))

    revoked_serial_numbers = json.loads(decompressed_bytes)
    return revoked_serial_numbers


def load_object_bytes(bucket, key):
    bytes_buffer = io.BytesIO()
    s3client.download_fileobj(Bucket=bucket, Key=key, Fileobj=bytes_buffer)
    return bytes_buffer.getvalue()
