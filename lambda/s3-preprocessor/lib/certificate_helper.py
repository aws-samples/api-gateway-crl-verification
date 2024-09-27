import io
import json
import logging
import zlib

import boto3
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm, InvalidSignature
from datetime import datetime
from cryptography.hazmat.backends import default_backend

acm_pca_client = boto3.client('acm-pca')
s3_client = boto3.client('s3')

logger = logging.getLogger()


def read_s3_object_bytes(bucket, key):
    # declare IO buffer for s3 data
    buffer = io.BytesIO()
    # download S3 file object
    s3_client.download_fileobj(Bucket=bucket, Key=key, Fileobj=buffer)
    # extract raw byte data for the CRL
    return buffer.getvalue()


def get_crl(bucket, key, allow_expired_crl: bool = False):
    crl_bytes = read_s3_object_bytes(bucket, key)
    return get_certificate_revocation_list(crl_bytes, allow_expired_crl=allow_expired_crl)


def get_crl_signing_ca_public_key(bucket, key):
    signing_ca_certificate_bytes = read_s3_object_bytes(bucket, key)

    # using format agnostic function, get the certificate public key
    return get_ca_public_key(signing_ca_certificate_bytes)


# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm-pca.html#ACMPCA.Client.get_certificate_authority_certificate
def get_crl_signing_ca_key_acm_pca(arn):
    certificate_authority = acm_pca_client.get_certificate_authority_certificate(
        CertificateAuthorityArn=arn)

    # cryptography functions expect bytes, not strings.
    # ACM PCA will return a string. Convert the string to bytes
    return get_ca_public_key(bytes(certificate_authority['Certificate'], 'utf-8'))


def get_ca_public_key(certificate_bytes: bytes):
    if is_pem_certificate(certificate_bytes):
        issuer_certificate = x509.load_pem_x509_certificate(certificate_bytes)
    else:
        issuer_certificate = x509.load_der_x509_certificate(certificate_bytes)

    return issuer_certificate.public_key()


# function to check if a certificate is in PEM or DER format
# attempt to decode the bytes as a string, and check if "-----BEGIN CERTIFICATE-----" is present
def is_pem_certificate(certificate_object) -> bool:
    try:
        # check if data is in byte or string format. Convert to string if bytes
        is_object_in_byte_format = isinstance(certificate_object, bytes)
        certificate_as_string = certificate_object.decode(
            'utf-8') if is_object_in_byte_format else certificate_object

        return certificate_as_string.index('-----BEGIN CERTIFICATE-----') >= 0

    except Exception:
        logger.info(f'Determined that the certificate is not in PEM format')
        return False

# function to check if a CRL is in PEM or DER format
# attempt to decode the bytes as a string, and check if "-----BEGIN X509 CRL-----" is present


def is_pem_CRL(crl_object) -> bool:
    try:
        # check if data is in byte or string format. Convert to string if bytes
        is_object_in_byte_format = isinstance(crl_object, bytes)
        crl_as_string = crl_object.decode(
            'utf-8') if is_object_in_byte_format else crl_object

        return crl_as_string.index('-----BEGIN X509 CRL-----') >= 0

    except Exception:
        logger.info(f'Determined that the CRL is not in PEM format')
        return False


# function to retrieve a certificate revocation list from bytes will read PEM or DER format
def get_certificate_revocation_list(certificate_bytes: bytes, allow_expired_crl: bool = False):
    """
    Retrieves a Certificate Revocation List (CRL) from bytes, handles errors, and returns the CRL object.
    Args:
        certificate_bytes (bytes): The bytes of the CRL.
    Returns:
        x509.CertificateRevocationList: The parsed CRL object.
    Raises:
        ValueError: If the CRL format is unsupported or if parsing fails.
    """

    try:
        logger.info('Parsing Certificate Revocation List')
        if is_pem_CRL(certificate_bytes):
            logger.info('Determined the CRL to be of PEM type')
            crl = x509.load_pem_x509_crl(certificate_bytes, default_backend())
        else:
            logger.info('Determined the CRL to be of DER type')
            crl = x509.load_der_x509_crl(certificate_bytes, default_backend())

        logger.debug(
            "Successfully parsed the CRL, validated its signature; proceeding with processing CRL expiration check.")

        # Check if the CRL is expired
        if not allow_expired_crl:
            next_update = crl.next_update
            if next_update and next_update < datetime.now():
                expired_time = next_update.strftime('%Y-%m-%d %H:%M:%S')
                error_message = f"CRL is expired as of {expired_time}"
                raise InvalidCRLDateException(error_message)
            logger.debug("CRL is valid and not expired; returning")
        elif allow_expired_crl:
            logger.debug(
                "Skipping CRL date verification check as per allow_expired_crl is set to True")

        return crl
    except InvalidCRLDateException as e:
        # Handle specific case for expired CRLs
        logger.error(f"CRL date error: {e}")
        raise

    except (UnsupportedAlgorithm, InvalidSignature) as e:
        logger.error(
            f"Failed to parse the CRL due to an unsupported algorithm or invalid signature: {e}")
        raise ValueError(f"Invalid CRL format or content: {e}")

    except ValueError as ve:
        logger.error(
            f"Failed to parse the CRL due to a value error (i.e. malformed CRL and alike): {ve}")
        raise

    except Exception as e:
        logger.error(
            f"An unexpected error occurred while parsing the CRL: {e}")
        raise ValueError(
            f"Unexpected error occurred while parsing the CRL: {e}")


def put_revoked_serial_numbers_object_into_s3(bucket, key, revoked_serial_numbers_dict, compress):
    key = f'{key}.zip' if compress else key

    bytes_buffer = get_revoked_serial_numbers_object_bytes(
        compress, revoked_serial_numbers_dict)

    s3_client.upload_fileobj(bytes_buffer, Bucket=bucket, Key=key)


def get_revoked_serial_numbers_object_bytes(compress, revoked_serial_numbers):
    bytes_buffer = io.BytesIO()

    # if compression is requested, compress the data to reduce future load times
    if compress:
        bytes_buffer.write(zlib.compress(json.dumps(
            revoked_serial_numbers).encode('utf-8'), 2))
    else:
        bytes_buffer.write(json.dumps(revoked_serial_numbers).encode('utf-8'))

    # rewind the write buffer to position zero so it can be read
    bytes_buffer.seek(0)
    return bytes_buffer


class InvalidCRLDateException(Exception):
    """Exception raised when the Certificate Revocation List (CRL) is expired or has an invalid date."""
    pass
