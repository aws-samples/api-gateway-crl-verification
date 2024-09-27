# Arthur Mnev (arthumne@) for Amazon Web Services. The intiial code base & logic
# Rafael Cassolato de Meneses (awsraf@) for Amazon Web Services code refactoring, error handling, and optimization
# Jason Garman (garmaja@) for Amazon Web Services. Code review
# Venkat Donavalli (donavv@) for Amazon Web Services. Code review and publication


import logging
import os

# This lambda function uses zlib for compression of the CRL cache.
from urllib.parse import unquote_plus

from lib import certificate_helper
from distutils.util import strtobool

# This function uses the Cryptography library all crypto operations
# Please note this Python library is bytecode specific.
# Use caution if building the library on a Mac or other non-intel CPUs (incompatible binary format and/or byte code)


# define the names for the environment variables

DEFAULT_ACM_PCA_ARN = 'arn:aws:acm-pca:<region>:<account_id>:certificate-authority/<acm_pca_id>'
env_ACM_PCA_ARN = "ACM_PCA_ARN"
env_IS_DEBUG = "IS_DEBUG"
env_USE_ACM_PCA = "USE_ACM_PCA"
env_ACM_PCA_ARN = "ACM_PCA_ARN"
env_COMPRESS_CACHE = "COMPRESS_CACHE"
env_ALLOW_EXPIRED_CRL = "ALLOW_EXPIRED_CRL"

logger = logging.getLogger()
logger.setLevel(logging.getLevelName(os.getenv('LOGGING_LEVEL', default='DEBUG')))

# configuration section

# Set the COMPRESS_CACHE environment variable to True if you would like to compress the file, avoid eval for arbitrary code execution
COMPRESS_CACHE = bool(strtobool(os.getenv(env_COMPRESS_CACHE, default='False')))

# Indicates whether to dynamically query ACM PCA for its Public Key or retrieve the file from the CRL's s3 bucket, avoid eval for arbitrary code execution
USE_ACM_PCA = bool(strtobool(os.getenv(env_USE_ACM_PCA, default='False')))

# For dynamic retrieval of the certificate from the ACM PCA,
# the function will require the ARN and appropriate permissions
ACM_PCA_ARN = os.getenv(env_ACM_PCA_ARN, default=DEFAULT_ACM_PCA_ARN)

# allow expired CRL check. In some cases we may want to allow expired CRLs to work with an assumption that something is better than nothing. 
# this is a business decision that may or may not be appropriate for some customers
ALLOW_EXPIRED_CRL = bool(strtobool(os.getenv(env_ALLOW_EXPIRED_CRL, 'False')))

# This function will verify the signature of the CRL and needs to know where it can find
# the Public Key. 
# 
# If configured to use ACM PCA, the function will dynamically retrieve the CA's public key.
# In absence of ACM PCA integration, the function will expect the public key file to
# be stored next to the CRL, with the format of <crl_name>.crt


def lambda_handler(event, context):
    log_function_configuration()

    logger.debug(f'Event: {event}, Context: {context}')

    try:
        # validate lambda event before use
        validate_lambda_event(event)

        s3_bucket = get_s3_bucket(event)
        crl_s3_object_key = get_crl_s3_object_key(event)

        revoked_serial_numbers_dict = create_revoked_serial_numbers_dict_from_crl(s3_bucket,
                                                                                  crl_s3_object_key, allow_expired_crl=ALLOW_EXPIRED_CRL)
        logger.debug("Successfully parsed the CRL and constructed cache object")

        # place the dictionary file into the s3 bucket with a .json extension
        revoked_serial_numbers_dict_key = f'{crl_s3_object_key}.json'
        certificate_helper.put_revoked_serial_numbers_object_into_s3(s3_bucket,
                                                                     revoked_serial_numbers_dict_key,
                                                                     revoked_serial_numbers_dict,
                                                                     COMPRESS_CACHE)
    except RevokeSerialNumberUpdateException as e:
        logger.error(f"RevokeSerialNumberUpdateException occurred: {e}. Terminating")
    except:
        logger.error(
            "There was an exception while creating the revoked serial numbers dictionary. Terminating")


def create_revoked_serial_numbers_dict_from_crl(s3_bucket, crl_s3_object_key, allow_expired_crl:bool =False):
    # declare variables
    revoked_serial_numbers_dict: dict = {}

    ca_s3_key = f'{crl_s3_object_key}.crt'
    # Depending on the USE_ACM_PCA will either retrieve from ACM or S3
    crl_signing_ca = get_crl_signing_ca_from_acm_or_s3(ca_s3_key, s3_bucket)

    # Validate the CA's Public Key is available, if not -- terminate
    if not crl_signing_ca:
        error_message = get_public_key_not_available_error_message(ca_s3_key, s3_bucket)
        raise RevokeSerialNumberUpdateException(error_message)

    logger.debug(f'CRL CA certificate decode, key size:{crl_signing_ca.key_size}') 
    logger.debug(f'Retrieving the CRL {s3_bucket}/{crl_s3_object_key}')

    # Retrieve the CRL from s3
    crl = certificate_helper.get_crl(s3_bucket, crl_s3_object_key,allow_expired_crl=allow_expired_crl)

    for revoked_cert in crl:
        revoked_serial_numbers_dict[hex(revoked_cert.serial_number)] = ''

    if not revoked_serial_numbers_dict:
        logger.warning("No revoked certificates found in the CRL.")


    return revoked_serial_numbers_dict


def get_public_key_not_available_error_message(ca_s3_key, s3_bucket):
    method = 'ACM PCA' if USE_ACM_PCA else 's3'
    location = ACM_PCA_ARN if USE_ACM_PCA else f'{s3_bucket}/{ca_s3_key}'
    msg = f"Error retrieving CRL's public key. Method: {method} Location: {location}. Terminating"
    return msg


# Retrieve the certificate for the CRL, if the certificate is not present, we cannot verify
# the signature, and there is no reason to move forward.
# The signing key can come from ACM PCA or a local file.
# We rely on function configuration parameters to determine which one to use.
def get_crl_signing_ca_from_acm_or_s3(ca_s3_key, s3_bucket):
    if USE_ACM_PCA:
        issuing_ca_public_key = certificate_helper.get_crl_signing_ca_key_acm_pca(ACM_PCA_ARN)
    else:
        issuing_ca_public_key = certificate_helper.get_crl_signing_ca_public_key(s3_bucket,
                                                                                 ca_s3_key)
    return issuing_ca_public_key


def log_function_configuration():
    logger.debug(
        f'Config: COMPRESS_CACHE:{COMPRESS_CACHE}; USE_ACM_PCA:{USE_ACM_PCA}; ACM_PCA_ARN:{ACM_PCA_ARN}')

    acm_message = f'Configured to dynamically retrieve CRL Signing Key from ACM PCA with ARN {USE_ACM_PCA}' if USE_ACM_PCA else 'Configured to use s3 as a location for CRL Signing Key location'
    logger.debug(acm_message)


def get_crl_s3_object_key(event):
    return unquote_plus(event['Records'][0]['s3']['object']['key'])


def get_s3_bucket(event):
    return event['Records'][0]['s3']['bucket']['name']


class RevokeSerialNumberUpdateException(Exception):
    pass


def validate_lambda_event(event):
    """
    Validates the incoming Lambda event to ensure all necessary elements are present and correctly formatted.
    Args:
        event (dict): The Lambda event object.
    Raises:
        ValueError: If required elements are missing or incorrectly formatted.
    """
    try:
        # Check if 'Records' exists and is a list
        if 'Records' not in event or not isinstance(event['Records'], list) or len(event['Records']) == 0:
            raise ValueError("Invalid event format: 'Records' key is missing or not properly formatted.")

        # Validate that the required 'bucket' and 'key' fields are present
        s3_bucket = event['Records'][0].get('s3', {}).get('bucket', {}).get('name')
        s3_key = event['Records'][0].get('s3', {}).get('object', {}).get('key')

        if not s3_bucket or not s3_key:
            raise ValueError("Invalid event format: 's3.bucket.name' or 's3.object.key' is missing.")

        logger.debug(f"Event validation passed. Bucket: {s3_bucket}, Key: {s3_key}")

    except ValueError as ve:
        logger.error(f"Event validation error: {ve}")
        raise

    except Exception as e:
        logger.error(f"Unexpected error during event validation: {e}")
        raise
