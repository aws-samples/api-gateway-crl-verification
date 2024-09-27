# Arthur Mnev (arthumne@) for Amazon Web Services. The intiial code base & logic
# Rafael Cassolato de Meneses (awsraf@) for Amazon Web Services code refactoring, error handling, and optimization
# Jason Garman (garmaja@) for Amazon Web Services. Code review
# Venkat Donavalli (donavv@) for Amazon Web Services. Code review and publication


import json
import logging
import os
import sys
import botocore


from cryptography import x509

from lib import s3_helper, iam_policy_helper
from distutils.util import strtobool

ALLOW_EFFECT = 'Allow'
DENY_EFFECT = 'Deny'

logger = logging.getLogger()
logger.setLevel(logging.getLevelName(os.getenv('LOGGING_LEVEL', default='INFO')))


env_COMPRESSED_CACHE = "COMPRESSED_CACHE"

# bucket and prefix configuration



s3bucket = os.getenv('s3Bucket')
jsonCRLkey = os.getenv('s3Key')

# configuration section
COMPRESSED_CACHE = bool(strtobool(os.getenv(env_COMPRESSED_CACHE, default='False')))

IS_REST_API_GW = bool(os.getenv('IS_REST_API_GW', default=True))

# Global variables
cached_etag = ''  # etag of cached CRL file
revoked_certificates_sn = {}  # cached pre-parsed CRL file

logger.info(f'This Lambda Authorizer is configured to use compressed cache: {COMPRESSED_CACHE}')


def lambda_handler(event, context):
    # global variables to leverage hot lambda state preservation for performance
    global cached_etag, revoked_certificates_sn

    logger.debug(f'event: {event}, context: {context}')
    logger.info(f'Will use bucket : { s3bucket} with key set to { jsonCRLkey }')
    validate_event_parameters(event=event)
    try:
        return generate_iam_policy(event)
    except botocore.exceptions.ClientError as err:

        errorCode = err.response['Error']['Code']
        errorMessage = err.response['Error']['Message']
        logger.error(f'error code: { errorCode }, message: {errorMessage}')
        
        logger.error(f'An botocore exception occurred. Returning policy with DENY effect')
        return iam_policy_helper.build_iam_policy_with_effect(DENY_EFFECT)
    except:
        logger.debug(json.dumps(sys.exc_info()[0], default=str))
        logger.error(f'An unknown exception occurred. Returning policy with DENY effect')

        # regardless of what kind of error has occurred and what handlers were applied,
        # if there is an exception, we automatically generate a deny policy
        # we have an option on either raising an error that will result in a "null" message
        # or silently returning a Deny Policy as below
        return iam_policy_helper.build_iam_policy_with_effect(DENY_EFFECT)


def generate_iam_policy(event):
    global revoked_certificates_sn, cached_etag


    reload_crl_if_needed()

    logger.info('loading mTLS certificate')
    mtls_certificate = load_mtls_certificate(event)

    serial_number = hex(mtls_certificate.serial_number)

    logger.info(
        f'Identified client certificate, checking the CRL cache for the serial number : {serial_number}')

    is_certificate_in_crl = serial_number in revoked_certificates_sn
    effect = DENY_EFFECT if is_certificate_in_crl else ALLOW_EFFECT
    logger.info(f'Is certificate in the CRL: {is_certificate_in_crl}, Policy Effect: {effect}')

    iam_policy = iam_policy_helper.build_iam_policy_with_effect(effect)

    logger.debug(f'Generated IAM Policy {json.dumps(iam_policy, default=str)}')
    return iam_policy


def reload_crl_if_needed():
    global cached_etag, revoked_certificates_sn
    logger.info(f'Checking if CRL relaod is required for bucket { s3bucket} key: { jsonCRLkey }')
    latest_etag = s3_helper.get_object_etag(s3bucket, jsonCRLkey)
    should_reload_crl = latest_etag != cached_etag
    logger.info(f'Determined if CRL needs to be reloaded: {should_reload_crl}')
    if should_reload_crl:
        logger.info('CRL reloaded (New Lambda execution container or the CRL has changed')

        revoked_certificates_sn = s3_helper.load_json(s3bucket, jsonCRLkey, COMPRESSED_CACHE)
        crl_list_size = len(revoked_certificates_sn)
        logger.info(f'New CRL List Size: {crl_list_size}')

        cached_etag = latest_etag
    else:
        logger.debug('CRL reused (hot Lambda function with etag match)')


# REST and HTTP APIs store client certificate in different locations.
# The environment variable IS_REST_API_GW determines whether or not you are using REST or HTTP APIs
def load_mtls_certificate(event):
    if IS_REST_API_GW:
        client_certificate_pem = event['requestContext']['identity']['clientCert']['clientCertPem']
    else:
        client_certificate_pem = event['requestContext']['authentication']['clientCert']['clientCertPem']

    client_certificate_bytes = client_certificate_pem.encode()
    return x509.load_pem_x509_certificate(client_certificate_bytes, backend=None)


# check if etag of the CRL object at s3 is the same as within this function.
# On the first run the function is in a cold state and etags will not match
# that will trigger a reload of the cached file.
# if the function is hot, the etag value will be populated, in that case the
# tag from this hot function will be compared to the etag present in S3. If
# etags match, no content change in the cache file and we can skip the retrieval
# if tags do not match, the content of the cache file has changed, and we will
# need to re-read it.
def is_crl_up_to_date():
    global s3bucket,jsonCRLkey
    try:
        logger.info(f'Attempting to retrieve S3 object header data {s3bucket}{jsonCRLkey}')
        current_etag = s3_helper.get_object_etag(s3bucket, jsonCRLkey)
        return cached_etag == current_etag
    except:
        logger.error(f'S3 object header data {s3bucket}{jsonCRLkey}')

def validate_event_parameters(event):
    """
    Validates the input event parameters for both REST API and HTTP API contexts.

    Parameters:
    event (dict): The event object passed to the Lambda function.

    Raises:
    ValueError: If any of the required input values are missing or invalid.
    """
    # Ensure the event is a dictionary
    if not isinstance(event, dict):
        raise ValueError("Event must be a dictionary.")

    # Determine if the event is from REST API or HTTP API Gateway
    client_cert = None
    if 'requestContext' in event:
        # REST API: Client certificate is under 'requestContext.identity.clientCert'
        if 'identity' in event['requestContext']:
            client_cert = event['requestContext']['identity'].get('clientCert')
            required_keys = ['requestContext', 'authorizationToken', 'methodArn']

        # HTTP API: Client certificate is under 'requestContext.http.clientCert'
        elif 'http' in event['requestContext']:
            client_cert = event['requestContext']['http'].get('clientCert')
            required_keys = ['requestContext', 'authorizationToken', 'routeArn']

        else:
            raise ValueError("Unsupported event structure: 'requestContext' is present but does not contain recognized keys.")

    else:
        raise ValueError("Event must contain the 'requestContext' key.")

    # Check for missing required keys in the event
    missing_keys = [key for key in required_keys if key not in event]
    if missing_keys:
        raise ValueError(f"Missing required keys in the event: {', '.join(missing_keys)}")

    # Validate specific event values
    if 'authorizationToken' in event and (not isinstance(event['authorizationToken'], str) or not event['authorizationToken']):
        raise ValueError("'authorizationToken' must be a valid non-empty string.")
    
    if 'methodArn' in event and (not isinstance(event['methodArn'], str) or not event['methodArn']):
        raise ValueError("'methodArn' must be a valid non-empty string.")
    
    if 'routeArn' in event and (not isinstance(event['routeArn'], str) or not event['routeArn']):
        raise ValueError("'routeArn' must be a valid non-empty string.")

    # Validate the client certificate if present
    if client_cert is not None and not isinstance(client_cert, dict):
        raise ValueError("Client certificate should be a dictionary if present.")

    logger.info("Event parameter validation passed.")
