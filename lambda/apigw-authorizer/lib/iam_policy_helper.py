IAM_POLICY_VERSION = '2012-10-17'  # default version
IAM_POLICY_PRINCIPAL = 'APIGWLambdaAuthorizer'


def build_iam_policy_with_effect(effect):
    auth_response = {}
    auth_response['principalId'] = IAM_POLICY_PRINCIPAL

    policy_document = {}
    policy_document['Version'] = IAM_POLICY_VERSION
    policy_document['Statement'] = []

    policy_statement = {}
    policy_statement['Action'] = 'execute-api:Invoke'
    policy_statement['Effect'] = effect
    policy_statement['Resource'] = '*'
    policy_document['Statement'].append(policy_statement)

    auth_response['policyDocument'] = policy_document
    return auth_response
