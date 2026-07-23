import requests

# Replace with your actual client ID and access key
CLIENT_ID = ''
ACCESS_KEY = ''

AUTH_URL = 'https://cloudinfra-gw.portal.checkpoint.com/auth/external'
GRAPHQL_URL_V1 = 'https://cloudinfra-gw.portal.checkpoint.com/app/waf/graphql/v1'
GRAPHQL_URL_V2 = 'https://cloudinfra-gw.portal.checkpoint.com/app/waf/graphql/v2'

def get_auth_token(client_id, access_key):
    headers = {'Content-Type': 'application/json'}
    payload = {
        'clientId': client_id,
        'accessKey': access_key,
        'ck': 'externalClient01'
    }
    response = requests.post(AUTH_URL, headers=headers, json=payload)
    response.raise_for_status()
    data = response.json()
    token = data.get('data', {}).get('token')
    if not token:
        print("Token not found in the response.")
        return None
    return token

def fetch_assets(auth_token):
    query = """
    query {
        getAssets(userDefined: true) {
            assets {
                id
                name
            }
        }
    }
    """
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {auth_token}'
    }
    response = requests.post(GRAPHQL_URL_V1, json={'query': query}, headers=headers)
    response.raise_for_status()
    return response.json()['data']['getAssets']['assets']

def fetch_tuning_suggestions(auth_token, asset_id):
    query = """
    query getAssetTuning($id: String!) {
        getAssetTuning(id: $id) {
            attackTypes
            decision
            eventTitle
            eventType
            logQuery
            policyVersion
            severity
        }
    }
    """
    variables = {'id': asset_id}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {auth_token}'
    }
    response = requests.post(GRAPHQL_URL_V2, json={'query': query, 'variables': variables}, headers=headers)
    response.raise_for_status()
    return response.json()['data']['getAssetTuning']

def main():
    auth_token = get_auth_token(CLIENT_ID, ACCESS_KEY)
    if not auth_token:
        print("Failed to retrieve authentication token.")
        return

    assets = fetch_assets(auth_token)
    for asset in assets:
        if asset['name'] == "Any Service":
            continue  # Skip the 'Any Service' asset
        print(f"Asset: {asset['name']} (ID: {asset['id']})")
        tuning_suggestions = fetch_tuning_suggestions(auth_token, asset['id'])
        if tuning_suggestions:
            print("Tuning Suggestions:")
            for suggestion in tuning_suggestions:
                print(f"  - Event Title: {suggestion['eventTitle']}")
                print(f"    Severity: {suggestion['severity']}")
                print(f"    Decision: {suggestion['decision']}")
                print(f"    Attack Types: {', '.join(suggestion['attackTypes'])}")
                print(f"    Log Query: {suggestion['logQuery']}")
                print(f"    Policy Version: {suggestion['policyVersion']}")
                print(f"    Event Type: {suggestion['eventType']}\n")
        else:
            print("No tuning suggestions found.\n")


if __name__ == "__main__":
    main()