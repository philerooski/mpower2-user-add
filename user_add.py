import synapseclient as sc
import bridgeclient as bc
import pandas as pd
import random
import boto3
import json
import os
import re
from botocore.exceptions import ClientError


INPUT_TABLE = "syn16847925"
OUTPUT_TABLE = "syn16847926"


def read_args():
    # for testing
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--bridgeUsername")
    parser.add_argument("--bridgePassword")
    parser.add_argument("--synapseUsername")
    parser.add_argument("--synapsePassword")
    args = parser.parse_args()
    return args


def get_env_var_credentials():
    credentials = {}
    credentials['synapseUsername'] = os.getenv('synapseUsername')
    credentials['synapsePassword'] = os.getenv('synapsePassword')
    credentials['bridgeUsername'] = os.getenv('bridgeUsername')
    credentials['bridgePassword'] = os.getenv('bridgePassword')
    return credentials


def delete_na_rows(syn):
    rows_to_delete = syn.tableQuery(
            "select * from {} where phone_number is null or guid is null".format(INPUT_TABLE))
    syn.delete(rows_to_delete)


def get_new_users(syn, input_table = INPUT_TABLE, output_table = OUTPUT_TABLE):
    input_table_df = syn.tableQuery(
            "select * from {}".format(input_table)).asDataFrame()
    for i, user in input_table_df.iterrows():
        if pd.isnull(user.phone_number) and pd.isnull(user.guid):
            delete_na_rows(syn)
            return ("Error: phone_number and guid was left blank", -1, -1, user.visit_date)
        elif pd.isnull(user.phone_number):
            delete_na_rows(syn)
            return ("Error: phone_number was left blank", -1, user.guid, user.visit_date)
        elif pd.isnull(user.guid):
            delete_na_rows(syn)
            return ("Error: guid was left blank", user.phone_number, -1, user.visit_date)
    phone_number_ints = input_table_df.phone_number.apply(get_phone_number_digits)
    input_table_df['phone_number'] = phone_number_ints
    input_table_df['phone_number'] = input_table_df.phone_number.astype(str)
    input_table_df = input_table_df.set_index(["phone_number", "guid"], drop=False)
    output_table_df = syn.tableQuery(
            "select phone_number, guid from {}".format(output_table)).asDataFrame()
    output_table_df['phone_number'] = output_table_df.phone_number.astype(str)
    output_table_df = output_table_df.set_index(["phone_number", "guid"], drop = False)
    new_numbers = set(input_table_df.index.values).difference(
            output_table_df.index.values)
    return input_table_df.loc[list(new_numbers)]


def get_bridge_client(bridge_username, bridge_password, study="sage-mpower-2"):
    bridge = bc.bridgeConnector(
            email = bridge_username, password = bridge_password, study = study)
    return bridge


def get_participant_info(bridge, phone_number):
    participant_info = bridge.restPOST(
            "/v3/participants/search",
            {"phoneFilter": phone_number})
    return participant_info


def process_request(bridge, participant_info, phone_number, external_id):
    if participant_info['total'] == 0:
        # create account
        try:
            # assign to random engagement group
            engagement_groups = random.choice([
                ["gr_SC_DB","gr_SC_CS"],
                ["gr_BR_AD","gr_BR_II"],
                ["gr_ST_T","gr_ST_F"],
                ["gr_DT_F","gr_DT_T"]])
            bridge.restPOST("/v3/externalIds", [external_id])
            bridge.restPOST(
                    "/v3/participants",
                    {"externalId": external_id,
                     "phone": {"number": phone_number,
                               "regionCode": "US"},
                     "dataGroups": engagement_groups + ["clinical_consent"],
                     "sharingScope": "sponsors_and_partners"}) # assume US?
            return "Success: User account created"
        except Exception as e:
            return ("Error: Could not create user account. "
                    "Does your phone number have a US area code and/or "
                    "has the GUID already been assigned? "
                    "Console output: {0}".format(e))
    elif 'externalId' not in participant_info['items'][0]:
        try:
            # add external_id and then assign to existing account
            user_id = participant_info['items'][0]['id']
            bridge.restPOST("/v3/externalIds", [external_id])
            bridge.restPOST(
                    "/v3/participants/{}".format(user_id),
                    {"externalId": external_id,
                     "dataGroups": ["clinical_consent"],
                     "sharingScope": "sponsors_and_partners"}) # assume US?
            return ("Success: Preexisting user account found. "
                    "New External ID assigned.")
        except Exception as e:
            return ("Error: Preexising user account found. "
                    "Could not assign new external ID. "
                    "Console output: {0}".format(e))
    elif participant_info['items'][0]['externalId'] != external_id:
        # phone and external ID have already been assigned
        return ("Error: Preexisting account found with guid {}. "
                "Please contact AtHomePD_support@synapse.org "
                "if you would like to assign a new guid.".format(
                    participant_info['items'][0]['externalId']))
    elif participant_info['items'][0]['externalId'] == external_id:
        # account exists and is correct, do nothing
        return ("Success: Preexisting account found with matching phone number "
                "and guid.")


def create_table_row(status, phone_number, guid,
                     visit_date, output_table = OUTPUT_TABLE):
    table_values = [str(phone_number), str(guid), int(visit_date), status]
    return table_values


def get_secret():
    secret_name = "phil/synapse/bridge"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
    return secret


def get_phone_number_digits(phone_number):
    phone_number = str(phone_number)
    p = re.compile("\D")
    phone_number = re.sub(p, "", phone_number)
    return phone_number


def is_valid_phone_number(phone_number):
    phone_number = get_phone_number_digits(phone_number)
    if len(phone_number) == 10 and phone_number.isdigit():
        return True
    else:
        return False


def is_valid_guid(guid):
    p = re.compile("\w{4}-\w{3}-\w{3}")
    match = re.match(p, guid)
    if match is not None:
        return True
    else:
        return False


def get_credentials():
    # Get credentials within this script
    credentials = json.loads(get_secret())
    return credentials


def main():
    credentials = get_credentials()
    syn = sc.Synapse(configPath="/var/task/.synapseConfig")
    syn.login(email = credentials['synapseUsername'],
              password = credentials['synapsePassword'])
    new_users = get_new_users(syn)
    if isinstance(new_users, tuple): # returned error message
        table_row = create_table_row(new_users[0], new_users[1],
                                     new_users[2], new_users[3])
        syn.store(sc.Table(OUTPUT_TABLE, [table_row]))
        return
    duplicated_numbers = new_users.phone_number.duplicated(keep = False)
    if any(duplicated_numbers):
        duplicates = new_users.loc[duplicated_numbers]
        if len(duplicates.guid) == len(duplicates.guid.unique()):
            table_row = create_table_row("Error: It looks like you accidentally "
                                         "entered an incorrect guid and tried to "
                                         "submit a corrected one immediately "
                                         "afterwards. Please contact "
                                         "AtHomePD_support@synapse.org "
                                         "if you would like to assign a new guid.",
                                         duplicates.phone_number.iloc[0],
                                         "", duplicates.visit_date.iloc[0])
            syn.store(sc.Table(OUTPUT_TABLE, [table_row]))
            return
    to_append_to_table = []
    for i, user in new_users.iterrows():
        phone_number = get_phone_number_digits(user.phone_number)
        guid = str(user.guid).strip()
        visit_date = int(user.visit_date)
        print("phone_number: ", phone_number)
        print("guid: ", guid)
        print("visit_date: ", visit_date)
        try:
            if not is_valid_phone_number(phone_number):
                table_row = create_table_row("Error: The phone number is improperly "
                                             "formatted. Please enter a valid, 10-digit "
                                             "number",
                                             phone_number, guid, visit_date)
            elif not is_valid_guid(guid):
                table_row = create_table_row("Error: The guid is improperly "
                                             "formatted. Please enter a valid guid "
                                             "in XXXX-XXX-XXX format using only "
                                             "alphanumeric characters and hyphens.",
                                             phone_number, guid, visit_date)
            else:
                bridge = get_bridge_client(credentials['bridgeUsername'],
                                           credentials['bridgePassword'])
                participant_info = get_participant_info(bridge, phone_number)
                status = process_request(bridge, participant_info,
                                         phone_number, guid)
                table_row = create_table_row(status, phone_number,
                                             guid, visit_date)
        except Exception as e:
            table_row = create_table_row("Error: One of the fields is improperly "
                                         "formatted. Console output: {0}".format(e),
                                         -1, guid, visit_date)
        to_append_to_table.append(table_row)
    if len(to_append_to_table):
        t = sc.Table(OUTPUT_TABLE, to_append_to_table)
        syn.store(t)


def lambda_handler(e, c):
    main()


if __name__ == "__main__":
    main()
