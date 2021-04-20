#!/usr/bin/env python

import boto3
import argparse
import re

from botocore.exceptions import ClientError


def assume_role(aws_account_number, role_name):
    """
    Assumes the provided role and returns a GuardDuty client
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :param aws_region: AWS Region for the Client call, not required for IAM calls
    :return: GuardDuty client in the specified AWS Account and Region
    """

    # Beginning the assume role process for account
    sts_client = boto3.client('sts')

    # Get the current partition
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]

    response = sts_client.assume_role(
        RoleArn='arn:{}:iam::{}:role/{}'.format(
            partition,
            aws_account_number,
            role_name
        ),
        RoleSessionName='EnableGuardDuty'
    )

    # Storing STS credentials
    session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )

    print("Assumed session for account {}.".format(
        aws_account_number
    ))

    return session


def list_detectors(gd_client, aws_region):
    """
    Lists the detectors in a given Region
    Used to detect if a detector exists already
    :param gd_client: GuardDuty client
    :param aws_region: AWS Region
    :return: Dictionary of AWS_Region: DetectorId
    """

    detector_dict = gd_client.list_detectors()

    if detector_dict['DetectorIds'] == []:
        pass
    else:
        return detector_dict


def create_list(gd_client, aws_region, detector_dict, name, list_format, threatlist_location):
    """
    Create a GuardDuty threat intel list
    :param gd_client: GuardDuty client
    :param aws_region: AWS Region
    :param desirec_frequency: arg for configuration setting
    :param detector_dict: GuardDuty Detector Id
    :param name: Name of threat list
    :param list_format: Format of threat list
    :param threatlist_location: Where to get threat list
    """
    try:
        gd_client.create_threat_intel_set(
            DetectorId=detector_dict['DetectorIds'][0],
            Name=name,
            Format=list_format,
            Location=threatlist_location,
            Activate=True,
        )
        print(f'GuardDuty Threat Intel Set changed in {aws_region}')
    except ClientError as err:
        print(err)


if __name__ == '__main__':

    # Setup command line arguments
    parser = argparse.ArgumentParser(description='Create a threat intel list for all enabled GuardDuty regions')
    parser.add_argument('--administrator_account', type=str, required=True, help="AccountId for Central AWS Account")
    parser.add_argument('--assume_role', type=str, required=True, help="Role Name to assume")
    parser.add_argument('--threatlist_location', type=str, help="S3 bucket URI where threat intel list is located. Accepted inputs: https://s3.us-west-2.amazonaws.com/my-bucket/my-object-key.")
    parser.add_argument('--list_name', type=str, required=True, help="Name for threat list")
    parser.add_argument('--list_format', type=str, required=True, help="List format. Accepted inputs: 'TXT'|'STIX'|'OTX_CSV'|'ALIEN_VAULT'|'PROOF_POINT'|'FIRE_EYE'")
    args = parser.parse_args()

    # Validate administrator accountId
    if not re.match(r'[0-9]{12}', args.administrator_account):
        raise ValueError("Master AccountId is not valid")

    # Getting GuardDuty regions
    session = boto3.session.Session()
    guardduty_regions = []
    guardduty_regions = session.get_available_regions('guardduty')
    print("Changing configuration in all available GuardDuty regions {}".format(guardduty_regions))

    # Processing Administrator account
    name = args.list_name
    list_format = args.list_format
    threatlist_location = args.threatlist_location
    master_session = assume_role(args.administrator_account, args.assume_role)
    for aws_region in guardduty_regions:
        gd_client = master_session.client('guardduty', region_name=aws_region)
        # Process threat intel list update
        try:
            detector_dict = list_detectors(gd_client, aws_region)
            if detector_dict != None:
                create_list(gd_client, aws_region, detector_dict, name, list_format, threatlist_location)
            else:
                print(f"Failed to list detectors in Administrator account for region: {aws_region}.  Either your credentials are not correctly configured or the region is an OptIn region that is not enabled on the Administrator account.  Skipping {aws_region} and attempting to continue")
        except ClientError as err:
            if err.response['ResponseMetadata']['HTTPStatusCode'] == 403:
                print(f"Failed to list detectors in Administrator account for region: {aws_region}.  Either your credentials are not correctly configured or the region is an OptIn region that is not enabled on the Administrator account.  Skipping {aws_region} and attempting to continue")
            else:
                print(err)
