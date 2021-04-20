# amazon-guardduty-threatintellist-script

This script automates the process of creating a GuardDuty threat intel list across all GuardDuty capable regions in a GuardDuty administrator account.

## Prerequisites

* This script requires permissions to make changes in the Guardduty administrator account. 

* An environment capable of executing this script is required. That can be an EC2 instance or locally.

* Threat intel list uploaded to S3

### Execute Scripts

```
usage: amazon-guardduty-threatintellist-script.py [-h] --administrator_account ADMINISTATOR_ACCOUNT --assume_role ASSUME_ROLE --threatlist_location THREATLIST_LOCATION --list_name LIST_NAME --list_format LIST_FORMAT

Create a threat intel list for all enabled GuardDuty regions

arguments:
  -h, --help            show this help message and exit
  --administrator_account ADMINISTRATOR_ACCOUNT
                        AccountId for Central AWS Account
  --assume_role ASSUME_ROLE
                        Role Name of role to use
  --threatlist_location THREATLIST_LOCATION
                        S3 bucket URI where threat intel list is located. Accepted inputs: https://s3.us-west-2.amazonaws.com/my-bucket/my-object-key
  --list_name LIST_NAME
                        Name for threat list
  --list_format LIST_FORMAT
                        List format. Accepted inputs: 'TXT'|'STIX'|'OTX_CSV'|'ALIEN_VAULT'|'PROOF_POINT'|'FIRE_EYE'
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

