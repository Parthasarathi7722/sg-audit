import boto3
import csv
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

def get_user_input():
    aws_profiles = input("Enter AWS profiles (comma-separated): ").split(',')
    aws_regions = input("Enter AWS regions (comma-separated): ").split(',')
    return aws_profiles, aws_regions

def write_to_csv(file_path, header, data):
    with open(file_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(header)
        writer.writerows(data)

def main():
    aws_profiles, aws_regions = get_user_input()

    # Open CSV file for writing
    output_csv_file = 'security_group_audit.csv'
    header = ['Profile Name', 'Account ID', 'Region', 'Security Group Name', 'Security Group ID', 'Open Port', 'Protocol', 'Direction', 'IP Range']
    data = []

    # Open error log file for writing
    error_log_file = 'error_log.txt'

    for aws_profile in aws_profiles:
        for aws_region in aws_regions:
            print(f"Processing {aws_profile} in {aws_region}...")

            try:
                # Set AWS region
                session = boto3.Session(profile_name=aws_profile, region_name=aws_region)

                # Create an EC2 client for the current AWS profile and region
                ec2 = session.client('ec2')

                # Get a list of all the security groups in the current profile and region
                security_groups = ec2.describe_security_groups()

                # Loop through each security group and get its inbound and outbound rules
                for group in security_groups['SecurityGroups']:
                    group_id = group['GroupId']
                    group_name = group['GroupName']

                    for direction, permission_list in {'inbound': group['IpPermissions'], 'outbound': group.get('IpPermissionsEgress', [])}.items():
                        for rule in permission_list:
                            from_port = rule.get('FromPort', 'N/A')
                            to_port = rule.get('ToPort', 'N/A')
                            port_range = f"{from_port}-{to_port}" if from_port != 'N/A' and to_port != 'N/A' else f"{from_port}"
                            protocol = rule.get('IpProtocol', 'N/A')
                            for ip_range in rule.get('IpRanges', []):
                                data.append([aws_profile, session.client('sts').get_caller_identity().get('Account'), aws_region, group_name, group_id, port_range, protocol, direction.upper(), ip_range['CidrIp']])

            except NoCredentialsError:
                print(f"Authentication error for profile {aws_profile} in region {aws_region}. Make sure you have valid AWS credentials.")
                with open(error_log_file, 'a') as error_log:
                    error_log.write(f"Authentication error for profile {aws_profile} in region {aws_region}. Make sure you have valid AWS credentials.\n")
            except PartialCredentialsError:
                print(f"Partial credentials error for profile {aws_profile} in region {aws_region}. Please check your AWS credentials configuration.")
                with open(error_log_file, 'a') as error_log:
                    error_log.write(f"Partial credentials error for profile {aws_profile} in region {aws_region}. Please check your AWS credentials configuration.\n")
            except ClientError as e:
                if e.response['Error']['Code'] == 'AuthFailure':
                    print(f"Authentication failure for profile {aws_profile} in region {aws_region}: {e}")
                    with open(error_log_file, 'a') as error_log:
                        error_log.write(f"Authentication failure for profile {aws_profile} in region {aws_region}: {e}\n")
                else:
                    print(f"An error occurred for profile {aws_profile} in region {aws_region}: {e}")
                    with open(error_log_file, 'a') as error_log:
                        error_log.write(f"An error occurred for profile {aws_profile} in region {aws_region}: {e}\n")

            print(f"Processing {aws_profile} in {aws_region} complete.")
            print("------------------------------")

    write_to_csv(output_csv_file, header, data)
    print(f"Security group audit report has been generated: {output_csv_file}")

if __name__ == "__main__":
    main()
