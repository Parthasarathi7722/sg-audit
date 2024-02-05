# AWS Security Group Audit

This Python script performs an audit of AWS security groups, checking for open ports and generating a report in CSV format. The script prompts the user for AWS profile names and regions, and it logs any errors encountered during the audit.

## Prerequisites

- Python 3.x installed
- AWS CLI configured with the necessary profiles and credentials

## Usage

1. Clone the repository:

    ```bash
    git clone https://github.com/Parthasarathi7722/sg-audit.git
    cd aws-security-group-audit
    ```

2. Install the required Python packages:

    ```bash
    pip install -r requirements.txt
    ```

3. Run the script:

    ```bash
    python security_group_audit.py
    ```

4. Follow the prompts to enter AWS profile names and regions.

5. The script will generate a security group audit report in CSV format (`security_group_audit.csv`). Any errors encountered during the audit will be logged in `error_log.txt`.

## Notes

- The script uses the AWS CLI configuration for authentication. Ensure that the AWS CLI is configured with the necessary profiles and credentials.

- The audit includes both inbound and outbound rules for TCP, UDP, and ICMP traffic.

- The generated CSV file includes the following columns:
    - Profile Name
    - Account ID
    - Region
    - Security Group Name
    - Security Group ID
    - Open Port
    - Protocol
    - Direction (Inbound or Outbound)
    - IP Range

## Error Handling

- Authentication errors: If there are authentication issues for a specific profile or region, the script will log an error in `error_log.txt` and continue with the next profile or region.

- Partial credentials errors: If there are partial credentials issues for a specific profile or region, the script will log an error in `error_log.txt` and continue with the next profile or region.

- Other errors: If other errors occur during the audit, they will be logged in `error_log.txt`.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
