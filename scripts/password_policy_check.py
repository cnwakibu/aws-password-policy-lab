#!/usr/bin/env python3
"""
AWS Password Policy Verification Tool
====================================

This script validates AWS account password policies against SOC 2 and NIST 800-53 compliance requirements.
It generates audit-ready evidence in JSON and CSV formats.

Control Mappings:
- SOC 2 CC6.2: Logical access security measures
- NIST 800-53 IA-5: Authenticator management
"""

import boto3
import json
import csv
import argparse
import sys
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound


class PasswordPolicyChecker:
    """
    A comprehensive AWS password policy compliance checker.
    
    This class handles the retrieval and evaluation of AWS account password policies
    against established security standards and generates compliance reports.
    """
    
    def __init__(self, profile_name=None, region='us-east-1'):
        """
        Initialize the password policy checker.
        
        Args:
            profile_name (str, optional): AWS profile name to use for authentication
            region (str): AWS region to use (default: us-east-1)
        """
        self.profile_name = profile_name
        self.region = region
        # Required AWS permissions: iam:GetAccountPasswordPolicy, iam:ListUsers, 
        # iam:GetLoginProfile, sso:ListInstances (for Identity Center detection)
        self.session = None
        self.iam_client = None
        self.account_id = None
        
        # Compliance standards for password policies
        self.compliance_standards = {
            'minimum_password_length': 12,  # NIST recommends 12+ characters
            'require_symbols': True,        # Special characters required
            'require_numbers': True,        # Numeric characters required
            'require_uppercase': True,      # Uppercase letters required
            'require_lowercase': True,      # Lowercase letters required
            'max_password_age': 90,         # Maximum password age in days
            'password_reuse_prevention': 12, # Prevent reuse of last N passwords
            'allow_users_to_change_password': True,  # Users can change their own passwords
            'hard_expiry': False           # Don't force immediate expiry
        }
        
    def initialize_aws_session(self):
        """
        Initialize AWS session with optional profile support.
        
        Returns:
            bool: True if session initialized successfully, False otherwise
        """
        try:
            # Create session with optional profile
            if self.profile_name:
                print(f"🔐 Initializing AWS session with profile: {self.profile_name}")
                self.session = boto3.Session(profile_name=self.profile_name, region_name=self.region)
            else:
                print("🔐 Initializing AWS session with default credentials")
                self.session = boto3.Session(region_name=self.region)
            
            # Create IAM client
            self.iam_client = self.session.client('iam')
            
            # Get account ID for reporting
            sts_client = self.session.client('sts')
            caller_identity = sts_client.get_caller_identity()
            self.account_id = caller_identity['Account']
            
            print(f"✅ Successfully connected to AWS Account: {self.account_id}")
            return True
            
        except ProfileNotFound:
            print(f"❌ Error: AWS profile '{self.profile_name}' not found")
            print("💡 Available profiles can be listed with: aws configure list-profiles")
            return False
            
        except NoCredentialsError:
            print("❌ Error: No AWS credentials found")
            print("💡 Please configure AWS credentials using: aws configure")
            return False
            
        except Exception as e:
            print(f"❌ Error initializing AWS session: {str(e)}")
            return False
    
    def check_identity_center_usage(self):
        """
        Check if the account is using AWS Identity Center (SSO) for authentication.
        
        Returns:
            dict: Information about Identity Center usage
        """
        try:
            # Check for SSO instances
            sso_admin_client = self.session.client('sso-admin')
            instances = sso_admin_client.list_instances()
            
            if instances['Instances']:
                return {
                    'uses_identity_center': True,
                    'instance_arn': instances['Instances'][0]['InstanceArn'],
                    'identity_store_id': instances['Instances'][0]['IdentityStoreId']
                }
            else:
                return {'uses_identity_center': False}
                
        except ClientError as e:
            if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                # Can't determine - assume traditional IAM
                return {'uses_identity_center': False, 'detection_limited': True}
            return {'uses_identity_center': False}
        except Exception:
            return {'uses_identity_center': False}
    
    def check_iam_user_count(self):
        """
        Check how many IAM users exist in the account.
        
        Returns:
            dict: IAM user statistics
        """
        try:
            paginator = self.iam_client.get_paginator('list_users')
            user_count = 0
            console_users = 0
            
            for page in paginator.paginate():
                for user in page['Users']:
                    user_count += 1
                    # Check if user has console access
                    try:
                        self.iam_client.get_login_profile(UserName=user['UserName'])
                        console_users += 1
                    except ClientError:
                        pass  # No console access
            
            return {
                'total_users': user_count,
                'console_users': console_users,
                'programmatic_only_users': user_count - console_users
            }
        except Exception as e:
            print(f"⚠️  Could not retrieve IAM user statistics: {str(e)}")
            return {'total_users': 0, 'console_users': 0, 'programmatic_only_users': 0}

    def get_password_policy(self):
        """
        Retrieve the AWS account password policy and analyze authentication context.
        
        Returns:
            dict: Password policy configuration or None if not configured
        """
        try:
            print("📋 Analyzing authentication configuration...")
            
            # Check Identity Center usage
            identity_center_info = self.check_identity_center_usage()
            
            # Check IAM user statistics
            iam_stats = self.check_iam_user_count()
            
            print(f"👥 IAM Users: {iam_stats['total_users']} total, {iam_stats['console_users']} with console access")
            
            if identity_center_info['uses_identity_center']:
                print("🔐 Identity Center detected - federated authentication in use")
                print("💡 Password policies are managed in Identity Center, not IAM")
                
                if iam_stats['console_users'] == 0:
                    print("ℹ️  No IAM console users found - IAM password policy not applicable")
                    return {
                        'policy_type': 'identity_center',
                        'iam_policy_applicable': False,
                        'identity_center_arn': identity_center_info.get('instance_arn'),
                        'iam_users': iam_stats
                    }
                else:
                    print(f"⚠️  Found {iam_stats['console_users']} IAM console users - hybrid authentication detected")
            
            # Get the account password policy for IAM users
            print("📋 Retrieving IAM account password policy...")
            response = self.iam_client.get_account_password_policy()
            policy = response['PasswordPolicy']
            
            # Add context information
            policy['policy_type'] = 'iam'
            policy['iam_policy_applicable'] = True
            policy['identity_center_info'] = identity_center_info
            policy['iam_users'] = iam_stats
            
            print("✅ IAM password policy retrieved successfully")
            return policy
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            
            if error_code == 'NoSuchEntity':
                # Check if this is because of Identity Center usage
                identity_center_info = self.check_identity_center_usage()
                iam_stats = self.check_iam_user_count()
                
                if identity_center_info['uses_identity_center'] and iam_stats['console_users'] == 0:
                    print("ℹ️  No IAM password policy needed - using Identity Center for authentication")
                    return {
                        'policy_type': 'identity_center',
                        'iam_policy_applicable': False,
                        'identity_center_arn': identity_center_info.get('instance_arn'),
                        'iam_users': iam_stats,
                        'recommendation': 'Verify password policies in Identity Center console'
                    }
                else:
                    print("⚠️  No IAM password policy configured for this AWS account")
                    return None
                    
            elif error_code == 'AccessDenied':
                print("❌ Access denied: Insufficient permissions to read password policy")
                print("💡 Required permission: iam:GetAccountPasswordPolicy")
                return None
            else:
                print(f"❌ Error retrieving password policy: {e.response['Error']['Message']}")
                return None
                
        except Exception as e:
            print(f"❌ Unexpected error retrieving password policy: {str(e)}")
            return None
    
    def evaluate_policy_compliance(self, policy):
        """
        Evaluate password policy against compliance standards.
        
        Args:
            policy (dict): AWS password policy configuration
            
        Returns:
            dict: Compliance evaluation results
        """
        print("🔍 Evaluating password policy against compliance standards...")
        
        # Initialize evaluation results
        evaluation = {
            'compliant_controls': [],
            'non_compliant_controls': [],
            'missing_controls': [],
            'compliance_score': 0,
            'soc2_cc6_2_status': 'UNKNOWN',
            'nist_ia_5_status': 'UNKNOWN',
            'overall_status': 'UNKNOWN',
            'policy_type': 'unknown'
        }
        
        if policy is None:
            # No policy configured - all controls are missing
            evaluation['missing_controls'] = list(self.compliance_standards.keys())
            evaluation['soc2_cc6_2_status'] = 'NON_COMPLIANT'
            evaluation['nist_ia_5_status'] = 'NON_COMPLIANT'
            evaluation['overall_status'] = 'NON_COMPLIANT'
            evaluation['policy_type'] = 'none'
            return evaluation
        
        # Handle Identity Center scenario
        if policy.get('policy_type') == 'identity_center':
            evaluation['policy_type'] = 'identity_center'
            evaluation['soc2_cc6_2_status'] = 'MANAGED_EXTERNALLY'
            evaluation['nist_ia_5_status'] = 'MANAGED_EXTERNALLY'
            evaluation['overall_status'] = 'IDENTITY_CENTER_MANAGED'
            evaluation['compliance_score'] = 100  # Assume compliant, managed externally
            print("ℹ️  Password policies managed by Identity Center - IAM evaluation not applicable")
            return evaluation
        
        total_controls = len(self.compliance_standards)
        compliant_count = 0
        
        # Evaluate each control
        for control, required_value in self.compliance_standards.items():
            current_value = policy.get(control)
            
            if current_value is None:
                evaluation['missing_controls'].append(control)
                print(f"  ⚠️  Missing: {control}")
            elif self._is_control_compliant(control, current_value, required_value):
                evaluation['compliant_controls'].append({
                    'control': control,
                    'current_value': current_value,
                    'required_value': required_value,
                    'status': 'COMPLIANT'
                })
                compliant_count += 1
                print(f"  ✅ Compliant: {control} (current: {current_value}, required: {required_value})")
            else:
                evaluation['non_compliant_controls'].append({
                    'control': control,
                    'current_value': current_value,
                    'required_value': required_value,
                    'status': 'NON_COMPLIANT'
                })
                print(f"  ❌ Non-compliant: {control} (current: {current_value}, required: {required_value})")
        
        # Calculate compliance score
        evaluation['compliance_score'] = round((compliant_count / total_controls) * 100, 2)
        
        # Determine overall compliance status
        if evaluation['compliance_score'] >= 90:
            evaluation['overall_status'] = 'COMPLIANT'
            evaluation['soc2_cc6_2_status'] = 'COMPLIANT'
            evaluation['nist_ia_5_status'] = 'COMPLIANT'
        elif evaluation['compliance_score'] >= 70:
            evaluation['overall_status'] = 'PARTIALLY_COMPLIANT'
            evaluation['soc2_cc6_2_status'] = 'PARTIALLY_COMPLIANT'
            evaluation['nist_ia_5_status'] = 'PARTIALLY_COMPLIANT'
        else:
            evaluation['overall_status'] = 'NON_COMPLIANT'
            evaluation['soc2_cc6_2_status'] = 'NON_COMPLIANT'
            evaluation['nist_ia_5_status'] = 'NON_COMPLIANT'
        
        print(f"📊 Compliance Score: {evaluation['compliance_score']}% ({compliant_count}/{total_controls} controls)")
        
        return evaluation
    
    def _is_control_compliant(self, control, current_value, required_value):
        """
        Check if a specific control meets compliance requirements.
        
        Args:
            control (str): Control name
            current_value: Current policy value
            required_value: Required value for compliance
            
        Returns:
            bool: True if compliant, False otherwise
        """
        if isinstance(required_value, bool):
            return current_value == required_value
        elif isinstance(required_value, int):
            if control in ['minimum_password_length', 'password_reuse_prevention']:
                # For these controls, current value should be >= required
                return current_value >= required_value
            elif control == 'max_password_age':
                # For max age, current value should be <= required
                return current_value <= required_value
            else:
                return current_value == required_value
        else:
            return current_value == required_value
    
    def generate_recommendations(self, evaluation, policy):
        """
        Generate remediation recommendations for non-compliant controls.
        
        Args:
            evaluation (dict): Compliance evaluation results
            policy (dict): Current password policy
            
        Returns:
            list: List of remediation recommendations
        """
        recommendations = []
        
        if policy is None:
            recommendations.append({
                'priority': 'HIGH',
                'control': 'password_policy',
                'issue': 'No password policy configured',
                'recommendation': 'Create an AWS account password policy with minimum security requirements',
                'aws_cli_command': 'aws iam put-account-password-policy --minimum-password-length 12 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 12 --allow-users-to-change-password'
            })
            return recommendations
        
        # Generate specific recommendations for non-compliant controls
        for control_info in evaluation['non_compliant_controls']:
            control = control_info['control']
            current = control_info['current_value']
            required = control_info['required_value']
            
            if control == 'minimum_password_length':
                recommendations.append({
                    'priority': 'HIGH',
                    'control': control,
                    'issue': f'Password length too short (current: {current}, required: {required})',
                    'recommendation': f'Increase minimum password length to {required} characters',
                    'aws_cli_command': f'aws iam put-account-password-policy --minimum-password-length {required}'
                })
            elif control == 'max_password_age':
                recommendations.append({
                    'priority': 'MEDIUM',
                    'control': control,
                    'issue': f'Password age too long (current: {current}, required: ≤{required})',
                    'recommendation': f'Reduce maximum password age to {required} days',
                    'aws_cli_command': f'aws iam put-account-password-policy --max-password-age {required}'
                })
            elif control.startswith('require_'):
                feature = control.replace('require_', '').replace('_', ' ')
                recommendations.append({
                    'priority': 'HIGH',
                    'control': control,
                    'issue': f'{feature.title()} not required in passwords',
                    'recommendation': f'Enable requirement for {feature} in passwords',
                    'aws_cli_command': f'aws iam put-account-password-policy --{control.replace("_", "-")}'
                })
        
        # Add recommendations for missing controls
        for control in evaluation['missing_controls']:
            required = self.compliance_standards[control]
            recommendations.append({
                'priority': 'HIGH',
                'control': control,
                'issue': f'Control not configured',
                'recommendation': f'Configure {control} with value: {required}',
                'aws_cli_command': f'aws iam put-account-password-policy --{control.replace("_", "-")} {required}'
            })
        
        return recommendations
    
    def generate_json_report(self, policy, evaluation, recommendations):
        """
        Generate comprehensive JSON report for audit evidence.
        
        Args:
            policy (dict): Password policy configuration
            evaluation (dict): Compliance evaluation results
            recommendations (list): Remediation recommendations
            
        Returns:
            dict: Complete JSON report
        """
        report = {
            'metadata': {
                'report_type': 'AWS Password Policy Compliance Assessment',
                'account_id': self.account_id,
                'assessment_date': datetime.now(timezone.utc).isoformat(),
                'aws_region': self.region,
                'aws_profile': self.profile_name,
                'tool_version': '1.0',
                'standards_evaluated': ['SOC 2 CC6.2', 'NIST 800-53 IA-5']
            },
            'password_policy': policy if policy else {},
            'compliance_standards': self.compliance_standards,
            'evaluation': evaluation,
            'recommendations': recommendations,
            'summary': {
                'policy_configured': policy is not None,
                'compliance_score': evaluation['compliance_score'],
                'total_controls': len(self.compliance_standards),
                'compliant_controls': len(evaluation['compliant_controls']),
                'non_compliant_controls': len(evaluation['non_compliant_controls']),
                'missing_controls': len(evaluation['missing_controls']),
                'high_priority_recommendations': len([r for r in recommendations if r['priority'] == 'HIGH'])
            }
        }
        
        return report
    
    def save_json_report(self, report, filename='password_policy_compliance_report.json'):
        """
        Save JSON report to file.
        
        Args:
            report (dict): JSON report data
            filename (str): Output filename
        """
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"📄 JSON report saved: {filename}")
        except Exception as e:
            print(f"❌ Error saving JSON report: {str(e)}")
    
    def save_csv_report(self, evaluation, recommendations, filename='password_policy_compliance_summary.csv'):
        """
        Save CSV summary report for audit teams.
        
        Args:
            evaluation (dict): Compliance evaluation results
            recommendations (list): Remediation recommendations
            filename (str): Output filename
        """
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Header information
                writer.writerow(['AWS Password Policy Compliance Summary'])
                writer.writerow(['Account ID', self.account_id])
                writer.writerow(['Assessment Date', datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')])
                writer.writerow(['Compliance Score', f"{evaluation['compliance_score']}%"])
                writer.writerow(['Overall Status', evaluation['overall_status']])
                writer.writerow([])
                
                # Control compliance details
                writer.writerow(['Control Name', 'Status', 'Current Value', 'Required Value', 'Priority'])
                
                # Compliant controls
                for control in evaluation['compliant_controls']:
                    writer.writerow([
                        control['control'],
                        'COMPLIANT',
                        control['current_value'],
                        control['required_value'],
                        'N/A'
                    ])
                
                # Non-compliant controls
                for control in evaluation['non_compliant_controls']:
                    writer.writerow([
                        control['control'],
                        'NON_COMPLIANT',
                        control['current_value'],
                        control['required_value'],
                        'HIGH'
                    ])
                
                # Missing controls
                for control in evaluation['missing_controls']:
                    required_value = self.compliance_standards[control]
                    writer.writerow([
                        control,
                        'MISSING',
                        'Not Configured',
                        required_value,
                        'HIGH'
                    ])
                
                writer.writerow([])
                writer.writerow(['Remediation Recommendations'])
                writer.writerow(['Priority', 'Control', 'Issue', 'Recommendation'])
                
                for rec in recommendations:
                    writer.writerow([
                        rec['priority'],
                        rec['control'],
                        rec['issue'],
                        rec['recommendation']
                    ])
            
            print(f"📊 CSV report saved: {filename}")
            
        except Exception as e:
            print(f"❌ Error saving CSV report: {str(e)}")
    
    def run_assessment(self):
        """
        Execute the complete password policy compliance assessment.
        
        Returns:
            bool: True if assessment completed successfully, False otherwise
        """
        print("🚀 Starting AWS Password Policy Compliance Assessment")
        print("=" * 60)
        
        # Initialize AWS session
        if not self.initialize_aws_session():
            return False
        
        # Retrieve password policy
        policy = self.get_password_policy()
        
        # Evaluate compliance
        evaluation = self.evaluate_policy_compliance(policy)
        
        # Generate recommendations
        recommendations = self.generate_recommendations(evaluation, policy)
        
        # Generate reports
        print("\n📋 Generating compliance reports...")
        json_report = self.generate_json_report(policy, evaluation, recommendations)
        
        # Save reports
        self.save_json_report(json_report)
        self.save_csv_report(evaluation, recommendations)
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 ASSESSMENT SUMMARY")
        print("=" * 60)
        print(f"Account ID: {self.account_id}")
        print(f"Compliance Score: {evaluation['compliance_score']}%")
        print(f"Overall Status: {evaluation['overall_status']}")
        print(f"SOC 2 CC6.2: {evaluation['soc2_cc6_2_status']}")
        print(f"NIST IA-5: {evaluation['nist_ia_5_status']}")
        print(f"High Priority Recommendations: {len([r for r in recommendations if r['priority'] == 'HIGH'])}")
        
        if evaluation['overall_status'] == 'COMPLIANT':
            print("✅ Password policy meets compliance requirements!")
        else:
            print("⚠️  Password policy requires attention - see recommendations above")
        
        return True


def main():
    """
    Main function to handle command-line arguments and execute the assessment.
    """
    parser = argparse.ArgumentParser(
        description='AWS Password Policy Compliance Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python password_policy_checker.py
  python password_policy_checker.py --profile production
  python password_policy_checker.py --profile dev --region us-west-2

This tool evaluates AWS account password policies against SOC 2 and NIST 800-53 standards.
        """
    )
    
    parser.add_argument(
        '--profile',
        type=str,
        help='AWS profile name to use for authentication (optional)'
    )
    
    parser.add_argument(
        '--region',
        type=str,
        default='us-east-1',
        help='AWS region to use (default: us-east-1)'
    )
    
    parser.add_argument(
        '--output-dir',
        type=str,
        default='.',
        help='Directory to save output files (default: current directory)'
    )
    
    args = parser.parse_args()
    
    # Create checker instance
    checker = PasswordPolicyChecker(
        profile_name=args.profile,
        region=args.region
    )
    
    # Run assessment
    success = checker.run_assessment()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()

