import boto3
import csv
import argparse
from datetime import datetime, timedelta

# Este script audita IAM Users con Access Keys activas en una o múltiples cuentas AWS

def get_accounts(org_client):
    """Retorna lista de todas las cuentas activas en la organización"""
    accounts = []
    paginator = org_client.get_paginator('list_accounts')
    for page in paginator.paginate():
        for account in page['Accounts']:
            if account['Status'] == 'ACTIVE':
                accounts.append({
                    'id': account['Id'],
                    'name': account['Name']
                })
    return accounts

def assume_role(session, account_id, role_name, session_name):
    """Asume un rol en otra cuenta y retorna credenciales temporales"""
    sts_client = session.client('sts')
    response = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
        RoleSessionName=session_name
    )
    return response['Credentials']

def get_iam_users_with_keys(iam_client, account_id, account_name):
    """Lista usuarios IAM con access keys activas en una cuenta"""
    findings = []
    paginator = iam_client.get_paginator('list_users')
    
    for page in paginator.paginate():
        for user in page['Users']:
            keys_response = iam_client.list_access_keys(
                UserName=user['UserName']
            )
            mfa_response = iam_client.list_mfa_devices(
                UserName=user['UserName']
            )
            mfa_devices = mfa_response['MFADevices']

            if len(mfa_devices) == 0:
                mfa_status = 'None'
            else:
                serial = mfa_devices[0]['SerialNumber']
                if 'virtual' in serial.lower():
                    mfa_status = 'Virtual'
                else:
                    mfa_status = 'Hardware'
            # Verificar el estado de la contraseña
            try:
                password_response = iam_client.get_login_profile(UserName=user['UserName'])
                password_status = 'Configurada'
            except iam_client.exceptions.NoSuchEntityException:
                password_status = 'No configurada'

            for key in keys_response['AccessKeyMetadata']:
                # Primero calculás los valores
                last_used_response = iam_client.get_access_key_last_used(
                    AccessKeyId=key['AccessKeyId']
                )
                last_used = last_used_response['AccessKeyLastUsed']
                last_used_date = str(last_used.get('LastUsedDate', 'Nunca utilizada'))
                service_name = last_used.get('ServiceName', 'N/A')

                # Después los metés al diccionario ya calculados
                findings.append({
                    'account_id': account_id,
                    'account_name': account_name,
                    'username': user['UserName'],
                    'password_status': password_status,
                    'password_last_used': str(user.get('PasswordLastUsed', 'Nunca')),
                    'access_key_id': key['AccessKeyId'],
                    'status': key['Status'],
                    'created_date': str(key['CreateDate']),
                    'last_used_date': last_used_date,
                    'service_name': service_name,
                    'mfa_status': mfa_status
                })
    return findings

def get_cloudtrail_events(session, accounts, role_name, start_date, end_date):
    """Obtiene eventos IAM de CloudTrail usando lookup_events por cuenta"""
    all_events = []
    event_names = ['DeleteUser', 'DeleteAccessKey', 'DeleteLoginProfile', 'CreateAccessKey', 'CreateUser']

    for account in accounts:
        print(f"  Consultando CloudTrail en cuenta: {account['name']} ({account['id']})")
        try:
            credentials = assume_role(session, account['id'], role_name, 'CloudTrailAudit')
            ct_client = boto3.client(
                'cloudtrail',
                region_name='us-east-1',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            for event_name in event_names:
                paginator = ct_client.get_paginator('lookup_events')
                for page in paginator.paginate(
                    LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': event_name}],
                    StartTime=start_date,
                    EndTime=end_date
                ):
                    for event in page.get('Events', []):
                        all_events.append({
                            'eventName': event['EventName'],
                            'eventTime': str(event['EventTime']),
                            'username': event.get('Username', 'N/A'),
                            'account_id': account['id'],
                            'account_name': account['name'],
                            'resources': [r.get('ResourceName', '') for r in event.get('Resources', [])]
                        })
        except Exception as e:
            print(f"  Error en CloudTrail cuenta {account['name']}: {e}")

    return all_events

def parse_args():
    parser = argparse.ArgumentParser(description='IAM Security Audit Tool')
    parser.add_argument('--profile', required=True, help='AWS CLI profile name')
    parser.add_argument('--role', required=True, help='Role name to assume in each account')
    return parser.parse_args()

def main():
    """Función principal que orquesta la auditoría"""
    args = parse_args()
    session = boto3.Session(profile_name=args.profile)
    org_client = session.client('organizations')
    accounts = get_accounts(org_client)
    
    all_findings = []

    start_date = datetime(2026, 2, 18)
    end_date = datetime.now()
    cloudtrail_events = get_cloudtrail_events(
        session,
        accounts,
        args.role,
        start_date,
        end_date
    )
    
    for account in accounts:
        print(f"Auditando cuenta: {account['name']} ({account['id']})")
        try:
            credentials = assume_role(
                session,
                account['id'],
                args.role,
                'SecurityAudit'
            )
            iam_client = boto3.client(
                'iam',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            findings = get_iam_users_with_keys(iam_client, account['id'], account['name'])
            all_findings.extend(findings)
        except Exception as e:
            print(f"Error en cuenta {account['name']}: {e}")
    
    return all_findings, cloudtrail_events

if __name__ == "__main__":
    findings, cloudtrail_events = main()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"iam_audit_report_{timestamp}.csv"
    
    if findings:
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['account_id', 'account_name', 'username',
                            'password_status', 'password_last_used',
                            'access_key_id', 'status', 'created_date', 
                            'last_used_date', 'service_name', 'mfa_status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(findings)
        
        print(f"\nTotal de Access Keys encontradas: {len(findings)}")
        print(f"Reporte exportado: {filename}")
    else:
        print("\nNo se encontraron Access Keys.")

    # Imprimir eventos de CloudTrail
    for event in cloudtrail_events:
        print(f"{event['eventTime']} - {event['eventName']} - Usuario: {event['username']} - Cuenta: {event['account_name']}")
        print(f"  Recursos afectados: {event['resources']}")
    print(f"\nTotal de eventos CloudTrail encontrados: {len(cloudtrail_events)}")
    # Guardar reporte en CSV
    print("\nGenerando reporte CSV...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Guardar eventos de CloudTrail en CSV
    ct_filename = f"cloudtrail_events_{timestamp}.csv"
    if cloudtrail_events:
        with open(ct_filename, 'w', newline='') as csvfile:
            fieldnames = ['eventTime', 'eventName', 'username', 'account_id', 'account_name', 'resources']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for event in cloudtrail_events:
                # Convertir lista de recursos a string para CSV
                event['resources'] = ', '.join(event['resources'])
                writer.writerow(event)

        print(f"Reporte de eventos CloudTrail exportado: {ct_filename}")