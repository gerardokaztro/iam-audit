import boto3
import csv
import argparse
from datetime import datetime, timedelta
import io
import json
import os
import http.server
import socketserver
import webbrowser
import sys

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

def get_cloudtrail_events(session, accounts, role_name):
    """Obtiene eventos IAM de CloudTrail usando lookup_events por cuenta"""
    all_events = []
    event_names = ['DeleteUser', 'DeleteAccessKey', 'DeleteLoginProfile', 'CreateAccessKey', 'CreateUser', 'ConsoleLogin']

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
                ):
                    for event in page.get('Events', []):
                        # Ahora sí existe event, podés parsear
                        if event_name == 'ConsoleLogin':
                            ct_event = json.loads(event.get('CloudTrailEvent', '{}'))
                            user_identity = ct_event.get('userIdentity', {})
                            if user_identity.get('type') != 'Root':
                                continue  # no es root, saltá este evento

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

def get_root_findings(iam_client, account_id, account_name):
    """Obtiene información sobre el usuario root"""
    findings = []
    response = iam_client.get_account_summary()
    summary = response['SummaryMap']

    mfa_enabled = summary.get('AccountMFAEnabled', 0) == 1
    access_key_present = summary.get('AccountAccessKeysPresent', 0) == 1

    findings.append({
        'account_id': account_id,
        'account_name': account_name,
        'mfa_enabled': mfa_enabled,
        'access_key_present': access_key_present,
        'root_last_login': 'Pendiente'
    })
    return findings
    
def main():
    """Función principal que orquesta la auditoría"""
    args = parse_args()
    session = boto3.Session(profile_name=args.profile)
    org_client = session.client('organizations')
    accounts = get_accounts(org_client)
    
    all_findings = []

    cloudtrail_events = get_cloudtrail_events(
        session,
        accounts,
        args.role
    )

    all_root_findings = []
    
    for account in accounts:
        print(f"Auditando cuenta: {account['name']} ({account['id']})")
        try:
            credentials = assume_role(session, account['id'], args.role, 'SecurityAudit')
            iam_client = boto3.client(
                'iam',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            findings = get_iam_users_with_keys(iam_client, account['id'], account['name'])
            root_findings = get_root_findings(iam_client, account['id'], account['name'])
            all_root_findings.extend(root_findings)
            all_findings.extend(findings)
        except Exception as e:
            print(f"Error en cuenta {account['name']}: {e}")

    # Cruzar DESPUÉS del for — fuera del try/except
    for root_finding in all_root_findings:
        root_logins = [
            e for e in cloudtrail_events
            if e['eventName'] == 'ConsoleLogin'
            and e['account_id'] == root_finding['account_id']
        ]
        if root_logins:
            root_logins.sort(key=lambda x: x['eventTime'], reverse=True)
            root_finding['root_last_login'] = root_logins[0]['eventTime'].split(' ')[0]
        else:
            root_finding['root_last_login'] = 'Nunca'

    return all_findings, cloudtrail_events, all_root_findings

def generate_html(findings, cloudtrail_events, template_path, root_findings):
    # Convierte findings a CSV string
    if findings:
        output = io.StringIO()
        fieldnames = ['account_id', 'account_name', 'username',
                      'password_status', 'password_last_used',
                      'access_key_id', 'status', 'created_date',
                      'last_used_date', 'service_name', 'mfa_status']
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)
        iam_csv_string = output.getvalue()
        output.close()
    else:
        iam_csv_string = ""

    # Convierte findings a CSV string
    if root_findings:
        output = io.StringIO()
        fieldnames = ['account_id', 'account_name', 'mfa_enabled', 'access_key_present', 'root_last_login']
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(root_findings)

        root_csv_string = output.getvalue()
        output.close()

    else:
        root_csv_string = ""

    # Convierte cloudtrail_events a CSV string
    if cloudtrail_events:
        output = io.StringIO()
        fieldnames = ['eventTime', 'eventName', 'username', 'account_id', 'account_name', 'resources']
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for event in cloudtrail_events:
            # Convertir lista de recursos a string para CSV
            resources = event['resources'] if isinstance(event['resources'], str) else ', '.join(event['resources'])
            writer.writerow({**event, 'resources': resources})
        ct_csv_string = output.getvalue()
        output.close()
    else:
        ct_csv_string = ""

    # Lee el template HTML
    with open(template_path, 'r') as file:
        template = file.read()

    # Reemplaza los placeholders
    html = template.replace("%%IAM_DATA%%", iam_csv_string)
    html = html.replace("%%CT_DATA%%", ct_csv_string)
    html = html.replace("%%ROOT_DATA%%", root_csv_string)

    return html

if __name__ == "__main__":
    findings, cloudtrail_events, root_findings = main()
    
    # Generar resumen de findings IAM Users
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs("output", exist_ok=True)
    filename = f"output/iam_audit_report_{timestamp}.csv"
    
    if findings:
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['account_id', 'account_name', 'username',
                            'password_status', 'password_last_used',
                            'access_key_id', 'status', 'created_date', 
                            'last_used_date', 'service_name', 'mfa_status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(findings)
        # Imprimir resumen de findings
        print(f"\nTotal de Access Keys encontradas: {len(findings)}")
        print(f"Reporte exportado: {filename}")
    else:
        print("\nNo se encontraron Access Keys.")

    # Generar reporte de findings Roots
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    root_filename = f"output/root_audit_report_{timestamp}.csv"

    if root_findings:
        with open(root_filename, "w", newline='') as csvfile:
            fieldnames = ['account_id', 'account_name', 'mfa_enabled', 'access_key_present', 'root_last_login']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(root_findings)
            print(f"Reporte root exportado: {root_filename}")

    # Imprimir eventos de CloudTrail
    print(f"\nTotal de eventos CloudTrail encontrados: {len(cloudtrail_events)}")
    # Guardar reporte en CSV
    print("\nGenerando reporte CSV...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Guardar eventos de CloudTrail en CSV
    ct_filename = f"output/cloudtrail_events_{timestamp}.csv"
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

    print("Auditoria completada.")

    # Generar reporte HTML
    print("\nGenerando reporte HTML...")
    template_path = os.path.join(os.path.dirname(__file__), 'template.html')
    html_content = generate_html(findings, cloudtrail_events, template_path, root_findings)
    html_filename = f"output/iam_audit_report_{timestamp}.html"
    with open(html_filename, 'w') as f:
        f.write(html_content)
    print(f"Reporte HTML generado: {html_filename}")

    # Servir el dashboard
    os.chdir("output")
    PORT = 8000
    html_basename = html_filename.split('/')[-1]

    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/':
                self.send_response(302)
                self.send_header('Location', f'/{html_basename}')
                self.end_headers()
            else:
                super().do_GET()
        
        def log_message(self, format, *args):
            pass

    print(f"\n{'='*50}")
    print(f"  Auditoría completada.")
    print(f"  Dashboard listo en: http://localhost:{PORT}")
    print(f"  Presioná Ctrl+C para detener")
    print(f"{'='*50}\n")
    sys.stdout.flush()  # ← fuerza que aparezca en terminal

    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        httpd.serve_forever()