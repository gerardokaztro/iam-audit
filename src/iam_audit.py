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
import requests

S3_BUCKET = os.environ.get("S3_BUCKET")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION")

# Este script audita IAM Users con Access Keys activas en una o múltiples cuentas AWS

def upload_to_s3(local_path, s3_key):
    """Sube un archivo local al bucket S3 de reportes"""
    bucket = os.environ.get("S3_BUCKET")
    region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    
    s3 = boto3.client("s3", region_name=region)
    s3.upload_file(local_path, bucket, s3_key)
    print(f"[S3] Subido: s3://{bucket}/{s3_key}")
    return bucket, s3_key

def generate_presigned_url(bucket, s3_key, expiration=172800):
    """Genera una presigned URL válida por 48 horas (172800 segundos)"""
    region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    s3 = boto3.client("s3", region_name=region)
    
    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": s3_key},
        ExpiresIn=expiration
    )
    print(f"[S3] Presigned URL generada — válida 48hs")
    return url

def notify_slack(presigned_url, findings_count, accounts_count, high_risk_count):
    """Envía notificación a Slack con resumen y URL del dashboard"""
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        print("[Slack] SLACK_WEBHOOK_URL no definida — omitiendo notificación")
        return

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔍 IAM Security Audit — Reporte semanal listo"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Cuentas auditadas:*\n{accounts_count}"},
                    {"type": "mrkdwn", "text": f"*Access Keys encontradas:*\n{findings_count}"},
                    {"type": "mrkdwn", "text": f"*Hallazgos de alto riesgo:*\n{high_risk_count}"}
                ]
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "📊 Ver dashboard"},
                        "url": presigned_url,
                        "style": "primary"
                    }
                ]
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": "⏱ URL válida por 48 horas"}
                ]
            }
        ]
    }

    response = requests.post(webhook_url, json=payload)
    if response.status_code == 200:
        print("[Slack] Notificación enviada correctamente")
    else:
        print(f"[Slack] Error al enviar notificación: {response.status_code}")

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
    parser.add_argument('--profile', required=False, help='AWS CLI profile name (local only)')
    parser.add_argument('--role', required=False, 
                        default=os.environ.get("AUDIT_ROLE_NAME", "AWSControlTowerExecution"),
                        help='Role name to assume in each account')
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

    # Local: usa profile. Fargate: boto3 usa el Task Role automáticamente
    if args.profile:
        session = boto3.Session(profile_name=args.profile)
    else:
        session = boto3.Session()

    # En Fargate, asumir rol en Management para listar cuentas
    mgmt_account_id = os.environ.get("MANAGEMENT_ACCOUNT_ID")
    if mgmt_account_id:
        credentials = assume_role(
            session,
            mgmt_account_id,
            "iam-audit-org-reader",
            "OrgReader"
        )
        org_session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        org_client = org_session.client('organizations')
    else:
        org_client = session.client('organizations')

    accounts = get_accounts(org_client)
    
    all_findings = []

    cloudtrail_events = get_cloudtrail_events(
        org_session if mgmt_account_id else session,
        accounts,
        args.role
    )

    all_root_findings = []
    
    for account in accounts:
        print(f"Auditando cuenta: {account['name']} ({account['id']})")
        try:
            credentials = assume_role(
                org_session if mgmt_account_id else session,
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
            root_findings = get_root_findings(iam_client, account['id'], account['name'])
            all_root_findings.extend(root_findings)
            all_findings.extend(findings)
        except Exception as e:
            print(f"Error en cuenta {account['name']}: {e}")

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

    # Upload a S3 y notificación Slack (solo en entorno Fargate)
    if os.environ.get("S3_BUCKET"):
        from datetime import date
        today = date.today().strftime("%Y-%m-%d")
        s3_key = f"reports/{today}/{os.path.basename(html_filename)}"
        
        bucket, key = upload_to_s3(html_filename, s3_key)
        presigned_url = generate_presigned_url(bucket, key)
        
        high_risk_count = sum(1 for f in findings if f.get("risk_score", 0) >= 7)
        
        notify_slack(
            presigned_url=presigned_url,
            findings_count=len(findings),
            accounts_count=len(root_findings),
            high_risk_count=high_risk_count
        )
    else:
        print("[Info] S3_BUCKET no definida — modo local, omitiendo upload y notificación")

    # Servir el dashboard (solo en modo local)
    if not os.environ.get("S3_BUCKET"):
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
        sys.stdout.flush()

        with socketserver.TCPServer(("", PORT), Handler) as httpd:
            httpd.serve_forever()
    else:
        print("\nAuditoría completada. Reporte disponible en S3.")