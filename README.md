# 🔍 iam-audit

> Audita IAM Users, Access Keys y cuentas root en toda una AWS Organization multicuenta — en minutos, con mínimo privilegio. Dashboard HTML interactivo incluido. Modo programado vía ECS Fargate con notificación a Slack.

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![AWS](https://img.shields.io/badge/AWS-boto3-FF9900?style=flat&logo=amazonaws&logoColor=white)](https://boto3.amazonaws.com)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat&logo=docker&logoColor=white)](https://hub.docker.com/r/gerardokaztro/iam-audit)
[![Terraform](https://img.shields.io/badge/Terraform-1.14+-7B42BC?style=flat&logo=terraform&logoColor=white)](https://terraform.io)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![Author](https://img.shields.io/badge/AWS-Security%20Hero-FF9900?style=flat&logo=amazonaws&logoColor=white)](https://aws.amazon.com/developer/community/heroes/)

---

## ¿Qué hace?

`iam-audit` recorre automáticamente todas las cuentas activas de tu AWS Organization, asume un rol de auditoría en cada una, y produce un reporte consolidado con:

- ✅ Todas las **Access Keys** por usuario — estado, fecha de creación, último uso y servicio
- ✅ Estado de **MFA** por usuario (Virtual, Hardware, o ausente)
- ✅ Acceso a **consola** — login profile, último uso, rotación de password
- ✅ **Root account** por cuenta — MFA habilitado, access keys activas, último login vía CloudTrail
- ✅ **Risk scoring** por usuario — priorización automática de hallazgos
- ✅ **Tendencia de remediación** vía CloudTrail — tracking de acciones correctivas en el tiempo
- ✅ **Dashboard HTML interactivo** con filtros globales, gráficos y tabla de hallazgos

Todo sin crear credenciales de largo plazo adicionales. El script usa `sts:AssumeRole` — credenciales temporales que expiran solas.

---

## ¿Por qué existe esto?

En entornos multicuenta, nadie tiene una vista consolidada de credenciales. Las Access Keys viejas no aparecen en ningún dashboard por defecto. No generan alertas. No molestan a nadie. Simplemente esperan.

Este script las encuentra.

> Probado en una AWS Organization real con más de 20 cuentas activas. Encontré una Access Key creada en 2018 — activa en producción. Lee el post completo → [roadtocloudsec.hashnode.dev](https://roadtocloudsec.hashnode.dev/encontre-access-key-2018-activa-produccion-python-boto3)

---

## Modos de uso

| | **Local** | **Fargate** |
|---|---|---|
| **Cómo corre** | Docker en tu máquina | ECS Fargate — automático |
| **Trigger** | Manual | EventBridge — lunes 9am |
| **Output** | `./output/` local + `localhost:8000` | S3 + Slack con presigned URL |
| **Infraestructura** | Ninguna | Terraform en cuenta Security |
| **Ideal para** | Auditorías puntuales | Monitoreo continuo semanal |

---

## Prerequisitos

### Modo Local

- Docker instalado
- AWS credentials configuradas localmente (`~/.aws`)
- Un rol de auditoría desplegado en cada cuenta miembro con permisos de lectura sobre IAM y CloudTrail
- Un rol en la cuenta Management con `organizations:ListAccounts` y `sts:AssumeRole` hacia las cuentas hijas

### Modo Fargate

Todo lo anterior, más:

- Terraform >= 1.14.0
- AWS CLI con acceso admin a tu cuenta Security
- Una Slack webhook URL — [cómo crearla](https://api.slack.com/messaging/webhooks)
- Un bucket S3 para el Terraform state (se crea manualmente una sola vez — ver instrucciones abajo)
- El rol `iam-audit-org-reader` en la cuenta Management (se crea manualmente una sola vez — ver instrucciones abajo)

---

## Inicio rápido — Modo Local

### Opción A — Docker Hub (recomendado)

Sin clonar el repo, sin instalar Python, sin instalar dependencias.

```bash
docker run --rm \
  -v ~/.aws:/root/.aws \
  -v $(pwd)/output:/app/output \
  -p 8000:8000 \
  gerardokaztro/iam-audit \
  --profile YOUR-AWS-PROFILE \
  --role YOUR-AUDIT-ROLE
```

Imagen disponible en: [hub.docker.com/r/gerardokaztro/iam-audit](https://hub.docker.com/r/gerardokaztro/iam-audit)

### Opción B — Build local

```bash
git clone https://github.com/gerardokaztro/iam-audit
cd iam-audit
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t iam-audit .
docker run --rm \
  -v ~/.aws:/root/.aws \
  -v $(pwd)/output:/app/output \
  -p 8000:8000 \
  iam-audit \
  --profile YOUR-AWS-PROFILE \
  --role YOUR-AUDIT-ROLE
```

> **Nota:** Si buildeas en Mac con Apple Silicon (arm64) y querés correr en Fargate, usá `--platform linux/amd64,linux/arm64` para generar una imagen multi-platform.

### Opción C — Sin Docker

```bash
pip install -r requirements.txt
python src/iam_audit.py --profile YOUR-AWS-PROFILE --role YOUR-AUDIT-ROLE
```

Cuando el scan termina, abrí el browser en `http://localhost:8000` para ver el dashboard interactivo.
Presioná `Ctrl+C` para detener el servidor.

---

## Inicio rápido — Modo Fargate

### Paso 1 — Crear el bucket de Terraform state (una sola vez)

```bash
# Reemplazá ACCOUNT-ID con el ID de tu cuenta Security
aws s3api create-bucket \
  --bucket iam-audit-tfstate-ACCOUNT-ID \
  --profile YOUR-SECURITY-PROFILE

aws s3api put-bucket-versioning \
  --bucket iam-audit-tfstate-ACCOUNT-ID \
  --versioning-configuration Status=Enabled \
  --profile YOUR-SECURITY-PROFILE

aws s3api put-public-access-block \
  --bucket iam-audit-tfstate-ACCOUNT-ID \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  --profile YOUR-SECURITY-PROFILE
```

> **Nota:** Si tu cuenta Security está en `us-east-1`, omitir `--region` es correcto — la API de S3 tiene un comportamiento particular con esa región.

### Paso 2 — Crear el rol de auditoría en la cuenta Management (una sola vez)

Este rol permite que el Task Role en la cuenta Security liste las cuentas de la organización y luego asuma el rol de auditoría en cada cuenta hija.

```bash
# Reemplazá SECURITY-ACCOUNT-ID con el ID de tu cuenta Security
aws iam create-role \
  --role-name iam-audit-org-reader \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::SECURITY-ACCOUNT-ID:role/iam-audit-task-role"
      },
      "Action": "sts:AssumeRole"
    }]
  }' \
  --profile YOUR-MANAGEMENT-PROFILE

aws iam attach-role-policy \
  --role-name iam-audit-org-reader \
  --policy-arn arn:aws:iam::aws:policy/AWSOrganizationsReadOnlyAccess \
  --profile YOUR-MANAGEMENT-PROFILE

aws iam put-role-policy \
  --role-name iam-audit-org-reader \
  --policy-name assume-member-accounts \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/YOUR-AUDIT-ROLE-NAME"
    }]
  }' \
  --profile YOUR-MANAGEMENT-PROFILE
```

### Paso 3 — Configurar y desplegar Terraform

```bash
cd infra
cp backend.hcl.example backend.hcl
cp terraform.tfvars.example terraform.tfvars
```

Editá `backend.hcl` con los datos de tu bucket de state:

```hcl
bucket  = "iam-audit-tfstate-ACCOUNT-ID"
key     = "iam-audit/terraform.tfstate"
region  = "us-east-1"
profile = "YOUR-SECURITY-PROFILE"
```

Editá `terraform.tfvars` con tus valores:

```hcl
aws_region              = "us-east-1"
aws_profile             = "YOUR-SECURITY-PROFILE"
environment             = "production"
tfstate_bucket          = "iam-audit-tfstate-ACCOUNT-ID"
reports_bucket_name     = "iam-audit-reports-ACCOUNT-ID"
management_account_id   = "YOUR-MANAGEMENT-ACCOUNT-ID"
audit_role_name         = "YOUR-AUDIT-ROLE-NAME"
slack_webhook_url       = "https://hooks.slack.com/services/XXX/YYY/ZZZ"
```

Desplegá:

```bash
terraform init -backend-config=backend.hcl
terraform plan
terraform apply
```

La auditoría correrá automáticamente cada lunes a las 9am (Lima, UTC-5). Para disparar manualmente:

```bash
aws ecs run-task \
  --cluster iam-audit-cluster \
  --task-definition iam-audit \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[SUBNET-ID],securityGroups=[SG-ID],assignPublicIp=ENABLED}" \
  --profile YOUR-SECURITY-PROFILE
```

---

## Configuración de permisos

El rol en cada cuenta hija necesita permisos de lectura sobre IAM y CloudTrail:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListMFADevices",
        "iam:GetLoginProfile",
        "iam:GetAccountSummary",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

> Si usás AWS Control Tower, el rol `AWSControlTowerExecution` ya existe en todas las cuentas y podés usarlo como punto de partida. Verificá que su trust policy permita ser asumido desde tu cuenta Management — que es desde donde `iam-audit-org-reader` asume roles en las cuentas hijas.

---

## Output

**Modo Local** — archivos guardados en `./output/`:

| Archivo | Contenido |
|---|---|
| `iam_audit_report_TIMESTAMP.html` | Dashboard interactivo con filtros, gráficos y tabla de hallazgos |
| `iam_audit_report_TIMESTAMP.csv` | Hallazgos de IAM por usuario y cuenta |
| `root_audit_report_TIMESTAMP.csv` | Estado de root account por cuenta |
| `cloudtrail_events_TIMESTAMP.csv` | Eventos IAM de CloudTrail para tracking de remediación |

**Modo Fargate** — archivos subidos a S3:

```
s3://iam-audit-reports-ACCOUNT-ID/
└── reports/
    └── YYYY-MM-DD/
        ├── iam_audit_report_TIMESTAMP.html
        ├── iam_audit_report_TIMESTAMP.csv
        ├── root_audit_report_TIMESTAMP.csv
        └── cloudtrail_events_TIMESTAMP.csv
```

Los reportes se eliminan automáticamente a los 90 días (lifecycle policy). La presigned URL del dashboard HTML es válida por 48 horas y se entrega vía Slack.

---

## Infraestructura desplegada (Modo Fargate)

Toda la infraestructura vive en la cuenta Security y se gestiona con Terraform:

| Recurso | Propósito |
|---|---|
| ECS Fargate Task | Corre el script de auditoría |
| EventBridge Scheduler | Dispara la task cada lunes 9am Lima |
| S3 Bucket | Almacena los reportes (lifecycle 90 días) |
| Secrets Manager | Guarda el Slack webhook URL cifrado |
| IAM Task Role | Permisos para asumir roles y escribir en S3 |
| IAM Execution Role | Permisos para arrancar el contenedor y leer secrets |
| CloudWatch Log Group | Logs de la task — retención 30 días |
| Security Group | Egress only — el contenedor no expone puertos |

---

## Relación con el AWS Security Maturity Model v2

Este script ayuda a avanzar en controles específicos del [AWS Security Maturity Model v2](https://maturitymodel.security.aws.dev/en/model/):

| Fase | Control | Cómo ayuda este script |
|---|---|---|
| Phase 1 — Quick Wins | Multi-Factor Authentication | Identifica usuarios y cuentas root sin MFA |
| Phase 2 — Foundational | Use Temporary Credentials | Expone usuarios con Access Keys de largo plazo activas |
| Phase 2 — Foundational | Protect Root Credentials | Detecta root sin MFA, con AK activas y con login reciente |

---

## Limitaciones conocidas

- CloudTrail se consulta en `us-east-1` por defecto — IAM es global pero los eventos son regionales
- Cuentas donde el rol de auditoría no esté desplegado serán omitidas con un error en consola — eso en sí mismo es un hallazgo
- `lookup_events` retorna eventos de los últimos 90 días por limitación de la API de CloudTrail
- La cuenta Management es omitida del audit de cuentas hijas si no tiene el rol de auditoría desplegado — comportamiento esperado

---

## Roadmap

- [x] Auditoría de IAM Users y Access Keys multicuenta
- [x] Risk scoring por usuario
- [x] Dashboard HTML interactivo con filtros globales
- [x] Tendencia de remediación vía CloudTrail
- [x] Detección de root account — MFA, Access Keys, último login
- [x] Dockerización — imagen disponible en Docker Hub
- [x] Notificaciones Slack con card resumen y presigned URL
- [x] Ejecución programada vía ECS Fargate + EventBridge
- [x] Infraestructura como código con Terraform
- [ ] Integración con AWS Security Hub (custom findings)
- [ ] Soporte para Microsoft Teams

---

## Estructura del repositorio

```
iam-audit/
├── src/
│   ├── iam_audit.py              # Script principal
│   └── template.html             # Template del dashboard HTML
├── infra/
│   ├── main.tf                   # Orquestador — llama a todos los módulos
│   ├── variables.tf              # Variables globales
│   ├── outputs.tf                # Outputs globales
│   ├── backend.hcl.example       # Template de configuración del backend
│   ├── terraform.tfvars.example  # Template de variables
│   └── modules/
│       ├── s3/                   # Bucket de reportes
│       ├── iam/                  # Task Role + Execution Role
│       ├── ecs/                  # Cluster + Task Definition
│       ├── secrets/              # Secrets Manager
│       └── eventbridge/          # Scheduler semanal
├── examples/
│   └── iam_audit_report_example.csv
├── output/                       # Generado en tiempo de ejecución — en .gitignore
├── Dockerfile
├── requirements.txt
└── README.md
```

---

## Autor

**Gerardo Castro** — AWS Security Hero · Cloud Security Engineer

Construyo herramientas de seguridad para entornos AWS reales en LATAM. Este script nació de una necesidad concreta en campo — como la mayoría de las herramientas que vale la pena usar.

🔗 [LinkedIn](https://linkedin.com/in/gerardokaztro)
🔗 [Blog](https://roadtocloudsec.hashnode.dev)
📝 [Post completo con contexto y hallazgos](https://roadtocloudsec.hashnode.dev/encontre-access-key-2018-activa-produccion-python-boto3)

---

## Licencia

MIT — usalo, modificalo, compartilo. Si encontrás algo interesante con él, contame.