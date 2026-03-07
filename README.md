# 🔍 iam-audit

> Audita IAM Users, Access Keys y cuentas root en toda una AWS Organization multicuenta — en minutos, con mínimo privilegio. Dashboard HTML interactivo incluido.

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![AWS](https://img.shields.io/badge/AWS-boto3-FF9900?style=flat&logo=amazonaws&logoColor=white)](https://boto3.amazonaws.com)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat&logo=docker&logoColor=white)](https://hub.docker.com/r/gerardokaztro/iam-audit)
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

## Inicio rápido

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
docker build -t iam-audit .
docker run --rm \
  -v ~/.aws:/root/.aws \
  -v $(pwd)/output:/app/output \
  -p 8000:8000 \
  iam-audit \
  --profile YOUR-AWS-PROFILE \
  --role YOUR-AUDIT-ROLE
```

### Opción C — Sin Docker

```bash
pip install -r requirements.txt
python src/iam_audit.py --profile YOUR-AWS-PROFILE --role YOUR-AUDIT-ROLE
```

Cuando el scan termina, abrí el browser en `http://localhost:8000` para ver el dashboard interactivo.
Presiona `Ctrl+C` para detener el servidor.

---

## Configuración de permisos

El principio de mínimo privilegio aplica también aquí. El rol en la cuenta de management solo necesita:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "organizations:ListAccounts",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/NOMBRE-DEL-ROL-EN-CHILD-ACCOUNTS"
    }
  ]
}
```

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

> Si usas AWS Control Tower, el rol `AWSControlTowerExecution` ya existe en todas las cuentas y podés usarlo como punto de partida.

---

## Output

Todos los archivos se guardan en `./output/` con timestamp:

| Archivo | Contenido |
|---|---|
| `iam_audit_report_TIMESTAMP.html` | Dashboard interactivo con filtros, gráficos y tabla de hallazgos |
| `iam_audit_report_TIMESTAMP.csv` | Hallazgos de IAM por usuario y cuenta |
| `root_audit_report_TIMESTAMP.csv` | Estado de root account por cuenta |
| `cloudtrail_events_TIMESTAMP.csv` | Eventos IAM de CloudTrail para tracking de remediación |

**Campos del reporte IAM:**

| Campo | Descripción |
|---|---|
| `account_id` | ID de la cuenta AWS |
| `account_name` | Nombre de la cuenta en la Organization |
| `username` | Nombre del usuario IAM |
| `password_status` | Acceso a consola configurado o no |
| `password_last_used` | Última vez que usó la consola |
| `access_key_id` | ID de la Access Key |
| `status` | Active / Inactive |
| `created_date` | Fecha de creación de la key |
| `last_used_date` | Último uso de la key |
| `service_name` | Último servicio AWS donde se usó |
| `mfa_status` | Virtual / Hardware / None |

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

---

## Roadmap

- [x] Auditoría de IAM Users y Access Keys multicuenta
- [x] Risk scoring por usuario
- [x] Dashboard HTML interactivo con filtros globales
- [x] Tendencia de remediación vía CloudTrail
- [x] Detección de root account — MFA, Access Keys, último login
- [x] Dockerización — imagen disponible en Docker Hub
- [ ] Notificaciones Slack / Teams con card resumen
- [ ] Ejecución programada vía ECS Fargate + EventBridge
- [ ] Infraestructura como código con Terraform

---

## Estructura del repositorio

```
iam-audit/
├── src/
│   ├── iam_audit.py       # Script principal
│   └── template.html      # Template del dashboard HTML
├── examples/
│   └── iam_audit_report_example.csv
├── output/                # Generado en tiempo de ejecución — en .gitignore
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