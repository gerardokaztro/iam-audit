# 🔍 iam-audit

> Audita IAM Users y Access Keys en toda una AWS Organization multicuenta — en minutos, con mínimo privilegio.

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![AWS](https://img.shields.io/badge/AWS-boto3-FF9900?style=flat&logo=amazonaws&logoColor=white)](https://boto3.amazonaws.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![Author](https://img.shields.io/badge/AWS-Security%20Hero-FF9900?style=flat&logo=amazonaws&logoColor=white)](https://aws.amazon.com/developer/community/heroes/)

---

## ¿Qué hace?

`iam-audit` recorre automáticamente todas las cuentas activas de tu AWS Organization, asume un rol de auditoría en cada una, y produce un reporte consolidado con:

- ✅ Todas las **Access Keys** por usuario — estado, fecha de creación, último uso y servicio
- ✅ Estado de **MFA** por usuario (Virtual, Hardware, o ausente)
- ✅ Acceso a **consola** (login profile configurado o no)
- ✅ Eventos de **CloudTrail** para tracking de remediación en el tiempo

Todo sin crear credenciales de largo plazo adicionales. El script usa `sts:AssumeRole` — credenciales temporales que expiran solas.

---

## ¿Por qué existe esto?

En entornos multicuenta, nadie tiene una vista consolidada de credenciales. Las Access Keys viejas no aparecen en ningún dashboard por defecto. No generan alertas. No molestan a nadie. Simplemente esperan.

Este script las encuentra.

> Probado en una AWS Organization real con más de 20 cuentas activas. Encontré una Access Key creada en 2018 — activa en producción. Lee el post completo → [link al blog]

---

## Requisitos

- Python 3.9+
- boto3
- Acceso a la cuenta de **management** de la AWS Organization
- Un rol de auditoría desplegado en cada cuenta miembro

```bash
pip install boto3
```

---

## Configuración de permisos

El principio de mínimo privilegio aplica también aquí. El rol en la cuenta de management solo necesita esto:

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
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

> Si usás AWS Control Tower, el rol `AWSControlTowerExecution` ya existe en todas las cuentas y podés usarlo como punto de partida.

---

## Uso

```bash
python iam_audit.py --profile <tu-perfil-mgmt> --role <nombre-del-rol>
```

**Ejemplos:**

```bash
# Con Control Tower
python iam_audit.py --profile mgmt-profile --role AWSControlTowerExecution

# Con rol de auditoría dedicado
python iam_audit.py --profile mgmt-profile --role IAMAuditRole
```

---

## Output

El script genera dos archivos CSV con timestamp:

| Archivo | Contenido |
|---|---|
| `iam_audit_report_YYYYMMDD_HHMMSS.csv` | Hallazgos de IAM por usuario y cuenta |
| `cloudtrail_events_YYYYMMDD_HHMMSS.csv` | Eventos IAM de CloudTrail para tracking de remediación |

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

Este script ayuda a avanzar en dos controles específicos del [AWS Security Maturity Model v2](https://maturitymodel.security.aws.dev/en/model/):

| Fase | Control | Cómo ayuda este script |
|---|---|---|
| Phase 1 — Quick Wins | Multi-Factor Authentication | Identifica usuarios sin MFA con acceso a consola |
| Phase 2 — Foundational | Use Temporary Credentials | Expone usuarios con Access Keys de largo plazo activas |

---

## Limitaciones conocidas

- El script audita IAM en `us-east-1` por defecto para CloudTrail — IAM es global pero los eventos de CloudTrail son regionales
- Cuentas donde el rol de auditoría no esté desplegado serán omitidas con un error en consola — eso en sí mismo es un hallazgo
- No audita root account keys (próxima versión)

---

## Roadmap

- [ ] Detección de root account keys
- [ ] Risk scoring por usuario (edad de key + MFA + acceso a consola)
- [ ] Integración con AWS Security Hub (custom findings)
- [ ] Dashboard HTML con visualización de hallazgos y tendencia de remediación
- [ ] Alertas por Slack / email para keys de alto riesgo
- [ ] Ejecución programada vía Lambda

---

## Autor

**Gerardo Castro** — AWS Security Hero · Cloud Security Engineer

Construyo herramientas de seguridad para entornos AWS reales en LATAM. Este script nació de una necesidad concreta en campo — como la mayoría de las herramientas que vale la pena usar.

🔗 [LinkedIn](https://linkedin.com/in/tu-perfil)
🔗 [Blog](https://tu-dominio.hashnode.dev)
📝 [Post completo con contexto y hallazgos](link-al-blog)

---

## Licencia

MIT — usalo, modificalo, compartilo. Si encontrás algo interesante con él, contame.
