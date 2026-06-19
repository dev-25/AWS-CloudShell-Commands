# AWS IAM Users Export — CloudShell Guide

**Tool:** AWS CloudShell  
**Output:** Excel report (`iam_users_report.xlsx`)  
**Purpose:** Export all IAM users with permissions, MFA status, access key details, and security metadata into a formatted Excel sheet for audit and compliance review.

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| AWS Access | AWS Console login with CloudShell access |
| IAM Permissions | `IAMReadOnlyAccess` managed policy (or equivalent `iam:List*` / `iam:Get*` on `*`) |
| Python Package | `openpyxl` (installed via pip in CloudShell) |

---

## How to Run

### Step 1 — Open AWS CloudShell

In the AWS Console, click the **CloudShell icon** in the top navigation bar (looks like `>_`).

> CloudShell automatically inherits the IAM permissions of your current logged-in session.

---

### Step 2 — Install Dependency

```bash
pip install openpyxl --quiet
```

---

### Step 3 — Run the Script (Paste Directly into CloudShell)

Copy the entire block below and paste it into CloudShell, then press **Enter**:

```bash
python3 << 'EOF'
import boto3
from datetime import datetime, timezone
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

iam = boto3.client('iam')

def age_days(dt):
    if not dt:
        return "N/A"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days

def fmt_dt(dt):
    if not dt:
        return "N/A"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M UTC")

def get_permissions_summary(username):
    policies = []
    pp = iam.list_attached_user_policies(UserName=username)
    for p in pp['AttachedPolicies']:
        policies.append(p['PolicyName'])
    ip = iam.list_user_policies(UserName=username)
    for p in ip['PolicyNames']:
        policies.append(f"[Inline] {p}")
    groups = iam.list_groups_for_user(UserName=username)
    for g in groups['Groups']:
        gp = iam.list_attached_group_policies(GroupName=g['GroupName'])
        for p in gp['AttachedPolicies']:
            policies.append(f"[Group:{g['GroupName']}] {p['PolicyName']}")
        gi = iam.list_group_policies(GroupName=g['GroupName'])
        for p in gi['PolicyNames']:
            policies.append(f"[Group:{g['GroupName']}][Inline] {p}")
    return "\n".join(policies) if policies else "No Policies"

def get_mfa_status(username):
    mfa = iam.list_mfa_devices(UserName=username)
    return "Enabled" if mfa['MFADevices'] else "Disabled"

def get_login_profile(username):
    try:
        lp = iam.get_login_profile(UserName=username)
        return True, lp['LoginProfile'].get('CreateDate')
    except iam.exceptions.NoSuchEntityException:
        return False, None

def get_access_keys(username):
    keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
    result = []
    for k in keys:
        kid = k['AccessKeyId']
        created = k['CreateDate']
        status = k['Status']
        try:
            lu = iam.get_access_key_last_used(AccessKeyId=kid)
            last_used = lu['AccessKeyLastUsed'].get('LastUsedDate')
        except:
            last_used = None
        result.append({'id': kid, 'status': status, 'created': created, 'last_used': last_used})
    return result

print("Fetching IAM users...")
paginator = iam.get_paginator('list_users')
users = []
for page in paginator.paginate():
    users.extend(page['Users'])

print(f"Found {len(users)} users. Collecting details...")

rows = []
for i, u in enumerate(users):
    uname = u['UserName']
    print(f"  [{i+1}/{len(users)}] {uname}")
    permissions = get_permissions_summary(uname)
    mfa = get_mfa_status(uname)
    has_console, pw_created = get_login_profile(uname)
    pw_age = age_days(pw_created) if has_console and pw_created else "N/A"
    last_signin_raw = u.get('PasswordLastUsed')
    console_last_signin = fmt_dt(last_signin_raw) if last_signin_raw else "Never / N/A"
    keys = get_access_keys(uname)
    if keys:
        for j, key in enumerate(keys):
            key_age = age_days(key['created']) if key['status'] == 'Active' else f"{age_days(key['created'])} (Inactive)"
            rows.append({
                'username': uname if j == 0 else "",
                'permissions': permissions if j == 0 else "",
                'mfa': mfa if j == 0 else "",
                'pw_age': pw_age if j == 0 else "",
                'console_last_signin': console_last_signin if j == 0 else "",
                'key_id': key['id'],
                'key_age': key_age,
                'key_last_used': fmt_dt(key['last_used']),
                'arn': u['Arn'] if j == 0 else "",
                'created': fmt_dt(u['CreateDate']) if j == 0 else "",
                'console_access': ("Yes" if has_console else "No") if j == 0 else "",
            })
    else:
        rows.append({
            'username': uname, 'permissions': permissions, 'mfa': mfa,
            'pw_age': pw_age, 'console_last_signin': console_last_signin,
            'key_id': "No Access Keys", 'key_age': "N/A", 'key_last_used': "N/A",
            'arn': u['Arn'], 'created': fmt_dt(u['CreateDate']),
            'console_access': "Yes" if has_console else "No",
        })

wb = Workbook()
ws = wb.active
ws.title = "IAM Users"

HEADERS = ["IAM Username","Permissions / Policies","MFA Status","Password Age (Days)",
           "Console Last Sign-In","Access Key ID","Active Key Age (Days)",
           "Access Key Last Used","ARN","Creation Time","Console Access"]

HDR_FILL  = PatternFill("solid", start_color="1F4E79")
HDR_FONT  = Font(bold=True, color="FFFFFF", name="Arial", size=10)
HDR_ALIGN = Alignment(horizontal="center", vertical="center", wrap_text=True)
CELL_FONT = Font(name="Arial", size=9)
WRAP      = Alignment(vertical="top", wrap_text=True)
THIN      = Side(style="thin", color="BFBFBF")
BORDER    = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
ALT_FILL  = PatternFill("solid", start_color="EBF3FB")
WARN_FILL = PatternFill("solid", start_color="FFEB9C")
GRN_FILL  = PatternFill("solid", start_color="E2EFDA")

ws.row_dimensions[1].height = 36
for ci, h in enumerate(HEADERS, 1):
    c = ws.cell(row=1, column=ci, value=h)
    c.fill = HDR_FILL; c.font = HDR_FONT; c.alignment = HDR_ALIGN; c.border = BORDER

for ri, row in enumerate(rows, 2):
    is_alt = (ri % 2 == 0)
    vals = [row['username'], row['permissions'], row['mfa'], row['pw_age'],
            row['console_last_signin'], row['key_id'], row['key_age'],
            row['key_last_used'], row['arn'], row['created'], row['console_access']]
    for ci, val in enumerate(vals, 1):
        c = ws.cell(row=ri, column=ci, value=val)
        c.font = CELL_FONT; c.alignment = WRAP; c.border = BORDER
        if is_alt:
            c.fill = ALT_FILL
    if row['mfa'] == "Disabled":
        ws.cell(row=ri, column=3).fill = WARN_FILL
    if row['key_id'] == "No Access Keys":
        ws.cell(row=ri, column=6).fill = GRN_FILL

col_widths = [22, 40, 14, 20, 25, 22, 20, 25, 60, 22, 16]
for ci, w in enumerate(col_widths, 1):
    ws.column_dimensions[get_column_letter(ci)].width = w

ws.freeze_panes = "A2"
ws.auto_filter.ref = ws.dimensions

ws2 = wb.create_sheet("Summary")
total        = len(users)
mfa_disabled = sum(1 for r in rows if r['username'] and r['mfa'] == "Disabled")
no_console   = sum(1 for r in rows if r['username'] and r['console_access'] == "No")
no_keys      = sum(1 for r in rows if r['username'] and r['key_id'] == "No Access Keys")
s_data = [("Total IAM Users", total), ("Users with MFA Disabled", mfa_disabled),
          ("Users without Console Access", no_console), ("Users with No Access Keys", no_keys),
          ("Report Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))]
ws2['A1'], ws2['B1'] = "Metric", "Value"
for ci in [1, 2]:
    c = ws2.cell(row=1, column=ci)
    c.fill = HDR_FILL; c.font = HDR_FONT; c.alignment = HDR_ALIGN
for ri, (k, v) in enumerate(s_data, 2):
    ws2.cell(row=ri, column=1, value=k).font = Font(name="Arial", size=10, bold=True)
    ws2.cell(row=ri, column=2, value=v).font = Font(name="Arial", size=10)
ws2.column_dimensions['A'].width = 35
ws2.column_dimensions['B'].width = 30

out = "iam_users_report.xlsx"
wb.save(out)
print(f"\n✅ Done! Report saved: ~/{out}")
print(f"   Users: {total} | MFA Disabled: {mfa_disabled} | No Console: {no_console} | No Keys: {no_keys}")
print(f"\n📥 To download: CloudShell → Actions → Download file → /home/cloudshell-user/{out}")
EOF
```

> **Note:** The heredoc syntax `python3 << 'EOF' ... EOF` lets you run a full Python script directly from the terminal without creating or uploading a file.

---

### Step 4 — Download the Excel File

1. In CloudShell, click **Actions** (top-right of the CloudShell panel)
2. Click **Download file**
3. Enter the path:
   ```
   /home/cloudshell-user/iam_users_report.xlsx
   ```
4. Click **Download** — the file saves to your local machine

---

## Excel Report — Column Reference

The report contains two sheets: **IAM Users** and **Summary**.

### Sheet 1: IAM Users

| # | Column | Description |
|---|--------|-------------|
| 1 | **IAM Username** | IAM user's login name |
| 2 | **Permissions / Policies** | All attached managed policies, inline policies, and group-inherited policies |
| 3 | **MFA Status** | `Enabled` or `Disabled` — highlighted **yellow** if Disabled |
| 4 | **Password Age (Days)** | Days since the console password was created. `N/A` if no console access |
| 5 | **Console Last Sign-In** | Last date/time the user logged into the AWS Console |
| 6 | **Access Key ID** | The IAM access key ID (`AKIA...`). `No Access Keys` highlighted green if none exist |
| 7 | **Active Key Age (Days)** | Age in days of the access key. Shows `(Inactive)` if key status is Inactive |
| 8 | **Access Key Last Used** | Last date/time the access key was used to make an API call |
| 9 | **ARN** | Full Amazon Resource Name of the IAM user |
| 10 | **Creation Time** | Date/time the IAM user account was created |
| 11 | **Console Access** | `Yes` if a login profile (console password) exists, `No` if programmatic-only |

> **Multi-key users:** If a user has 2 access keys, they appear on 2 rows. User-level columns (Username, ARN, MFA, etc.) are populated only on the first row.

### Sheet 2: Summary

| Metric | Description |
|--------|-------------|
| Total IAM Users | Total count of IAM users in the account |
| Users with MFA Disabled | Count of users without any MFA device registered |
| Users without Console Access | Count of programmatic-only users (no login profile) |
| Users with No Access Keys | Count of users with no access keys configured |
| Report Generated | UTC timestamp of when the report was generated |

---

## Excel Formatting Features

| Feature | Details |
|---------|---------|
| **Header row** | Dark blue background, white bold text, frozen (stays visible on scroll) |
| **Alternating rows** | Light blue alternate row shading for readability |
| **MFA Disabled highlight** | Yellow cell highlight on MFA column for users without MFA |
| **No Access Keys highlight** | Green cell highlight when a user has no access keys |
| **Auto-filter** | Dropdown filters on all columns — filter by MFA, Console Access, etc. |
| **Column widths** | Pre-sized per column content; Permissions and ARN columns are wider |
| **Wrap text** | Policies column wraps so all policy names are visible |

---

## Permissions Data Breakdown

The **Permissions / Policies** column (Column 2) captures all three sources of IAM permissions:

| Prefix | Source | Example |
|--------|--------|---------|
| *(no prefix)* | Directly attached AWS managed or customer managed policy | `AdministratorAccess` |
| `[Inline]` | Inline policy directly embedded on the user | `[Inline] S3ReadPolicy` |
| `[Group:GroupName]` | Policy inherited via IAM Group membership | `[Group:Developers] PowerUserAccess` |
| `[Group:GroupName][Inline]` | Inline policy on a group the user belongs to | `[Group:Admins][Inline] CustomDenyPolicy` |

---

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `AccessDenied` on `list_users` | Current IAM role/user lacks IAM read permissions | Attach `IAMReadOnlyAccess` policy to your IAM entity |
| `ModuleNotFoundError: openpyxl` | Package not installed | Run `pip install openpyxl --quiet` first |
| `NoCredentialError` | CloudShell session expired | Refresh the AWS Console page and reopen CloudShell |
| Empty report / 0 users | Querying wrong AWS account or region | CloudShell uses the account of your current console session — verify you're in the right account |
| Script appears to hang | Large number of IAM users | Wait — each user makes ~6 API calls; 100 users may take 2–3 minutes |

---

## IAM Permissions Required

The script only reads IAM data. Minimum required permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:ListGroupsForUser",
        "iam:ListAttachedGroupPolicies",
        "iam:ListGroupPolicies",
        "iam:ListMFADevices",
        "iam:GetLoginProfile",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed"
      ],
      "Resource": "*"
    }
  ]
}
```

Or simply attach the AWS managed policy: **`IAMReadOnlyAccess`**

---

*Generated for use with AWS CloudShell — ap-south-1 (Mumbai) and all regions*
