import json
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

CONFIG_PATH = Path.home() / ".opsec-guard" / "alert_config.json"


def load_config() -> dict | None:
    if not CONFIG_PATH.exists():
        return None
    try:
        return json.loads(CONFIG_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def save_config(cfg: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


def _build_html(subject: str, findings: list[str], score: int, level: str) -> str:
    finding_rows = "".join(f"<li>{f}</li>" for f in findings)
    level_color = {"critical": "#e53e3e", "high": "#dd6b20", "medium": "#d69e2e", "low": "#38a169"}.get(level, "#666")

    return f"""
<html><body style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px;">
  <h2 style="color: {level_color};">opsec-guard — {level.upper()} Alert</h2>
  <p>Your MAID exposure audit has returned a <strong>{level.upper()}</strong> risk rating.</p>
  <table style="border-collapse: collapse; width: 100%; margin-bottom: 20px;">
    <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Exposure Score</strong></td>
        <td style="padding: 8px; border: 1px solid #ddd; color: {level_color};">{score}/100</td></tr>
    <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Risk Level</strong></td>
        <td style="padding: 8px; border: 1px solid #ddd; color: {level_color};">{level.upper()}</td></tr>
  </table>
  <h3>Critical Findings</h3>
  <ul style="line-height: 1.8;">{finding_rows}</ul>
  <hr/>
  <h3>Immediate Actions</h3>
  <ol>
    <li>Run <code>opsec-guard maid reset</code> to reset your MAID now.</li>
    <li>Revoke background location from all non-essential apps.</li>
    <li>Enable ad tracking opt-out on your device.</li>
    <li>Run <code>opsec-guard maid report</code> for a full remediation plan.</li>
  </ol>
  <p style="color: #666; font-size: 12px; margin-top: 30px;">
    Sent by opsec-guard — Mobile MAID Exposure Auditing Tool<br/>
    <a href="https://github.com/arctracerexequias/opsec-guard">github.com/arctracerexequias/opsec-guard</a>
  </p>
</body></html>
"""


def send_critical_alert(findings: list[str], score: int, level: str) -> tuple[bool, str]:
    """
    Send an email alert for critical/high audit results.
    Returns (success: bool, message: str).
    Only sends for 'critical' or 'high' risk levels.
    """
    if level not in ("critical", "high"):
        return False, "Alert not sent — risk level is not critical or high."

    cfg = load_config()
    if cfg is None:
        return False, "No alert configuration found. Run `opsec-guard maid alerts configure` first."

    recipient   = cfg.get("recipient_email")
    smtp_host   = cfg.get("smtp_host")
    smtp_port   = cfg.get("smtp_port", 587)
    smtp_user   = cfg.get("smtp_user")
    smtp_pass   = cfg.get("smtp_password")
    sender      = cfg.get("sender_email", smtp_user)

    if not all([recipient, smtp_host, smtp_user, smtp_pass]):
        return False, "Incomplete alert configuration. Run `opsec-guard maid alerts configure`."

    subject = f"[opsec-guard] {level.upper()} MAID Exposure Alert — Score {score}/100"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = sender
    msg["To"]      = recipient

    plain = (
        f"opsec-guard {level.upper()} Alert\n"
        f"Exposure Score: {score}/100\n\n"
        f"Findings:\n" + "\n".join(f"- {f}" for f in findings) +
        "\n\nRun `opsec-guard maid reset` and `opsec-guard maid report` for remediation steps."
    )
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(_build_html(subject, findings, score, level), "html"))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(smtp_user, smtp_pass)
            server.sendmail(sender, recipient, msg.as_string())
        return True, f"Alert sent to {recipient}"
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP authentication failed. Check your credentials."
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {e}"
    except OSError as e:
        return False, f"Network error: {e}"
