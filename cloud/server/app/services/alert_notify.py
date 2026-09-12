"""Pod Cloud：告警渠道通知（webhook）。

支持渠道：generic（自定义 JSON）/ wecom（企业微信）/ dingtalk（钉钉）/
feishu（飞书）/ slack。发送在后台线程执行，不阻塞 sync 主流程；
失败只记日志，不重试（告警已落库，通知尽力而为）。
"""

import json
import logging
import threading

import httpx

logger = logging.getLogger("podcloud.alert_notify")

CHANNELS = {"generic", "wecom", "dingtalk", "feishu", "slack"}
SEVERITY_LEVEL = {"low": 1, "medium": 2, "high": 3}


def _severity_ok(min_severity: str, severity: str) -> bool:
    if not min_severity:
        return True
    return SEVERITY_LEVEL.get(severity, 0) >= SEVERITY_LEVEL.get(min_severity, 0)


def format_payload(channel: str, alerts: list[dict]) -> dict:
    """按渠道拼装 webhook 载荷。alerts: [{kind, severity, message, agent, ts}]"""
    if channel == "wecom":
        text = "\n".join(f"[{a['severity']}] {a['message']}" for a in alerts)
        return {"msgtype": "text", "text": {"content": f"⚠️ Pod Cloud 告警 ×{len(alerts)}\n{text}"}}
    if channel == "dingtalk":
        text = "\n".join(f"- [{a['severity']}] {a['message']}" for a in alerts)
        return {"msgtype": "text", "text": {"content": f"⚠️ Pod Cloud 告警 ×{len(alerts)}\n{text}"}}
    if channel == "feishu":
        text = "\n".join(f"[{a['severity']}] {a['message']}" for a in alerts)
        return {"msg_type": "text", "content": {"text": f"⚠️ Pod Cloud 告警 ×{len(alerts)}\n{text}"}}
    if channel == "slack":
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"Pod Cloud 告警 ×{len(alerts)}"}}
        ]
        for a in alerts:
            blocks.append(
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*[{a['severity']}]* {a['message']}"}}
            )
        return {"blocks": blocks}
    # generic
    return {"event": "alert", "count": len(alerts), "alerts": alerts}


def send_webhook(cfg: dict, alerts: list[dict]) -> None:
    """后台线程发送。cfg: {channel, url, secret}"""
    if not cfg or not cfg.get("url"):
        return
    try:
        payload = format_payload(cfg.get("channel", "generic"), alerts)
        headers = {"Content-Type": "application/json"}
        if cfg.get("secret"):
            headers["X-PodCloud-Signature"] = cfg["secret"]
        httpx.post(cfg["url"], json=payload, headers=headers, timeout=5.0)
        logger.info("alert webhook sent: channel=%s alerts=%d", cfg.get("channel"), len(alerts))
    except Exception as e:  # noqa: BLE001 通知失败不影响主流程
        logger.warning("alert webhook failed: %s", e)


def notify_async(cfg: dict, alerts: list[dict]) -> None:
    if not alerts:
        return
    threading.Thread(target=send_webhook, args=(cfg, alerts), daemon=True).start()


def load_webhook_cfg(raw_json: str) -> dict:
    try:
        cfg = json.loads(raw_json or "{}")
        if not isinstance(cfg, dict):
            return {}
        return cfg
    except json.JSONDecodeError:
        return {}


# ---- 邮件渠道（SMTP，用户自设） ----

def send_email(cfg: dict, alerts: list[dict]) -> None:
    """SMTP 发送告警邮件。cfg: {host, port, user, password, from_addr, to_addrs, tls, enabled}"""
    if not cfg or not cfg.get("enabled") or not cfg.get("host"):
        return
    try:
        import smtplib
        from email.header import Header
        from email.mime.text import MIMEText

        to_addrs = [a.strip() for a in (cfg.get("to_addrs") or "").split(",") if a.strip()]
        if not to_addrs:
            return
        lines = [f"[{a['severity']}] {a['message']} (agent: {a['agent']}, {a['ts']})" for a in alerts]
        body = "Pod Cloud 告警 ×{n}\n\n{lines}\n\n—— Pod Cloud (AI Agent 安全舱)".format(
            n=len(alerts), lines="\n".join(lines)
        )
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = Header(f"Pod Cloud 告警 ×{len(alerts)}（含高危 {sum(1 for a in alerts if a['severity']=='high')}）", "utf-8")
        msg["From"] = cfg.get("from_addr") or cfg.get("user") or "podcloud@localhost"
        msg["To"] = ", ".join(to_addrs)

        port = int(cfg.get("port") or 465)
        if port == 465:
            smtp = smtplib.SMTP_SSL(cfg["host"], port, timeout=10)
        else:
            smtp = smtplib.SMTP(cfg["host"], port, timeout=10)
            smtp.ehlo()
            if cfg.get("tls") is not False:
                smtp.starttls()
                smtp.ehlo()
        try:
            if cfg.get("user"):
                smtp.login(cfg["user"], cfg.get("password") or "")
            smtp.sendmail(msg["From"], to_addrs, msg.as_string())
        finally:
            smtp.quit()
        logger.info("alert email sent: to=%s alerts=%d", to_addrs, len(alerts))
    except Exception as e:  # noqa: BLE001
        logger.warning("alert email failed: %s", e)


def email_async(cfg: dict, alerts: list[dict]) -> None:
    if not alerts:
        return
    threading.Thread(target=send_email, args=(cfg, alerts), daemon=True).start()
