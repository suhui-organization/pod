"""系统级发信通道(找回密码)。

与 alert_notify 里的租户告警邮件刻意分开:告警邮件是"发给管理员自己看"的
租户级配置,而找回密码要服务**未登录**的用户——单一管理员把自己锁在外面时
根本进不去设置页配 SMTP,只能靠部署期的系统配置救回自己(见 config.smtp_*)。
"""

import logging
import smtplib
from email.header import Header
from email.mime.text import MIMEText

from app.config import settings

logger = logging.getLogger("podcloud.mailer")


def mailer_configured() -> bool:
    """实例是否具备发信能力。前端据此提前告诉用户链接会去哪。"""
    return bool(settings.smtp_host)


def send_mail(to: str, subject: str, body: str) -> bool:
    """同步发送,返回是否成功。

    返回值**不用于**决定对外响应(那会泄露账号是否存在),只用来决定
    要不要走日志兜底。
    """
    if not mailer_configured():
        return False
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = Header(subject, "utf-8")
        msg["From"] = settings.smtp_from or settings.smtp_user or "podcloud@localhost"
        msg["To"] = to

        port = int(settings.smtp_port or 465)
        if port == 465:
            smtp = smtplib.SMTP_SSL(settings.smtp_host, port, timeout=10)
        else:
            smtp = smtplib.SMTP(settings.smtp_host, port, timeout=10)
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
        try:
            if settings.smtp_user:
                smtp.login(settings.smtp_user, settings.smtp_password or "")
            smtp.sendmail(msg["From"], [to], msg.as_string())
        finally:
            smtp.quit()
        logger.info("mail sent: to=%s subject=%s", to, subject)
        return True
    except Exception as e:  # noqa: BLE001 发信失败不该把异常抛给未登录用户
        logger.warning("mail failed: to=%s err=%s", to, e)
        return False


def deliver_reset_link(to_email: str, link: str) -> None:
    """把重置链接送出去。

    没配 SMTP 时写服务端日志,这是自托管下的既定行为而非降级失败:
    能读日志的人(kubectl logs)本来就能直接改库,不算提权。
    这里不返回所用通道——否则调用方容易拿它当"账号存在与否"的信号,
    对外的说法统一由 /auth/config 的 password_reset 字段给出。
    """
    body = (
        "你正在重置 Pod Cloud 的登录密码。\n\n"
        f"{link}\n\n"
        "链接 30 分钟内有效,且只能使用一次。\n"
        "如果这不是你发起的,忽略这封邮件即可——你的密码不会被改动。\n\n"
        "—— Pod Cloud (AI Agent 安全舱)"
    )
    if send_mail(to_email, "Pod Cloud 重置密码", body):
        return
    logger.warning("password reset link (SMTP 未配置,请从服务端日志取走): %s -> %s", to_email, link)
