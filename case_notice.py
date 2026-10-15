"""One moderation case sends the member one direct message, even when several rules apply.

A warning's message is held briefly. If the same warning also triggers a
warning-count escalation (timeout, kick or ban), the escalation is folded into
the held message instead of being sent as a second one."""
from __future__ import annotations

# The held message is always sent: by the caller right after the escalation was
# decided, or by a timer if that never happens.
CASE_NOTICE_GRACE_SECONDS = 15
APPEAL_MARKER = "\n\n**Appeal this decision**"
_PAST_TENSE = {"timeout": "timed out", "kick": "kicked", "ban": "banned"}


def merged_title(base: str, action: str) -> str:
    past = _PAST_TENSE[action]
    if base == "You received a warning":
        return f"You were warned and {past}"
    if base == "You were warned and timed out":
        return base if action == "timeout" else f"You were warned, timed out and {past}"
    return base


class CaseNotice:
    def __init__(self, user_id: str, title: str, description: str, *,
                 server_id: str | None, user: object | None, color: str) -> None:
        self.user_id = user_id
        self.title = title
        self.description = description
        self.server_id = server_id
        self.user = user
        self.color = color
        self.escalations: list[str] = []
        self.escalation_appeal = ""
        self.timer = None  # asyncio.TimerHandle, cancelled once the message is sent

    @property
    def has_appeal(self) -> bool:
        return APPEAL_MARKER in self.description

    def add_escalation(self, action: str, warning_count: int, action_label: str,
                       server_name: str, appeal: str) -> None:
        self.title = merged_title(self.title, action)
        self.escalations.append(
            "**Warning policy**\n"
            f"A moderation action was applied to you in **{server_name}** "
            f"because you reached {warning_count} warnings.\n"
            f"**Action:** {action_label}"
        )
        if appeal and not self.has_appeal and not self.escalation_appeal:
            self.escalation_appeal = appeal

    def compose(self) -> tuple[str, str]:
        if not self.escalations:
            return self.title, self.description
        extra = "\n\n".join(self.escalations)
        position = self.description.find(APPEAL_MARKER)
        if position >= 0:
            # The appeal block stays last and appears once for the whole case.
            return self.title, self.description[:position] + "\n\n" + extra + self.description[position:]
        return self.title, self.description + "\n\n" + extra + self.escalation_appeal
