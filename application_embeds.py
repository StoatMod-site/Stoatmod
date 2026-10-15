"""The same embed payloads power applicant DMs and the dashboard preview."""
from __future__ import annotations

import re
from typing import Any

DEFAULT_APPEARANCE = {"color": "#5865F2", "footer": "", "submitted_title": "Application submitted",
                      "submitted_message": "Thank you for applying! The team will review your answers.", "submitted_emoji": "📬"}
QUESTION_EMOJIS = {"text": "👋", "choice": "💬", "agreement": "📜"}
APPLICATION_PRIVACY_VERSION = "2026-10-01-applications-v1"


def privacy_embed(form: dict[str, Any], server_name: str, policy_url: str) -> dict[str, str]:
    return {"title": "Application privacy agreement", "color": appearance(form)["color"],
            "description": (
                f"Before applying to **{server_name}**, read our [Privacy Policy]({policy_url}).\n\n"
                "Stoatmod stores your answers, user and server IDs, verification status, agreement and review details. "
                "Authorised moderators of this server can review them.\n\n"
                "Your application data is deleted **14 days after submission**, whether accepted or denied. "
                "If no decision has been made, your application is automatically denied at that deadline. "
                "Approval does not extend storage. An unfinished application is deleted after seven days.\n\n"
                "Deletion covers Stoatmod's stored application records. DMs and notices already sent on Stoat "
                "remain subject to Stoat's controls. Agreement does not permit AI training.\n\n"
                "Reply **I agree** to agree to the Privacy Policy and this application processing before answering "
                "any questions. You can decline by not continuing. For withdrawal or earlier deletion, contact "
                "admin@modstoat.site with your user and server IDs."
            )}


def embed_title(text: str) -> str:
    # Preserve saved legacy titles while respecting Stoat's 100-character cap.
    return text if len(text) <= 100 else text[:99] + "…"


def validate_appearance(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        raise ValueError("Embed appearance must be an object.")
    result = dict(DEFAULT_APPEARANCE)
    for key, limit in {"color": 7, "footer": 160, "submitted_title": 120,
                       "submitted_message": 1000, "submitted_emoji": 32}.items():
        value = raw.get(key, result[key])
        if not isinstance(value, str) or len(value) > limit:
            raise ValueError(f"{key.replace('_', ' ').title()} must be at most {limit} characters.")
        result[key] = value.strip()
    if not re.fullmatch(r"#[0-9a-fA-F]{6}", result["color"]):
        raise ValueError("Choose a valid embed colour, such as #5865F2.")
    if not result["submitted_title"]:
        raise ValueError("Add a submission embed title.")
    return result


def appearance(form: dict[str, Any]) -> dict[str, str]:
    return {**DEFAULT_APPEARANCE, **form.get("appearance", {})}


def question_embeds(form: dict[str, Any], server_name: str, position: int) -> list[dict[str, str]]:
    style = appearance(form)
    question = form["questions"][position]
    emoji = question.get("emoji", QUESTION_EMOJIS[question["type"]])
    title = embed_title(f"{emoji} {question['title'] or 'Question title'}".strip())
    color = question.get("color") or style["color"]
    prompt = question["prompt"] or "Your question will appear here."
    intro = form.get("introduction", "") if position == 0 else ""
    instructions = "Reply to this message with your answer (up to 2,000 characters)."
    if question["type"] == "choice":
        instructions = "\n".join(f"{i + 1}. {option or f'Option {i + 1}'}" for i, option in enumerate(question["options"]))
        instructions += "\nReply with the option number."
    elif question["type"] == "agreement":
        instructions = "Reply with **agree** to accept."
    if not question["required"]:
        instructions += " Reply **skip** to skip this optional question."
    footer = f"\n\n{style['footer']}" if style["footer"] else ""
    heading = f"**{server_name} · Question {position + 1} of {len(form['questions'])}**"
    text = "\n\n".join(part for part in [heading, intro, prompt, instructions] if part) + footer
    embeds = []
    if len(text) > 1900 and intro:
        embeds.append({"title": embed_title(f"👋 Apply to {server_name}"), "description": intro, "color": color})
        text = "\n\n".join([heading, prompt, instructions]) + footer
    if len(text) > 1900:
        embeds.append({"title": title, "description": prompt, "color": color})
        text = "\n\n".join([heading, "See the question above.", instructions]) + footer
    return [*embeds, {"title": title, "description": text, "color": color}]


def submission_embed(form: dict[str, Any], server_name: str, deadline: str) -> dict[str, str]:
    style = appearance(form)
    text = f"Your application to **{server_name}** has been submitted."
    if style["submitted_message"]:
        text += "\n\n" + style["submitted_message"]
    text += ("\n\nThe server moderators have 14 days from submission to accept or deny it. "
             f"Your application data is deleted on **{deadline}**, including accepted applications. "
             "An undecided application is automatically denied at that deadline. Approval does not restart the period.")
    if style["footer"]:
        text += "\n\n" + style["footer"]
    return {"title": embed_title(f"{style['submitted_emoji']} {style['submitted_title']}".strip()),
            "description": text, "color": style["color"]}
