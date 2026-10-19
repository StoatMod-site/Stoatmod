from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import math
import socket
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlsplit

from moderation_policy import (
    IMAGE_MODERATION_CATEGORIES, MIN_MODERATION_THRESHOLD, SEXUAL_CATEGORY,
    SUPPORT_ONLY_CATEGORIES, SUPPORTED_MODERATION_CATEGORIES,
)

if TYPE_CHECKING:
    import aiohttp

logger = logging.getLogger("stoat_moderator")


class ModerationError(RuntimeError):
    """An unusable moderation response, never a violation itself."""


@dataclass(frozen=True)
class ModerationResult:
    flagged: bool
    categories: dict[str, bool]
    scores: dict[str, float]
    score_kind: str = "label_probability_uncalibrated"
    action_exempt: bool = False
    # Optional reasoning from the classifier's "thinking" verifier. Message-derived:
    # stored only with the case and purged with the original message after 30 days.
    thinking: dict[str, Any] | None = None

    def blocked_categories(self, threshold: float) -> list[str]:
        if self.action_exempt:
            return []
        return sorted(name for name, score in self.scores.items()
                      if score >= max(MIN_MODERATION_THRESHOLD, threshold))


THINKING_TIMEOUT_SECONDS = 30.0
THINKING_REASONING_MAX_CHARS = 1000
THINKING_VERDICTS = frozenset({"safe", "unsafe", "unknown"})


def parse_thinking(raw: Any, scores: dict[str, float]) -> dict[str, Any]:
    """Keep only well-formed per-category verdicts from the classifier's thinking block.
    Malformed parts are dropped rather than trusted; scores were already validated."""
    heads: dict[str, Any] = {}
    raw_heads = raw.get("heads") if isinstance(raw, dict) else None
    if isinstance(raw_heads, dict):
        for head, item in raw_heads.items():
            if head not in scores or not isinstance(item, dict):
                continue
            verdict = item.get("verdict")
            reasoning = item.get("reasoning")
            if verdict not in THINKING_VERDICTS or not isinstance(reasoning, str):
                continue
            entry: dict[str, Any] = {
                "verdict": verdict,
                "reasoning": reasoning.strip()[:THINKING_REASONING_MAX_CHARS],
                "forced_answer": bool(item.get("forced_answer")),
            }
            for key in ("classifier_score", "final_score"):
                value = item.get(key)
                if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0 <= value <= 1:
                    entry[key] = float(value)
            heads[head] = entry
    return {"used": True, "heads": heads}


def validate_model_base_url(base_url: str) -> str:
    parsed = urlsplit(base_url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("LOCAL_AI_BASE_URL must be an HTTP(S) API URL without credentials or query")
    hostname = parsed.hostname.lower().rstrip(".")
    if hostname == "openai.com" or hostname.endswith(".openai.com"):
        raise ValueError("LOCAL_AI_BASE_URL must point to the self-hosted model")
    return base_url.rstrip("/")


class StoatGuardModerator:
    """Production client for StoatGuard's fixed text and vision endpoints."""

    SUPPORTED_IMAGE_TYPES = frozenset({
        "image/gif", "image/jpeg", "image/png", "image/webp",
    })

    def __init__(
        self,
        *,
        base_url: str,
        expected_version: str,
        api_key: str = "",
        timeout_seconds: float = 45,
        max_image_bytes: int = 10 * 1024 * 1024,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        import aiohttp

        self._aiohttp = aiohttp
        self.base_url = validate_model_base_url(base_url)
        self.expected_version = expected_version.strip()
        if not self.expected_version:
            raise ValueError("LOCAL_AI_EXPECTED_VERSION is required")
        self.api_key = api_key
        self.text_endpoint = self.base_url + "/classify"
        self.image_endpoint = self.base_url + "/classify-image"
        self.health_endpoint = self.base_url + "/health"
        self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self.max_image_bytes = int(max_image_bytes)
        self._session = session
        self._owns_session = session is None

    async def __aenter__(self) -> "StoatGuardModerator":
        if self._session is None:
            self._session = self._aiohttp.ClientSession(timeout=self.timeout)
        try:
            await self.verify_health()
        except ModerationError:
            # Start anyway: commands, logs and the non-AI protections keep working, and each scan
            # fails open until the classifier answers again (every response is version-checked).
            logger.warning("stoatguard_unavailable_at_startup", exc_info=True)
        except BaseException:
            if self._owns_session and self._session is not None:
                await self._session.close()
                self._session = None
            raise
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._owns_session and self._session is not None:
            await self._session.close()
            self._session = None

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def _request_json(
        self, method: str, endpoint: str, *, payload: dict[str, Any] | None = None,
        timeout: Any = None,
    ) -> dict[str, Any]:
        if self._session is None:
            raise RuntimeError(
                "StoatGuardModerator must be used as an async context manager"
            )
        try:
            async with self._session.request(
                method,
                endpoint,
                headers=self._headers(),
                json=payload,
                timeout=timeout or self.timeout,
                allow_redirects=False,
            ) as response:
                if response.status != 200:
                    raise ModerationError(
                        f"StoatGuard returned HTTP {response.status}"
                    )
                body = await response.json(content_type=None)
        except ModerationError:
            raise
        except (self._aiohttp.ClientError, TimeoutError, ValueError) as exc:
            raise ModerationError("StoatGuard request failed") from exc
        if not isinstance(body, dict):
            raise ModerationError("StoatGuard returned invalid JSON")
        return body

    async def verify_health(self) -> dict[str, Any]:
        body = await self._request_json("GET", self.health_endpoint)
        if body.get("ok") is not True:
            raise ModerationError("StoatGuard health check failed")
        if body.get("version") != self.expected_version:
            raise ModerationError("StoatGuard version does not match the pinned release")
        vision = body.get("vision")
        if (
            not isinstance(vision, dict)
            or vision.get("enabled") is not True
            or set(vision.get("image_categories") or ())
            != IMAGE_MODERATION_CATEGORIES
        ):
            raise ModerationError("StoatGuard vision policy does not match production")
        return body

    def _validate_result(
        self,
        data: Any,
        *,
        expected_categories: frozenset[str],
    ) -> ModerationResult:
        if not isinstance(data, dict) or data.get("version") != self.expected_version:
            raise ModerationError("StoatGuard returned an unexpected model version")
        raw_scores = data.get("scores")
        raw_fired = data.get("fired")
        if not isinstance(raw_scores, dict) or set(raw_scores) != expected_categories:
            raise ModerationError("StoatGuard returned an unexpected category set")
        if not isinstance(raw_fired, list) or any(
            not isinstance(name, str) or name not in expected_categories
            for name in raw_fired
        ):
            raise ModerationError("StoatGuard returned invalid fired categories")
        scores: dict[str, float] = {}
        for category, value in raw_scores.items():
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0 <= value <= 1
            ):
                raise ModerationError(
                    f"StoatGuard returned an invalid score for {category}"
                )
            scores[category] = float(value)
        fired = set(raw_fired)
        categories = {name: name in fired for name in scores}
        return ModerationResult(
            flagged=any(
                active and name not in SUPPORT_ONLY_CATEGORIES
                for name, active in categories.items()
            ),
            categories=categories,
            scores=scores,
            score_kind="stoatguard_policy_score",
        )

    async def classify_text(self, text: str, *, thinking: bool = False) -> ModerationResult:
        """Classify one message. With thinking=True the classifier's reasoning verifier
        double-checks borderline categories; if that request fails or is too slow, the
        message is classified normally so moderation never waits on the verifier."""
        if thinking:
            try:
                return await self._classify_text_once(text, thinking=True)
            except ModerationError:
                pass
        return await self._classify_text_once(text, thinking=False)

    async def _classify_text_once(self, text: str, *, thinking: bool) -> ModerationResult:
        payload: dict[str, Any] = {"texts": [text]}
        if thinking:
            payload["thinking"] = True
        body = await self._request_json(
            "POST", self.text_endpoint, payload=payload,
            timeout=(
                self._aiohttp.ClientTimeout(total=min(THINKING_TIMEOUT_SECONDS, self.timeout.total or THINKING_TIMEOUT_SECONDS))
                if thinking else None
            ),
        )
        if body.get("version") != self.expected_version:
            raise ModerationError("StoatGuard returned an unexpected model version")
        results = body.get("results")
        if not isinstance(results, list) or len(results) != 1:
            raise ModerationError("StoatGuard returned an unexpected text response")
        result = self._validate_result(
            results[0],
            expected_categories=frozenset(
                category
                for category in SUPPORTED_MODERATION_CATEGORIES
                if category not in IMAGE_MODERATION_CATEGORIES - {SEXUAL_CATEGORY}
            ),
        )
        if not thinking:
            return result
        details = parse_thinking(results[0].get("thinking"), result.scores)
        return ModerationResult(
            flagged=result.flagged, categories=result.categories, scores=result.scores,
            score_kind=result.score_kind, action_exempt=result.action_exempt, thinking=details,
        )

    async def _validate_public_image_url(self, url: str) -> None:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ModerationError("Image must use a public HTTPS URL")
        try:
            addresses = [ipaddress.ip_address(parsed.hostname)]
        except ValueError:
            try:
                infos = await asyncio.get_running_loop().getaddrinfo(
                    parsed.hostname,
                    parsed.port or 443,
                    type=socket.SOCK_STREAM,
                )
            except socket.gaierror as exc:
                raise ModerationError("Image host does not resolve") from exc
            addresses = list({ipaddress.ip_address(info[4][0]) for info in infos})
        if not addresses or any(not address.is_global for address in addresses):
            raise ModerationError("Image host resolves to a non-public address")

    async def _download_image(self, image_url: str) -> str:
        if self._session is None:
            raise RuntimeError(
                "StoatGuardModerator must be used as an async context manager"
            )
        url = image_url
        for _ in range(4):
            await self._validate_public_image_url(url)
            try:
                async with self._session.get(
                    url, allow_redirects=False, timeout=self.timeout
                ) as response:
                    if response.status in {301, 302, 303, 307, 308}:
                        location = response.headers.get("Location", "")
                        if not location:
                            raise ModerationError("Image redirect was invalid")
                        url = urljoin(url, location)
                        continue
                    if response.status != 200:
                        raise ModerationError(
                            f"Image download returned HTTP {response.status}"
                        )
                    mime = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
                    if mime not in self.SUPPORTED_IMAGE_TYPES:
                        raise ModerationError("Image format is not supported")
                    if (
                        response.content_length is not None
                        and response.content_length > self.max_image_bytes
                    ):
                        raise ModerationError("Image exceeds the configured size limit")
                    data = bytearray()
                    async for chunk in response.content.iter_chunked(65536):
                        data.extend(chunk)
                        if len(data) > self.max_image_bytes:
                            raise ModerationError(
                                "Image exceeds the configured size limit"
                            )
            except ModerationError:
                raise
            except (self._aiohttp.ClientError, TimeoutError) as exc:
                raise ModerationError("Image download failed") from exc
            if not data:
                raise ModerationError("Image was empty")
            return "data:" + mime + ";base64," + base64.b64encode(data).decode("ascii")
        raise ModerationError("Image had too many redirects")

    async def classify_url(self, image_url: str) -> ModerationResult:
        image_data = await self._download_image(image_url)
        body = await self._request_json(
            "POST",
            self.image_endpoint,
            payload={"image": image_data, "caption": "", "policy_mode": "stoat"},
        )
        if body.get("version") != self.expected_version:
            raise ModerationError("StoatGuard returned an unexpected model version")
        return self._validate_result(
            body.get("result"), expected_categories=IMAGE_MODERATION_CATEGORIES
        )
