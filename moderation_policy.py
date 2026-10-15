"""Moderation categories shared by the bot, the dashboard API and the database."""
from __future__ import annotations

MIN_ACTION_SCORE = 0.90
# Configurable action thresholds are independent of the classifier's default labels.
MIN_MODERATION_THRESHOLD = 0.0
SUPPORT_CATEGORY = "suicidal-thoughts"
CREDENTIALS_CATEGORY = "credentials"
SUPPORT_ONLY_CATEGORIES = frozenset({SUPPORT_CATEGORY, CREDENTIALS_CATEGORY})
SEXUAL_CATEGORY = "sexual"
SEXUAL_MINORS_CATEGORY = "sexual/minors"
# The production classifier returns these twelve policy heads.  Violence and
# adult sexual content are also the only two image-moderation categories.
IMAGE_MODERATION_CATEGORIES = frozenset({"violence", SEXUAL_CATEGORY})
CATEGORY_LABELS = {
    CREDENTIALS_CATEGORY: "Live credentials of your own account",
    "violent-extremism": "Violent extremism",
    "hate": "Hate speech",
    "hateful-conduct": "Hateful conduct",
    "self-harm/promotion": "Encouraging or promoting self harm",
    "illicit": "Illegal content",
    "violence": "Violent or graphic image content",
    "scams": "Financial scams / scams",
    "unsolicited-advertising": "Unsolicited advertising",
    SEXUAL_MINORS_CATEGORY: "Sexual content involving minors",
    SUPPORT_CATEGORY: "Suicidal thoughts",
    SEXUAL_CATEGORY: "Adult sexual content",
}
SUPPORTED_MODERATION_CATEGORIES = tuple(CATEGORY_LABELS)
PROTECTED_MODERATION_CATEGORY_PREFIXES = (SUPPORT_CATEGORY, CREDENTIALS_CATEGORY)
# Preserve relevant saved preferences; historical case evidence is untouched.
LEGACY_CATEGORY_ALIASES = {
    "harassment": "hateful-conduct",
    "self-harm/intent": SUPPORT_CATEGORY,
    "self-harm": SUPPORT_CATEGORY,
    "self-harm/instructions": "self-harm/promotion",
    "violence/graphic": "violence",
    "animal-violence": "violence",
}
