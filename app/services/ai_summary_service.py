"""
Service de résumé IA pour les négociations de contrats.

Utilise :
  - Groq API (cloud, gratuit) si GROQ_API_KEY est définie
  - Fallback heuristique (regex + mots-clés) sinon

Le service extrait les modifications demandées par le client
à partir de la conversation de chat.
"""
import json
import os
import re

import requests
from flask import current_app


# =========================================================================
#  Configuration
# =========================================================================
AI_PROVIDER = os.getenv("AI_PROVIDER", "heuristic").lower()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "openai/gpt-oss-20b"
TIMEOUT_SECONDS = 30


# =========================================================================
#  Prompt pour l'IA
# =========================================================================
PROMPT_TEMPLATE = """Tu es un assistant qui analyse une conversation \
entre un client et un manager de contrats.

Voici la conversation :
---
{conversation}
---

Analyse cette conversation et extrait TOUTES les modifications demandées \
par le client au manager (dates, description, titre, type de contrat, etc.).

Retourne UNIQUEMENT un objet JSON valide avec cette structure exacte :
{{
  "modifications": [
    {{
      "champ": "date_fin",
      "ancien": "31/10/2026",
      "nouveau": "15/12/2026",
      "raison": "Le client a besoin de plus de temps"
    }}
  ],
  "resume": "Résumé en 2 phrases maximum de l'accord trouvé"
}}

Champs possibles : titre, description, date_debut, date_fin, contract_type, autre.

Règles :
- Si aucune modification n'est clairement demandée, retourne :
  {{"modifications": [], "resume": "Aucune modification demandée"}}
- Ne JAMAIS inclure de texte en dehors du JSON
- Utilise uniquement les champs listés ci-dessus
- Si une date est mentionnée sans contexte, utilise "date_fin"
"""


# =========================================================================
#  Helpers
# =========================================================================
def _format_conversation(messages) -> str:
    """
    Formate les messages du chat pour le prompt.
    `messages` : liste de dicts avec sender_role et content.
    """
    lines = []
    for m in messages:
        role = m.get("sender_role", "USER")
        content = m.get("content", "")
        # Renommer les rôles pour être plus clair pour l'IA
        if role == "CLIENT":
            who = "Client"
        elif role == "MANAGER":
            who = "Manager"
        elif role == "ADMIN":
            who = "Admin"
        elif role == "SYSTEM":
            who = "Système"
        else:
            who = "Utilisateur"
        lines.append(f"{who}: {content}")
    return "\n".join(lines)


def _extract_json(text: str) -> dict:
    """
    Extrait un objet JSON d'une réponse qui pourrait contenir du texte
    autour (l'IA ne respecte pas toujours la consigne).
    """
    # Chercher la première { et la dernière }
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("Pas de JSON trouvé dans la réponse.")
    return json.loads(text[start:end + 1])


# =========================================================================
#  Provider : Groq
# =========================================================================
def _call_groq(prompt: str) -> dict:
    """Appelle l'API Groq et retourne le JSON parsé."""
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY manquante.")

    response = requests.post(
        GROQ_URL,
        headers={
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": GROQ_MODEL,
            "messages": [
                {"role": "system", "content": "Tu réponds uniquement en JSON."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        },
        timeout=TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    data = response.json()
    text = data["choices"][0]["message"]["content"]
    return _extract_json(text)


# =========================================================================
#  Fallback : heuristique
# =========================================================================
def _fallback_heuristic(conversation: str) -> dict:
    """
    Analyse par mots-clés si l'IA n'est pas disponible.
    Détecte les champs mentionnés et les dates.
    """
    modifications = []
    lower = conversation.lower()

    # Dictionnaire des champs et de leurs mots-clés
    keywords = {
        "date_fin":      ["date de fin", "expiration", "date finale",
                          "échéance", "fin du contrat"],
        "date_debut":    ["date de début", "commencement", "début du contrat"],
        "description":   ["description", "clause", "texte", "contenu"],
        "titre":         ["titre", "nom du contrat", "intitulé"],
        "contract_type": ["type de contrat", "type"],
    }

    # Chercher toutes les dates dans la conversation
    dates = re.findall(r"\b(\d{1,2}[/-]\d{1,2}[/-]\d{4})\b", conversation)

    for champ, kws in keywords.items():
        for kw in kws:
            if kw in lower:
                # Trouver la phrase qui contient le mot-clé
                idx = lower.find(kw)
                snippet = conversation[max(0, idx - 80):idx + 120].strip()

                modifications.append({
                    "champ":   champ,
                    "ancien":  "—",
                    "nouveau": dates[-1] if dates else "À préciser",
                    "raison":  f"Détecté : « {snippet[:80]}… »",
                })
                break  # un seul match par champ

    if modifications:
        resume = f"{len(modifications)} modification(s) potentielle(s) " \
                 f"détectée(s) par analyse heuristique."
    else:
        resume = "Aucune modification détectée dans la conversation."

    return {
        "modifications": modifications,
        "resume":        resume,
        "provider":      "heuristic",
        "error":         None,
    }


# =========================================================================
#  Fonction principale
# =========================================================================
def summarize_modifications(messages) -> dict:
    """
    Analyse une conversation et retourne un résumé structuré.

    Paramètre :
        messages : liste de dicts avec 'sender_role' et 'content'
                   (format retourné par chat_service.list_messages)

    Retourne :
        {
            "modifications": [...],
            "resume": "...",
            "provider": "groq" | "heuristic" | "none",
            "error": None | "message d'erreur"
        }
    """
    if not messages:
        return {
            "modifications": [],
            "resume":        "Aucune conversation.",
            "provider":      "none",
            "error":         None,
        }

    # Filtrer les messages système pour l'analyse
    user_messages = [
        m for m in messages
        if m.get("sender_role") in ("CLIENT", "MANAGER", "ADMIN")
    ]
    if not user_messages:
        return {
            "modifications": [],
            "resume":        "Aucun échange entre utilisateurs.",
            "provider":      "none",
            "error":         None,
        }

    conversation = _format_conversation(user_messages)

    # --- Tentative Groq
    if AI_PROVIDER == "groq" and GROQ_API_KEY:
        try:
            prompt = PROMPT_TEMPLATE.format(conversation=conversation)
            result = _call_groq(prompt)
            # S'assurer que la structure est correcte
            result.setdefault("modifications", [])
            result.setdefault("resume", "")
            result["provider"] = "groq"
            result["error"] = None

            current_app.logger.info(
                "[AI] Résumé généré par Groq : %d modification(s)",
                len(result["modifications"])
            )
            return result
        except Exception as e:
            current_app.logger.warning(
                "[AI] Échec Groq → fallback heuristique : %s", e)
            fallback = _fallback_heuristic(conversation)
            fallback["error"] = f"Groq indisponible : {type(e).__name__}"
            return fallback

    # --- Fallback heuristique par défaut
    return _fallback_heuristic(conversation)


# =========================================================================
#  Vérification de l'état du service
# =========================================================================
def get_provider_info() -> dict:
    """Retourne des infos sur le provider actif."""
    return {
        "provider":    AI_PROVIDER,
        "groq_ready":  bool(GROQ_API_KEY),
        "model":       GROQ_MODEL if AI_PROVIDER == "groq" else None,
    }