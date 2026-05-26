#!/usr/bin/env python3
from __future__ import annotations

import argparse
import difflib
import json
import re
from typing import Any

from core.app_paths import ensure_runtime_dirs
from core.config_loader import load_all_config
from core.llm_client import ask_ollama
from core.prompt_builder import (
    build_classifier_prompt,
    build_followup_prompt,
    build_grounded_answer_prompt,
    build_repair_prompt,
    build_system_prompt,
)
from core.session_store import SessionStore
from core.tool_registry import build_registry
from orchestrator import execute_tool_call, extract_json_tool_call
from tools.local_tools import _find_default_wordlist, _resolve_wordlist_alias
from tools.wifi_deep_report import _is_likely_sibling_radio


def _cfg_get(cfg: dict[str, Any], *keys: str, default: Any = None) -> Any:
    cur: Any = cfg
    for key in keys:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def _ask_model(cfg: dict[str, Any], prompt: str, temperature: float | None = None) -> str:
    config = cfg["config"]
    ollama = config["ollama"]
    return ask_ollama(
        prompt=prompt,
        model_name=ollama["model_name"],
        ollama_url=ollama["url"],
        temperature=ollama["temperature"] if temperature is None else temperature,
        top_p=ollama.get("top_p", 0.1),
        num_predict=ollama["num_predict"],
        timeout=ollama["timeout_sec"],
    ).strip()


def _extract_json_object(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if not text.startswith("{") or not text.endswith("}"):
        return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def _extract_pure_json_tool_call(text: str) -> dict[str, Any] | None:
    """
    Extract a tool-call JSON object from model output.
    Uses the balanced-brace scanner from orchestrator for robustness
    against mixed-prose replies.
    """
    if not isinstance(text, str) or not text.strip():
        return None
    return extract_json_tool_call(text.strip())


def _looks_like_attempted_tool_call(text: str) -> bool:
    t = text.strip()
    return ("action" in t or '"action"' in t or '"type"' in t) and "{" in t and "}" in t


def _normalize_user_text(text: str) -> str:
    """
    Normalize common operator phrasing and typo variants before intent routing.
    This preserves user meaning while making tool selection much more reliable.
    """
    out = text

    replacements: list[tuple[str, str]] = [
        (r"\bdeuth\b", "deauth"),
        (r"\bdeath and capture\b", "deauth and capture"),
        (r"\bdo a death and capture\b", "do a deauth and capture"),
        (r"\bperform a death and capture\b", "perform a deauth and capture"),
        (r"\bdo a deauth and scan\b", "do a deauth and capture"),
        (r"\bperform a deauth and scan\b", "perform a deauth and capture"),
        (r"\bdisconnect and capture\b", "deauth and capture"),
        (r"\bdeauthentication and capture\b", "deauth and capture"),
        (r"\bde-auth and capture\b", "deauth and capture"),
        (r"\bde auth and capture\b", "deauth and capture"),
        (r"\bhandshake capture\b", "deauth and capture"),
        (r"\bcapture a handshake\b", "deauth and capture"),
        (r"\bget a handshake\b", "deauth and capture"),
        (r"\bdeepy\b", "deep"),
        (r"\bdeeply analysis\b", "deep analysis"),
        (r"\bscan nearby networks until you find\b", "scan until you find"),
        (r"\blook until you find\b", "scan until you find"),
    ]

    for pattern, repl in replacements:
        out = re.sub(pattern, repl, out, flags=re.IGNORECASE)

    return out


def _extract_all_macs(text: str) -> list[str]:
    matches = re.findall(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", text)
    seen: set[str] = set()
    ordered: list[str] = []
    for m in matches:
        mac = m.upper()
        if mac not in seen:
            seen.add(mac)
            ordered.append(mac)
    return ordered


def _extract_bssid(text: str) -> str | None:
    patterns = [
        r"\bbssid\s+(?:is\s+)?((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\b",
        r"\bap\s+(?:bssid\s+)?((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\b",
        r"\baccess point\s+(?:bssid\s+)?((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\b",
    ]
    for pattern in patterns:
        m = re.search(pattern, text, flags=re.IGNORECASE)
        if m:
            return m.group(1).upper()

    macs = _extract_all_macs(text)
    if not macs:
        return None
    return macs[0]


def _extract_target_mac(text: str, bssid: str | None = None) -> str | None:
    patterns = [
        r"\btarget(?:\s+mac)?\s+(?:is\s+)?((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\b",
        r"\btargeting\s+(?:client|station|sta|device)?\s*((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\b",
        r"\bon target\s+((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\b",
        r"\bclient(?:\s+mac)?\s+(?:is\s+)?((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\b",
        r"\bstation(?:\s+mac)?\s+(?:is\s+)?((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\b",
        r"\bsta(?:\s+mac)?\s+(?:is\s+)?((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\b",
    ]
    for pattern in patterns:
        m = re.search(pattern, text, flags=re.IGNORECASE)
        if m:
            return m.group(1).upper()

    macs = _extract_all_macs(text)
    if not macs:
        return None

    if bssid:
        bssid = bssid.upper()
        for mac in macs:
            if mac != bssid:
                return mac
        return None

    if len(macs) >= 2:
        return macs[1]

    return None


def _extract_channel(text: str) -> int | None:
    patterns = [
        r"\bchannel\s+(\d{1,3})\b",
        r"\bch\s+(\d{1,3})\b",
    ]
    for pattern in patterns:
        m = re.search(pattern, text, flags=re.IGNORECASE)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                return None
    return None


def _extract_password_from_text(text: str) -> str | None:
    """Extract a plaintext password/passphrase from user input."""
    patterns = [
        r'\bpassword\s+is\s+["\']?(\S+)["\']?',
        r'\busing\s+(?:the\s+)?password\s+["\']?(\S+)["\']?',
        r'\bwith\s+(?:the\s+)?password\s+["\']?(\S+)["\']?',
        r'\bpassword[:\s]+["\']?(\S+)["\']?',
        r'\bpwd[:\s]+["\']?(\S+)["\']?',
        r'\bpsk[:\s]+["\']?(\S+)["\']?',
    ]
    for pattern in patterns:
        m = re.search(pattern, text, flags=re.IGNORECASE)
        if m:
            candidate = m.group(1).strip().strip('"\'')
            if candidate:
                return candidate
    return None


def _extract_connect_ssid_from_text(text: str) -> str | None:
    """
    Extract an SSID from connect-intent phrasing like
    'connect to <SSID> using/with password ...' or 'join <SSID> with password ...'.
    This handles forms that _extract_ssid_from_free_text misses because the SSID
    is not at end-of-line.
    """
    _pw_keywords = {"password", "using", "with", "pwd", "psk", "key", "the", "a"}
    patterns = [
        r'\bconnect(?:\s+the\s+pineapple)?\s+to\s+(.+?)\s+(?:using|with)\s+(?:the\s+)?(?:password|pwd|psk|key)',
        r'\bjoin\s+(.+?)\s+(?:using|with)\s+(?:the\s+)?(?:password|pwd|psk|key)',
        r'\bconnect\s+to\s+(\S+)\s*$',
        r'\bjoin\s+(\S+)\s*$',
    ]
    for pattern in patterns:
        m = re.search(pattern, text, flags=re.IGNORECASE)
        if m:
            candidate = m.group(1).strip().strip('"\'')
            if candidate and candidate.lower() not in _pw_keywords:
                return candidate
    return None


def _looks_like_deauth_capture_intent(text: str) -> bool:
    lowered = text.lower()

    deauth_terms = [
        "deauth",
        "deauthentication",
        "disconnect",
        "kick off",
        "kick off clients",
    ]
    capture_terms = [
        "capture",
        "handshake",
        "eapol",
    ]

    has_deauthish = any(term in lowered for term in deauth_terms)
    has_captureish = any(term in lowered for term in capture_terms)

    return has_deauthish and has_captureish


def _looks_like_hcx_capture_intent(text: str) -> bool:
    """Return True when the user explicitly requests HCX/PMKID-style capture."""
    lowered = text.lower()
    hcx_terms = [
        "hcxdumptool",
        "hcx capture",
        "use hcx",
        "try hcx",
        "hcx instead",
        "pmkid",
        "pmkid capture",
        "pmf capture",
        "no deauth",
        "don't deauth",
        "dont deauth",
        "without deauth",
        "instead of deauth",
        "instead of normal deauth",
        "802.11w capture",
        "skip deauth",
        "avoid deauth",
    ]
    # Also match bare "hcx" as a standalone word (not part of another word)
    if re.search(r'\bhcx\b', lowered):
        return True
    return any(term in lowered for term in hcx_terms)


def _looks_like_connect_intent(text: str) -> bool:
    """Return True when the user wants the Pineapple to join a wireless network."""
    lowered = text.lower()
    phrases = [
        "connect to ",
        "connect the pineapple to ",
        "connect using password",
        "connect with password",
        "join network",
        "join the network",
        "connect pineapple to",
    ]
    # "join " as a standalone phrase - be careful not to match "join" as part of another word
    if re.search(r'\bjoin\s+\S', lowered):
        return True
    return any(p in lowered for p in phrases)


def _is_greeting_or_smalltalk(text: str) -> bool:
    # Strip trailing punctuation and whitespace before comparing
    cleaned = re.sub(r'[\s!.?]+$', '', text.lower().strip())
    simple = {
        "hi", "hello", "hey", "good evening", "good morning", "good afternoon",
        "good night", "good day", "thanks", "thank you", "nice", "cool",
        "ok", "okay", "cheers", "howdy", "sup", "yo",
    }
    if cleaned in simple:
        return True
    if re.fullmatch(r"(hi+|hello+|hey+|howdy|sup|yo)[!.? ]*", text.lower().strip()):
        return True
    if re.fullmatch(r"good (evening|morning|afternoon|night|day)[!.? ]*", text.lower().strip()):
        return True
    return False


def _smalltalk_reply(text: str) -> str | None:
    # Strip trailing punctuation and whitespace before comparing
    cleaned = re.sub(r'[\s!.?]+$', '', text.lower().strip())
    if re.match(r'^good evening', cleaned):
        return "Good evening."
    if re.match(r'^good morning', cleaned):
        return "Good morning."
    if re.match(r'^good afternoon', cleaned):
        return "Good afternoon."
    if re.match(r'^good (night|day)', cleaned):
        return "Hello."
    if cleaned in {"hi", "hello", "hey", "howdy", "sup", "yo"}:
        return "Hello."
    if cleaned in {"thanks", "thank you", "cheers"}:
        return "You're welcome."
    if cleaned in {"ok", "okay", "nice", "cool"}:
        return "Got it."
    return None


def _looks_like_live_wireless_request(text: str) -> bool:
    """Return True only if the text looks like it needs a live observation.

    A conceptual question that merely *mentions* wireless terms (e.g., "what
    can a hacker gain from hacking into a guest wifi") must NOT trigger this.
    We require both a wireless-topic keyword AND an action/observation verb
    that implies the user wants something done *now* against real hardware.
    """
    t = text.lower()

    # Bail early if this is a conceptual question - even if wireless keywords
    # appear, the user is asking for an explanation, not a live action.
    if _is_definition_question(text):
        return False

    # Action verbs that imply the user wants a live observation or operation.
    action_verbs = [
        "scan", "capture", "find", "identify", "show", "list", "check",
        "look for", "discover", "detect", "monitor", "sniff", "deauth",
        "analyze", "analyse", "connect", "join", "run", "start", "do a",
        "get me", "give me a report", "tell me what's nearby",
    ]
    # Wireless-context keywords.
    wireless_keywords = [
        "ssid", "ssids", "bssid", "bssids", "nearby", "pineapple",
        "access point", "access points", "pcap", "beacon", "probe",
        "handshake", "handshakes", "eapol", "wlan", "monitor mode",
    ]
    has_action = any(v in t for v in action_verbs)
    has_wireless = any(k in t for k in wireless_keywords)

    # If the text contains a MAC address and a channel, that's an explicit
    # live request regardless of phrasing.
    if _extract_bssid(text) and _extract_channel(text) is not None:
        return True

    return has_action and has_wireless


def _requested_count(text: str) -> int | None:
    lowered = text.lower()
    number_words = {
        "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
        "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
        "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
        "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20,
    }
    for word, value in number_words.items():
        if re.search(rf"\b{re.escape(word)}\b", lowered):
            return value

    matches = re.findall(r"\b(\d+)\b", lowered)
    if not matches:
        return None

    n = int(matches[-1])
    return max(1, min(n, 50))


def _extract_ssid_from_free_text(text: str) -> str | None:
    s = text.strip()

    quoted = re.findall(r'"([^"]+)"|\'([^\']+)\'', s)
    for pair in quoted:
        candidate = next((x for x in pair if x), "").strip()
        if candidate:
            return candidate

    patterns = [
        r"\bsummary of ([^\n\r]+?)\s*$",
        r"\bsummary for ([^\n\r]+?)\s*$",
        r"\bdetails? on ([^\n\r]+?)\s*$",
        r"\bdetails? for ([^\n\r]+?)\s*$",
        r"\breport on ([^\n\r]+?)\s*$",
        r"\breport for ([^\n\r]+?)\s*$",
        r"\banaly[sz]e ([^\n\r]+?)\s*$",
        r"\bin-?depth analysis on ([^\n\r]+?)\s*$",
        r"\bin-?depth analysis for ([^\n\r]+?)\s*$",
        r"\beverything on ([^\n\r]+?)\s*$",
        r"\bfull report on ([^\n\r]+?)\s*$",
        r"\bclients on ([^\n\r]+?)\s*$",
        r"\bclients for ([^\n\r]+?)\s*$",
        r"\bhandshakes on ([^\n\r]+?)\s*$",
        r"\bhandshakes for ([^\n\r]+?)\s*$",
        r"\babout ([^\n\r]+?)\s*$",
        r"\bnetwork scan on ([^\n\r]+?)\s*$",
        r"\bscan on ([^\n\r]+?)\s*$",
        r"\bfind the ssid ([^\n\r]+?)\s*$",
        r"\blook for the ssid ([^\n\r]+?)\s*$",
        r"\bdid you see ([^\n\r]+?)\s*$",
        r"\bscan until you find ([^\n\r]+?)\s*$",
        r"\blook for ([^\n\r]+?)\s*$",
        r"\bfind ([^\n\r]+?)\s*$",
    ]
    for pattern in patterns:
        m = re.search(pattern, s, flags=re.IGNORECASE)
        if m:
            candidate = m.group(1).strip().strip('"').strip("'").strip().strip(",")
            if candidate:
                return candidate

    return None


def _analysis_mode_for_text(text: str) -> str:
    lowered = text.lower()

    client_markers = [
        # Explicit client queries - order matters: longer/more specific first
        "how many clients", "connected clients", "clients are connected", "show clients",
        "client activity", "capture handshakes", "handshakes", "eapol", "stations",
        "connected or any observed handshakes", "connected clients on",
        # Additional patterns that clearly express client-finding intent
        "find clients", "list clients", "clients on", "clients for",
        "who is connected", "who's connected", "who are connected",
        "show me clients", "get clients", "see clients",
        "any clients", "check clients",
    ]
    if any(marker in lowered for marker in client_markers):
        return "clients"

    deep_markers = [
        "in-depth", "indepth", "deep analysis", "full report", "everything",
        "all information", "all info", "complete analysis", "detailed analysis",
        "look for handshakes",
        "deep ",
    ]
    if any(marker in lowered for marker in deep_markers):
        return "deep"

    return "summary"


def _validate_tool_call(cfg: dict[str, Any], tool_call: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(tool_call, dict):
        return None

    # Flatten params-wrapped structure that some LLMs produce:
    # {"action": "...", "params": {"key": val}} → {"action": "...", "key": val}
    # Then also flatten options-wrapped structure (e.g.
    # {"action":"crack_wifi_pcap","options":{"capture_file":"..."}}). Top-level
    # keys still win because we only setdefault.
    if isinstance(tool_call.get("params"), dict):
        flat: dict[str, Any] = {k: v for k, v in tool_call.items() if k != "params"}
        for k, v in tool_call["params"].items():
            flat.setdefault(k, v)
        tool_call = flat

    if isinstance(tool_call.get("options"), dict):
        flat = {k: v for k, v in tool_call.items() if k != "options"}
        for k, v in tool_call["options"].items():
            flat.setdefault(k, v)
        tool_call = flat

    action = tool_call.get("action")
    if not isinstance(action, str):
        return None

    registry = build_registry(cfg)
    if action not in registry:
        return None

    # ── nmap_scan / pineapple_nmap_scan: require target, reject hallucinated fields ──
    if action in ('nmap_scan', 'pineapple_nmap_scan'):
        for bad_key in ('hosts_file', 'output_file', 'host', 'hosts', 'file'):
            tool_call.pop(bad_key, None)
        if not tool_call.get('target'):
            return None

    # ── pineapple_subnet_map: require target, normalize stages/aggressive ──
    if action == 'pineapple_subnet_map':
        for bad_key in ('hosts_file', 'output_file', 'host', 'hosts', 'file'):
            tool_call.pop(bad_key, None)
        if not tool_call.get('target'):
            return None
        raw_stages = tool_call.get('stages')
        if isinstance(raw_stages, str):
            tool_call['stages'] = [raw_stages]
        elif not isinstance(raw_stages, list):
            tool_call['stages'] = ['discover', 'ports', 'services', 'os']
        if 'aggressive' in tool_call:
            tool_call['aggressive'] = bool(tool_call['aggressive'])
        iface_val = tool_call.get('interface')
        if iface_val is None or not str(iface_val).strip():
            tool_call['interface'] = 'wlan2'

    # ── pineapple_arpspoof: require target_ip ──
    if action == 'pineapple_arpspoof' and not tool_call.get('target_ip'):
        return None

    return tool_call


def _known_ssids_from_result(result: Any) -> list[str]:
    names: list[str] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(key, str) and key.lower() == "ssid" and isinstance(value, str):
                    v = value.strip()
                    if v and v not in names:
                        names.append(v)
                elif isinstance(key, str) and key.lower() == "ssids" and isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            v = item.strip()
                            if v and v not in names:
                                names.append(v)
                        elif isinstance(item, dict):
                            walk(item)
                elif isinstance(key, str) and key.lower() == "networks" and isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            walk(item)
                else:
                    walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(result)
    return names


def _known_ssids_from_session(store: SessionStore, session_id: str) -> list[str]:
    names: list[str] = []
    for item in store.items(session_id):
        if item.get("type") == "tool":
            result = item.get("result", {})
            for ssid in _known_ssids_from_result(result):
                if ssid not in names:
                    names.append(ssid)
    return names


def _match_known_ssid_in_text(text: str, known_ssids: list[str]) -> str | None:
    lowered = text.lower()

    for ssid in sorted(known_ssids, key=len, reverse=True):
        if ssid.lower() in lowered:
            return ssid

    tokens = re.findall(r"[A-Za-z0-9._-]+", text)
    for token in tokens:
        matches = difflib.get_close_matches(token, known_ssids, n=1, cutoff=0.88)
        if matches:
            return matches[0]

    explicit = _extract_ssid_from_free_text(text)
    if explicit:
        matches = difflib.get_close_matches(explicit, known_ssids, n=1, cutoff=0.88)
        if matches:
            return matches[0]

    return None


def _is_definition_question(text: str) -> bool:
    """Return True if the text is a conceptual / educational question that
    should be answered with normal LLM prose rather than a live tool call.

    The check is deliberately broad: any question-like phrasing about wireless,
    security, or hacking concepts should be caught here as long as it does NOT
    contain live-action or current-environment indicators.
    """

    lowered = text.lower().strip()

    starters = [
        # Classic definition/explanation openers
        "what is ", "what are ", "what's ", "what're ",
        "explain ", "can you explain ", "define ", "tell me about ",
        "how does ", "how do ", "how is ", "how are ",
        "describe ", "can you describe ", "walk me through ",
        "what is the difference", "what's the difference",
        "compare ", "why does ", "why is ", "tell me how ",
        # Broader conceptual openers (the gap that let "what can a hacker..."
        # fall through to the tool pipeline)
        "what can ", "what could ", "what would ", "what might ",
        "what happens ", "what should ", "what kind ", "what types ",
        "what risks ", "what threats ", "what damage ",
        "how can ", "how could ", "how would ", "how might ",
        "why can ", "why could ", "why would ", "why might ",
        "is it possible ", "is there a way ", "is it true ",
        "can a ", "can an ", "can someone ", "could a ", "could someone ",
        "would a ", "would it ", "should i ", "should a ",
        "in what ways ", "what do you mean ",
        "give me an overview", "give me a summary",
        "what's the point of ", "what are the benefits ",
        "what are the risks ", "what are the dangers ",
    ]
    # If the message contains a live-action verb, the user wants an operation, not an explanation.
    # "deauth" as a standalone action verb blocks, but "deauthentication" as a concept does not.
    live_action_verbs = [
        "scan", "capture", "connect to", "use hcx", "run hcx",
        "run a scan", "start a scan", "do a scan", "find the ssid",
        "look for the ssid", "show me nearby", "analyze now",
        "identify nearby", "identify networks", "crack this", "crack the",
        "run a deauth", "do a deauth", "start a deauth", "deauth and capture",
    ]
    # If the message contains a live-scope term, the user is asking about the
    # current environment. Use phrases specific enough to avoid false positives:
    # "current" alone matches "current issues" (conceptual), so require
    # "current network/ssid/channel/capture/scan/environment" etc.
    live_scope_terms = [
        "nearby", "right now", "at the moment", "visible",
        "in the area", "around here", "around me", "this network",
        "this ssid", "that ssid", "that network",
        "current network", "current ssid", "current channel",
        "current capture", "current scan", "current environment",
        "current wireless", "current pineapple", "current state",
    ]

    if not any(lowered.startswith(s) for s in starters):
        return False
    if any(v in lowered for v in live_action_verbs):
        return False
    if any(t in lowered for t in live_scope_terms):
        return False
    return True


def _is_find_ssid_request(text: str) -> str | None:
    lowered = text.lower()
    triggers = [
        "find the ssid",
        "find ssid",
        "did you see",
        "do you see",
        "scan until you find",
        "look for the ssid",
        "look for ssid",
        "look for ",
        "find ",
    ]
    if any(t in lowered for t in triggers):
        return _extract_ssid_from_free_text(text)
    return None


def _is_ssid_analysis_request(
    text: str,
    known_ssids: list[str],
    active_ssid: str | None = None,
) -> tuple[str, str] | None:
    mode = _analysis_mode_for_text(text)

    direct = _extract_ssid_from_free_text(text)
    if direct:
        if known_ssids:
            fuzzy = _match_known_ssid_in_text(direct, known_ssids)
            if fuzzy:
                return mode, fuzzy
        return mode, direct

    ssid = _match_known_ssid_in_text(text, known_ssids)
    if ssid:
        return mode, ssid

    followup_markers = [
        "client", "clients", "connected", "handshake", "handshakes", "eapol",
        "analysis", "analyze", "analyse", "report", "details", "detail",
        "summary", "everything", "about", "that network", "that ssid", "that one", "it",
    ]
    lowered = text.lower()
    if any(marker in lowered for marker in followup_markers):
        if active_ssid:
            return mode, active_ssid
        if known_ssids:
            return mode, known_ssids[-1]

    return None


def _request_requires_live_tool(user_text: str, known_ssids: list[str]) -> bool:
    if _is_definition_question(user_text):
        return False
    if _looks_like_connect_intent(user_text):
        return True
    if _looks_like_deauth_capture_intent(user_text):
        return True
    if _looks_like_live_wireless_request(user_text):
        return True
    if _match_known_ssid_in_text(user_text, known_ssids):
        return True
    if _is_find_ssid_request(user_text):
        return True
    if _extract_bssid(user_text) and _extract_channel(user_text) is not None:
        return True
    return False


_BROADCAST_MAC = 'FF:FF:FF:FF:FF:FF'

_HASH_FILE_SUFFIXES = ('.22000', '.hccapx', '.hash')


def _extract_path_from_text(text: str) -> str | None:
    """Pull a likely filesystem path out of free text.

    Looks for quoted paths first, then bare absolute / tilde / relative paths
    that contain a path separator. Used to spot prompts like
    `run hashcat on /tmp/x.22000` or `crack /home/USER/captures/x.pcapng`.
    """
    if not text:
        return None
    # Quoted forms
    m = re.search(r'["\']([^"\']+\.[A-Za-z0-9]+)["\']', text)
    if m:
        return m.group(1).strip()
    # Bare paths - must contain a separator and a recognizable extension
    m = re.search(r'(?<!\S)(/[^\s\'"]+|~/[^\s\'"]+|\./[^\s\'"]+)', text)
    if m:
        return m.group(1).strip().rstrip('.,;:')
    return None


def _extract_wordlist_from_text(text: str) -> str | None:
    """Extract a wordlist name, alias, or path from user text.

    Handles both absolute paths ('using /usr/share/wordlists/rockyou.txt')
    and bare aliases ('using rockyou', 'using fasttrack.txt').  The raw
    token is returned as-is - the caller is responsible for resolving it
    to a real filesystem path via ``_resolve_wordlist_alias``.
    """
    if not text:
        return None
    # "using <path-or-name>", "with wordlist <path-or-name>", "wordlist <path-or-name>"
    # The capture group now accepts both absolute paths and bare words.
    patterns = [
        r'\busing\s+(?:the\s+)?(?:wordlist\s+)?([^\s\'",.;:]+(?:/[^\s\'",.;:]+)*)',
        r'\bwith\s+(?:the\s+)?(?:wordlist\s+)?([^\s\'",.;:]+(?:/[^\s\'",.;:]+)*)',
        r'\bwordlist\s+([^\s\'",.;:]+(?:/[^\s\'",.;:]+)*)',
    ]
    for pattern in patterns:
        m = re.search(pattern, text, flags=re.IGNORECASE)
        if m:
            candidate = m.group(1).strip().rstrip('.,;:')
            # Must not look like the hash file itself
            if candidate and not any(candidate.lower().endswith(s) for s in _HASH_FILE_SUFFIXES):
                return candidate
    # Fallback: if there are two distinct absolute paths, the second is likely the wordlist
    all_paths = re.findall(r'(?<!\S)(/[^\s\'"]+)', text)
    if len(all_paths) >= 2:
        candidate = all_paths[1].strip().rstrip('.,;:')
        if not any(candidate.lower().endswith(s) for s in _HASH_FILE_SUFFIXES):
            return candidate
    return None


def _looks_like_hash_path(path: str | None) -> bool:
    if not path:
        return False
    lowered = path.lower().strip()
    return any(lowered.endswith(suf) for suf in _HASH_FILE_SUFFIXES)


def _looks_like_direct_hashcat_intent(text: str) -> bool:
    """Return True when the user explicitly asks to run hashcat against an
    already-extracted hash file. The path itself is the strongest signal:
    if the user names a .22000/.hccapx/.hash file, we should route to the
    hashcat action directly and skip extraction.
    """
    if not text:
        return False
    lowered = text.lower()
    path = _extract_path_from_text(text)
    if _looks_like_hash_path(path):
        return True
    # "run hashcat on …", "hashcat against …", "crack the hash …"
    if re.search(r'\bhashcat\b.*\b(on|against|with)\b', lowered):
        return True
    if re.search(r'\bcrack\s+(the\s+)?(extracted\s+)?hash\b', lowered):
        return True
    return False


def _build_direct_hashcat_tool_call_from_text(
    user_text: str,
    store: SessionStore,
    session_id: str,
) -> dict[str, Any] | None:
    """Build a hashcat tool call when the user provided (or session has) a
    pre-extracted hash file. Falls back to None if no usable hash path can
    be located.

    Crucially, this also extracts the wordlist path from user text so that
    hashcat is launched in positional wordlist mode (not stdin/pipe mode).
    """
    candidate = _extract_path_from_text(user_text)
    if not _looks_like_hash_path(candidate):
        # Try the most-recent hash path the orchestrator persisted
        candidate = store.get_context(session_id, "last_hash_path")
        if not _looks_like_hash_path(candidate):
            return None

    args: list[str] = ["-m", "22000", str(candidate)]

    # Extract wordlist from user text - may be an absolute path, a bare
    # filename, or a shorthand alias like "rockyou" or "fasttrack.txt".
    # Resolve it to a real filesystem path before building the hashcat args.
    raw_wordlist = _extract_wordlist_from_text(user_text)
    wordlist = _resolve_wordlist_alias(raw_wordlist) if raw_wordlist else None
    if not wordlist:
        wordlist = _find_default_wordlist()
    if wordlist:
        args.append(wordlist)

    return {
        "action": "hashcat",
        "args": args,
    }


def _known_clients_for_bssid_from_session(
    store: SessionStore,
    session_id: str,
    bssid: str | None,
) -> list[str]:
    """Walk session history newest-first and return real client MACs that have
    been observed (in any prior tool result) on the given BSSID.

    Preference order, highest first:
    - confirmed_clients
    - high_confidence_clients
    - observed_clients
    Excludes broadcast, multicast, locally-administered (randomized), and the
    BSSID itself. Used by deauth routing so a follow-up "deauth and capture"
    request can reuse a real station instead of falling back to broadcast.
    """
    if not bssid:
        return []
    bssid_upper = bssid.upper()

    def _looks_real(mac: str) -> bool:
        if not mac or not isinstance(mac, str):
            return False
        m = mac.strip().upper()
        if not re.fullmatch(r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}', m):
            return False
        if m == _BROADCAST_MAC or m == bssid_upper:
            return False
        try:
            first_octet = int(m.split(':')[0], 16)
            if first_octet & 0x01:  # multicast bit
                return False
        except ValueError:
            return False
        # Reject sibling radios of the target AP - same OUI + small last-byte
        # delta means almost certainly another radio on the same physical
        # device, not a real client station.
        if _is_likely_sibling_radio(m, bssid_upper):
            return False
        return True

    def _collect_from_result(result: dict[str, Any]) -> list[tuple[int, str]]:
        # Returns list of (priority, mac). Lower priority value = higher rank.
        candidates: list[tuple[int, str]] = []
        result_bssid = str(result.get('bssid') or '').upper()
        # If the result is for a different BSSID, skip it.
        if result_bssid and result_bssid != bssid_upper:
            return []
        for prio, key in (
            (0, 'confirmed_clients'),
            (1, 'high_confidence_clients'),
            (2, 'observed_clients'),
        ):
            entries = result.get(key) or []
            if not isinstance(entries, list):
                continue
            for entry in entries:
                mac = None
                if isinstance(entry, dict):
                    if entry.get('locally_administered'):
                        continue
                    mac = entry.get('mac')
                elif isinstance(entry, str):
                    mac = entry
                if _looks_real(mac):
                    candidates.append((prio, str(mac).upper()))
        return candidates

    seen: set[str] = set()
    ranked: list[tuple[int, str]] = []
    for item in reversed(store.items(session_id)):
        if item.get('type') != 'tool':
            continue
        result = item.get('result') or {}
        for prio, mac in _collect_from_result(result):
            if mac in seen:
                continue
            seen.add(mac)
            ranked.append((prio, mac))
    ranked.sort(key=lambda t: t[0])
    return [mac for _, mac in ranked]


def _last_deauth_context_from_session(store: SessionStore, session_id: str) -> dict[str, Any]:
    """
    Walk session history in reverse to find the most recent tool result that
    contains bssid and channel - used to fill in deauth parameters when the
    user omits them in a follow-up request.
    """
    for item in reversed(store.items(session_id)):
        if item.get("type") == "tool":
            result = item.get("result", {})
            tool_call = item.get("tool_call", {})
            bssid = result.get("bssid") or tool_call.get("bssid")
            channel = result.get("channel") or tool_call.get("channel")
            if bssid and channel is not None:
                return {
                    "bssid": str(bssid).upper(),
                    "channel": int(channel),
                    "target_mac": result.get("target_mac") or tool_call.get("target_mac"),
                }
        if item.get("type") == "context":
            key = item.get("key", "")
            if key == "active_bssid":
                bssid = item.get("value")
                channel = store.get_context(session_id, "active_channel")
                if bssid and channel is not None:
                    return {"bssid": str(bssid).upper(), "channel": int(channel), "target_mac": None}
    return {}


def _build_deauth_capture_tool_call_from_text(
    user_text: str,
    store: SessionStore,
    session_id: str,
) -> dict[str, Any] | None:
    bssid = _extract_bssid(user_text)
    channel = _extract_channel(user_text)
    explicit_target_mac = _extract_target_mac(user_text, bssid=bssid)
    target_mac = explicit_target_mac

    # If missing bssid or channel, try to fill from session context
    if not bssid or channel is None:
        ctx = _last_deauth_context_from_session(store, session_id)
        if not bssid:
            bssid = ctx.get("bssid")
        if channel is None:
            channel = ctx.get("channel")
        if not target_mac:
            ctx_target = ctx.get("target_mac")
            if ctx_target and str(ctx_target).upper() != _BROADCAST_MAC:
                target_mac = ctx_target

    # If the user did NOT explicitly request a target client, try to reuse a
    # real station already observed for this BSSID in the session - this is
    # what makes a follow-up "do a deauth and capture on <BSSID>" actually
    # target the real client we already saw, instead of falling back to
    # broadcast (which is silently dropped on PMF and very weak in general).
    if not explicit_target_mac and bssid:
        known_clients = _known_clients_for_bssid_from_session(store, session_id, bssid)
        if known_clients:
            # Highest-confidence first; never overwrite an explicit user target.
            target_mac = known_clients[0]

    if bssid and channel is not None:
        tool_call: dict[str, Any] = {
            "action": "pineapple_deauth_and_capture",
            "bssid": bssid,
            "channel": channel,
        }
        if target_mac:
            tool_call["target_mac"] = target_mac
        return tool_call

    return None


def _build_hcx_capture_tool_call_from_text(
    user_text: str,
    store: SessionStore,
    session_id: str,
) -> dict[str, Any] | None:
    """Build an hcxdumptool_capture tool call from user text and session context."""
    bssid = _extract_bssid(user_text)
    channel = _extract_channel(user_text)

    # Fill missing parameters from session context
    if not bssid or channel is None:
        ctx = _last_deauth_context_from_session(store, session_id)
        if not bssid:
            bssid = ctx.get("bssid")
        if channel is None:
            channel = ctx.get("channel")

    if bssid and channel is not None:
        return {
            "action": "hcxdumptool_capture",
            "bssid": bssid,
            "channel": channel,
            "capture_seconds": 180,
        }

    return None


def _looks_like_live_unencrypted_scan_intent(text: str) -> bool:
    """Return True if the user wants a fresh live scan for unencrypted traffic."""
    t = text.lower()
    # Must NOT be asking about an existing / latest / specific PCAP
    if _looks_like_existing_pcap_unencrypted_intent(text):
        return False
    # Must NOT be a conceptual question
    if _is_definition_question(text):
        return False
    # Check for unencrypted/plaintext scan indicators
    scan_keywords = [
        'unencrypted traffic', 'plaintext traffic', 'cleartext traffic',
        'unencrypted protocol', 'plaintext protocol', 'cleartext protocol',
        'unencrypted conversation', 'plaintext conversation',
        'unencrypted scan', 'plaintext scan', 'cleartext scan',
        'scan for http', 'scan for ftp', 'scan for telnet',
        'look for unencrypted', 'look for plaintext', 'look for cleartext',
        'check for unencrypted', 'check for plaintext', 'check for cleartext',
        'find unencrypted', 'find plaintext', 'find cleartext',
        'http credentials', 'plaintext credentials', 'cleartext credentials',
        'unencrypted credentials', 'http, ftp', 'ftp, telnet',
        'plaintext auth', 'cleartext auth',
        'scan for credentials', 'scan for images',
        'using unencrypted', 'unencrypted protocols',
        # Media extraction triggers - route to live_unencrypted_scan (which now
        # exports HTTP objects and renders image/video previews).
        'unencrypted media', 'plaintext media', 'cleartext media',
        'http image', 'http images', 'http video', 'http videos',
        'http file', 'http files',
        'look for http images', 'look for http videos',
        'look for plaintext images', 'look for plaintext videos',
        'look for plaintext images and videos', 'look for plaintext media',
        'extract http objects', 'extract media', 'extract images',
        'extract video', 'extract plaintext',
        'capture unencrypted traffic and report',
        'scan for images through the pineapple',
        'scan for videos through the pineapple',
        'scan for plaintext', 'scan for media',
    ]
    return any(k in t for k in scan_keywords)


def _looks_like_existing_pcap_unencrypted_intent(text: str) -> bool:
    """Return True if the user wants to analyze an existing PCAP for unencrypted traffic."""
    t = text.lower()
    existing_indicators = [
        'latest capture', 'latest pcap', 'existing capture', 'existing pcap',
        'the capture', 'the pcap', 'this pcap', 'that pcap',
        'use the existing', 'analyze the capture', 'analyze the pcap',
        'scan the latest', 'check the latest', 'scan the pcap',
    ]
    has_existing = any(k in t for k in existing_indicators)
    # Also check for explicit file paths
    has_path = bool(re.search(r'[/~]\S+\.pcap', t))
    if not has_existing and not has_path:
        return False
    # Must also mention unencrypted/plaintext
    unenc_keywords = [
        'unencrypted', 'plaintext', 'cleartext', 'http',
        'ftp', 'telnet', 'credentials', 'credential',
    ]
    return any(k in t for k in unenc_keywords)


def _extract_scan_duration_from_text(text: str) -> int | None:
    """Extract a duration in seconds from user text. Returns None if not specified."""
    t = text.lower()
    # "for 3 minutes", "for 180 seconds", etc.
    m = re.search(r'(?:for|duration)\s+(\d+)\s*(?:min(?:ute)?s?)\b', t)
    if m:
        return int(m.group(1)) * 60
    m = re.search(r'(?:for|duration)\s+(\d+)\s*(?:sec(?:ond)?s?)\b', t)
    if m:
        return int(m.group(1))
    # Bare "180 seconds" or "3 minutes"
    m = re.search(r'(\d+)\s*(?:min(?:ute)?s?)\b', t)
    if m:
        return int(m.group(1)) * 60
    m = re.search(r'(\d+)\s*(?:sec(?:ond)?s?)\b', t)
    if m:
        return int(m.group(1))
    return None


def _extract_interface_from_text(text: str) -> str | None:
    """Extract a network interface name from user text."""
    # "on eth0", "on local eth0", "on Kali eth0", "interface eth1"
    m = re.search(r'\b(?:on|interface)\s+(?:local\s+|kali\s+)?(eth\d+|wlan\d+|en\w+|br[\w-]+)\b', text.lower())
    if m:
        return m.group(1)
    return None


def _looks_like_pineapple_path_scan(text: str) -> bool:
    """Return True if the user wants to scan through/from the Pineapple network path."""
    t = text.lower()
    return any(k in t for k in [
        'pineapple', 'through the pineapple', 'from the pineapple',
        'pineapple-connected', 'pineapple connected', 'pineapple path',
        'pineapple network', 'connected pineapple',
    ])


def _build_live_unencrypted_scan_tool_call(user_text: str) -> dict[str, Any]:
    """Build a live_unencrypted_scan tool call. Defaults to pineapple_path=True."""
    duration = _extract_scan_duration_from_text(user_text) or 180
    duration = max(30, min(duration, 600))
    interface = _extract_interface_from_text(user_text)
    local = _looks_like_local_execution_intent(user_text)
    tc: dict[str, Any] = {"action": "live_unencrypted_scan", "duration": duration}
    if local and interface:
        tc["interface"] = interface
        tc["pineapple_path"] = False
    elif interface:
        tc["interface"] = interface
        tc["pineapple_path"] = not local
    else:
        tc["pineapple_path"] = not local
    return tc


def _looks_like_arpspoof_intent(text: str) -> bool:
    """Return True if the user wants to start ARP spoofing."""
    t = text.lower()
    return any(k in t for k in [
        'arpspoof', 'arp spoof', 'mitm', 'man in the middle',
        'intercept traffic', 'start arp', 'run arp',
        'bidirectional arp', 'poison arp',
    ])


def _looks_like_stop_arpspoof_intent(text: str) -> bool:
    """Return True if the user wants to stop ARP spoofing.

    Matches any stop-verb (``stop``, ``kill``, ``terminate``, ``end``) anywhere
    in the text combined with any ARP/MITM noun (``arpspoof``, ``arp spoof``,
    ``mitm``). This deliberately tolerates intervening words like "local" or
    "Kali" - "stop local arpspoof" and "stop Kali arpspoof" must both fire.
    """
    t = text.lower()
    has_stop_verb = any(re.search(rf'\b{verb}\b', t) for verb in ('stop', 'kill', 'terminate', 'end'))
    has_arp_noun = any(noun in t for noun in ('arpspoof', 'arp spoof', 'mitm'))
    return has_stop_verb and has_arp_noun


def _extract_ipv4s_from_text(text: str) -> list[str]:
    """Extract all IPv4 addresses from text, validated."""
    import ipaddress as _ipaddr
    candidates = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
    valid = []
    for c in candidates:
        try:
            _ipaddr.ip_address(c)
            valid.append(c)
        except ValueError:
            pass
    return valid


def _build_arpspoof_tool_call(
    user_text: str,
    store: SessionStore,
    session_id: str,
) -> dict[str, Any] | None:
    """Build an arpspoof tool call. Defaults to pineapple_arpspoof.

    Two IPs in the text are treated as target_ip and peer_ip - neither needs
    to be a gateway. We still pass the second IP under both ``peer_ip`` and
    ``gateway_ip`` keys so the helper accepts either.
    """
    ips = _extract_ipv4s_from_text(user_text)
    target_ip = ips[0] if len(ips) >= 1 else None
    peer_ip = (ips[1] if len(ips) >= 2
               else store.get_context(session_id, "active_gateway")
               or store.get_context(session_id, "connected_gateway"))

    if not target_ip:
        return None  # Caller will ask user

    if not peer_ip:
        return None  # Caller will ask for the second IP

    local = _looks_like_local_execution_intent(user_text)
    if local:
        iface = _extract_interface_from_text(user_text) or 'eth0'
        return {
            "action": "arpspoof",
            "target_ip": target_ip,
            "gateway_ip": peer_ip,
            "interface": iface,
        }

    # Pineapple path: omit interface so the helper auto-detects via `ip route get`.
    return {
        "action": "pineapple_arpspoof",
        "target_ip": target_ip,
        "peer_ip": peer_ip,
        "gateway_ip": peer_ip,
    }


def _default_nmap_args(full_ports: bool = False) -> list[str]:
    """Return the standard aggressive nmap argument set."""
    args = ['-T4', '-A', '-sV', '-O', '--version-all', '--osscan-guess', '--reason', '--open']
    if full_ports:
        args.append('-p-')
    return args


def _looks_like_full_port_nmap_intent(text: str) -> bool:
    """Return True if the user wants a full/every-port scan."""
    t = text.lower()
    return any(k in t for k in [
        'full port', 'every port', 'all port', 'all 65535', '65535 port',
        'complete port', 'most aggressive', '-p-', 'p dash', 'all tcp',
        'scan every port', 'scan all ports',
    ])


def _looks_like_nmap_intent(text: str) -> bool:
    """Return True if the user wants any kind of nmap / network scan.

    This covers both local-Kali and Pineapple-origin scans.  It does NOT
    match conceptual questions, SSID wireless analysis, or unrelated requests.
    """
    if _is_definition_question(text):
        return False
    t = text.lower()
    # Direct nmap mention
    if 'nmap' in t:
        return True
    # "scan the subnet" / "scan the network" / "map the network" / "port scan"
    scan_phrases = [
        'scan the subnet', 'scan the entire subnet', 'scan the whole subnet',
        'scan the network', 'scan the entire network', 'scan the whole network',
        'scan the connected network', 'scan the network we joined', 'scan the joined network',
        'map the subnet', 'map the network', 'map the entire',
        'map the connected network', 'map the network we joined', 'map the joined network',
        'subnet map', 'map the /24',
        'port scan', 'service scan', 'os detect', 'service detect',
        'network scan', 'host discovery', 'scan all hosts',
        'scan every port', 'scan all ports', 'most aggressive scan',
        'aggressive scan', 'full scan',
    ]
    if any(k in t for k in scan_phrases):
        return True
    # IP/CIDR with scan verb
    has_ip = bool(re.search(r'\d+\.\d+\.\d+\.\d+', t))
    has_scan = any(v in t for v in ['scan', 'nmap', 'map', 'discover', 'enumerate'])
    if has_ip and has_scan:
        return True
    # Nmap flag + IP: "run -sV against 192.168.X.X" / "-A on 10.0.0.1"
    if has_ip and re.search(r'(?<!\w)-(?:s[VUTAPNRFX]|A|O|p-?|T[0-5]|Pn|n|v|oX|oG|oN|F)\b', text):
        return True
    return False


def _looks_like_subnet_map_intent(text: str) -> bool:
    """Return True if the user wants a staged subnet map of the connected
    network, rather than a single direct nmap command against one host.
    """
    if _is_definition_question(text):
        return False
    t = text.lower()
    strong_map_phrases = [
        'map the subnet', 'map the entire subnet', 'map the whole subnet',
        'map the network', 'map the entire network', 'map the whole network',
        'map the connected network', 'map the network we joined',
        'map the joined network', 'subnet map', 'map the /24',
        'map the /16', 'map the /23',
    ]
    if any(p in t for p in strong_map_phrases):
        return True
    broad_scan_phrases = [
        'scan the subnet', 'scan the entire subnet', 'scan the whole subnet',
        'scan the network', 'scan the entire network', 'scan the whole network',
        'scan the connected network', 'scan the network we joined',
        'scan the joined network', 'scan the whole subnet from the pineapple',
    ]
    if any(p in t for p in broad_scan_phrases):
        return True
    return False


def _looks_like_aggressive_nmap_intent(text: str) -> bool:
    """Return True when the user explicitly asks for an aggressive / deep scan."""
    t = text.lower()
    keyword_hits = any(k in t for k in [
        'aggressive', 'deep scan', 'full port', 'full scan', 'all ports',
        'scan every port', 'scan all ports', 'most aggressive',
        '--version-all', 'default scripts', 'run scripts',
        '-p-',
    ])
    if keyword_hits:
        return True
    if re.search(r'(?<!\w)-A(?!\w)', text):
        return True
    return False


def _extract_nmap_target(text: str) -> str | None:
    """Extract an IP address or CIDR from user text for nmap targeting."""
    # CIDR first
    m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', text)
    if m:
        return m.group(1)
    # IP range (e.g. 192.168.X.1-254)
    m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3})', text)
    if m:
        return m.group(1)
    # Single IP - only if surrounded by word boundaries and looks like a real address
    m = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
    if m:
        import ipaddress
        try:
            ipaddress.ip_address(m.group(1))
            return m.group(1)
        except ValueError:
            pass
    return None


def _looks_like_local_execution_intent(text: str) -> bool:
    """Return True if the user explicitly wants local Kali execution."""
    t = text.lower()
    return any(k in t for k in [
        'locally', 'local kali', 'on kali', 'from kali', 'run locally',
        'local scan', 'local eth0', 'kali eth0', 'use local',
        'run on kali', 'local nmap', 'local arpspoof',
        # "use Kali arpspoof" / "stop Kali arpspoof" - Kali immediately before
        # the action word, with no connecting "on"/"from"/"local".
        'kali arpspoof', 'kali nmap',
    ])


def _build_pineapple_subnet_map_tool_call(
    user_text: str,
    store: SessionStore,
    session_id: str,
) -> dict[str, Any] | None:
    """Build a pineapple_subnet_map tool call using connected session context.

    Returns None if no subnet target can be resolved.
    """
    target = _extract_nmap_target(user_text)
    if not target:
        target = (store.get_context(session_id, "active_subnet")
                  or store.get_context(session_id, "connected_subnet"))
    if not target:
        return None
    interface = (store.get_context(session_id, "active_interface")
                 or store.get_context(session_id, "connected_interface")
                 or 'wlan2')
    aggressive = _looks_like_aggressive_nmap_intent(user_text)
    return {
        "action": "pineapple_subnet_map",
        "target": target,
        "interface": interface,
        "stages": ['discover', 'ports', 'services', 'os'],
        "aggressive": aggressive,
    }


def _build_nmap_tool_call(
    user_text: str,
    store: SessionStore,
    session_id: str,
) -> dict[str, Any] | None:
    """Build an nmap tool call.

    Routing:
      - Broad subnet-mapping phrases (``"scan the entire subnet"``,
        ``"map the connected network"``, etc.) route to ``pineapple_subnet_map``.
      - Direct one-off requests against a specific IP (``"scan 192.168.X.X"``,
        ``"aggressive scan 192.168.X.X"``) route to ``pineapple_nmap_scan``.
      - Local-Kali opt-out phrases route to ``nmap_scan``.
    """
    explicit_target = _extract_nmap_target(user_text)
    local = _looks_like_local_execution_intent(user_text)
    subnet_intent = _looks_like_subnet_map_intent(user_text)

    # Broad subnet mapping always uses the staged Pineapple flow (unless the
    # user explicitly opted into local Kali).
    if subnet_intent and not local:
        subnet_tc = _build_pineapple_subnet_map_tool_call(user_text, store, session_id)
        if subnet_tc:
            return subnet_tc
        if not explicit_target:
            return None  # caller turns this into __nmap_target_needed__

    # Direct one-off scan.
    target = explicit_target
    if not target:
        target = (store.get_context(session_id, "active_subnet")
                  or store.get_context(session_id, "connected_subnet"))
    if not target:
        target = (store.get_context(session_id, "active_gateway")
                  or store.get_context(session_id, "connected_gateway"))
    if not target:
        return None

    full_ports = _looks_like_full_port_nmap_intent(user_text)
    args = _default_nmap_args(full_ports=full_ports)
    action = "nmap_scan" if local else "pineapple_nmap_scan"
    return {"action": action, "target": target, "args": args}


def _looks_like_pineapple_nmap_intent(text: str) -> bool:
    """Return True if the user wants an nmap scan originating from the Pineapple."""
    t = text.lower()
    # Must mention the Pineapple as the scan origin AND have nmap/scan/map intent
    pineapple_origin = any(p in t for p in [
        'from the pineapple', 'on the pineapple', 'via the pineapple',
        'through the pineapple', 'pineapple nmap', 'pineapple scan',
        'scan from pineapple', 'nmap from pineapple',
        'scan the connected network', 'map the connected network',
        'scan the network we joined', 'map the network we joined',
        'scan the joined network', 'map the joined network',
    ])
    if pineapple_origin:
        return True
    # IP/CIDR target + "from the pineapple" / "pineapple"
    has_ip = bool(re.search(r'\d+\.\d+\.\d+\.\d+', t))
    has_cidr = bool(re.search(r'\d+\.\d+\.\d+\.\d+/\d+', t))
    has_pineapple = 'pineapple' in t
    has_nmap = any(k in t for k in ['nmap', 'port scan', 'service scan', 'os detect', 'service detect'])
    if (has_ip or has_cidr) and has_pineapple:
        return True
    if (has_ip or has_cidr) and has_nmap and 'from' in t:
        return True
    return False


def _extract_nmap_args_from_text(text: str) -> list[str]:
    """Extract nmap flags from user text.  Falls back to -F (fast scan)."""
    t = text.lower()
    args: list[str] = []
    if 'aggressive' in t or '-a' in text:
        args.append('-A')
    if 'os detect' in t or 'os fingerprint' in t or '-o ' in text.lower():
        if '-A' not in args:
            args.append('-O')
    if 'service' in t or 'version' in t or '-sv' in t.replace(' ', ''):
        if '-A' not in args:
            args.append('-sV')
    if '-t4' in t or 'fast' in t or 'quick' in t:
        args.append('-T4')
    elif '-t5' in t:
        args.append('-T5')
    else:
        args.append('-T4')
    if not args or args == ['-T4']:
        args.insert(0, '-F')
    return args


def _build_pineapple_nmap_tool_call(
    user_text: str,
    store: SessionStore,
    session_id: str,
) -> dict[str, Any] | None:
    """Build a pineapple_nmap_scan tool call from user text and session context."""
    target = _extract_nmap_target(user_text)
    if not target:
        target = (store.get_context(session_id, "active_subnet")
                  or store.get_context(session_id, "connected_subnet"))
    if not target:
        target = (store.get_context(session_id, "active_gateway")
                  or store.get_context(session_id, "connected_gateway"))
    if not target:
        return None
    full_ports = _looks_like_full_port_nmap_intent(user_text)
    args = _default_nmap_args(full_ports=full_ports)
    return {"action": "pineapple_nmap_scan", "target": target, "args": args}


def _build_connect_tool_call_from_text(
    user_text: str,
    store: SessionStore,
    session_id: str,
) -> dict[str, Any] | None:
    """Build a pineapple_connect tool call from user text and session context."""
    ssid = _extract_connect_ssid_from_text(user_text) or _extract_ssid_from_free_text(user_text)
    if not ssid:
        ssid = store.get_context(session_id, "active_ssid")
    password = _extract_password_from_text(user_text)
    if ssid and password:
        return {"action": "pineapple_connect", "ssid": ssid, "password": password}
    return None


def _route_request(
    cfg: dict[str, Any],
    user_text: str,
    store: SessionStore,
    session_id: str,
) -> dict[str, Any] | None:
    registry = build_registry(cfg)
    known_ssids = _known_ssids_from_session(store, session_id)
    active_ssid = store.get_context(session_id, "active_ssid")

    # Priority -1: direct hashcat against an already-extracted hash file.
    # If the user supplied a .22000/.hccapx/.hash path (or asks to run hashcat
    # on an existing extracted hash), skip crack_wifi_pcap entirely and route
    # straight to the hashcat action. This avoids unnecessary re-extraction
    # and is the operator's explicit intent. The crack_wifi_pcap .22000
    # shortcut is still kept as a fallback safety net.
    if _looks_like_direct_hashcat_intent(user_text) and "hashcat" in registry:
        forced = _build_direct_hashcat_tool_call_from_text(user_text, store, session_id)
        if forced:
            return forced

    # Priority 0: connect/join intent - must be checked before Priority 3 (SSID analysis)
    # which would match any known SSID and wrongly route a connect request to
    # pineapple_analyze_ssid instead of pineapple_connect.
    if _looks_like_connect_intent(user_text) and "pineapple_connect" in registry:
        forced = _build_connect_tool_call_from_text(user_text, store, session_id)
        if forced:
            return forced
        # Intent detected but SSID or password is missing - return a sentinel so
        # _run_turn falls through to the LLM, which will ask the user for details.
        return {"action": "__connect_params_needed__"}

    # Priority 1: HCX/PMKID capture - explicit user request overrides everything.
    # Must be checked before deauth since HCX requests often also contain
    # capture-related words that would otherwise match deauth routing.
    if _looks_like_hcx_capture_intent(user_text) and "hcxdumptool_capture" in registry:
        forced = _build_hcx_capture_tool_call_from_text(user_text, store, session_id)
        if forced:
            return forced

    # Priority 2: Normal deauth + capture (only when HCX not explicitly requested).
    if (
        _looks_like_deauth_capture_intent(user_text)
        and not _looks_like_hcx_capture_intent(user_text)
        and "pineapple_deauth_and_capture" in registry
    ):
        forced = _build_deauth_capture_tool_call_from_text(user_text, store, session_id)
        if forced:
            return forced

    # Priority 2.5: Nmap / network scan.  Defaults to pineapple_nmap_scan.
    if _looks_like_nmap_intent(user_text):
        forced = _build_nmap_tool_call(user_text, store, session_id)
        if forced:
            return forced
        return {"action": "__nmap_target_needed__"}

    # Priority 2.6: ARP spoof.  Defaults to pineapple_arpspoof.
    if _looks_like_stop_arpspoof_intent(user_text):
        local = _looks_like_local_execution_intent(user_text)
        return {"action": "stop_arpspoof" if local else "pineapple_stop_arpspoof"}
    if _looks_like_arpspoof_intent(user_text):
        forced = _build_arpspoof_tool_call(user_text, store, session_id)
        if forced:
            return forced
        return {"action": "__arpspoof_params_needed__"}

    # Priority 2.7: Live unencrypted scan.  Defaults to pineapple_path=True.
    if _looks_like_live_unencrypted_scan_intent(user_text) and "live_unencrypted_scan" in registry:
        return _build_live_unencrypted_scan_tool_call(user_text)

    # Priority 3: SSID-specific analysis (client / deep / summary).
    # Checked BEFORE generic SSID find so that "find clients on X" routes to
    # pineapple_client_activity_report rather than pineapple_nearby_ssids.
    analysis_request = _is_ssid_analysis_request(user_text, known_ssids, active_ssid)
    if analysis_request:
        mode, ssid = analysis_request
        if mode == "clients" and "pineapple_client_activity_report" in registry:
            return {"action": "pineapple_client_activity_report", "ssid": ssid, "dwell_sec": 120}
        if mode == "deep" and "pineapple_deep_analyze_ssid" in registry:
            return {"action": "pineapple_deep_analyze_ssid", "ssid": ssid, "dwell_sec": 180}
        if "pineapple_analyze_ssid" in registry:
            return {"action": "pineapple_analyze_ssid", "ssid": ssid}

    # Priority 4: Generic nearby SSID scan (last resort for plain find/look-for queries).
    target_find_ssid = _is_find_ssid_request(user_text)
    if target_find_ssid and "pineapple_nearby_ssids" in registry:
        requested = _requested_count(user_text) or 20
        return {"action": "pineapple_nearby_ssids", "limit": max(10, requested)}

    return None


def _tool_call_matches_user_intent(
    tool_call: dict[str, Any],
    user_text: str,
) -> bool:
    action = str(tool_call.get("action", "")).strip()

    # HCX intent is explicit - if the user asked for HCX, only hcxdumptool_capture matches.
    if _looks_like_hcx_capture_intent(user_text):
        return action == "hcxdumptool_capture"

    # Nmap intent - reject wireless-summary tools.
    if _looks_like_nmap_intent(user_text):
        return action in {"pineapple_nmap_scan", "nmap_scan", "pineapple_subnet_map"}

    # Live unencrypted scan - reject SSID analysis / nmap / other tools.
    if _looks_like_live_unencrypted_scan_intent(user_text):
        return action in {"live_unencrypted_scan", "unencrypted_scan"}

    target_find_ssid = _is_find_ssid_request(user_text)
    if target_find_ssid:
        return action in {"pineapple_nearby_ssids", "pineapple_analyze_ssid"}

    if _looks_like_deauth_capture_intent(user_text):
        bssid = _extract_bssid(user_text)
        channel = _extract_channel(user_text)
        requested_target = _extract_target_mac(user_text, bssid=bssid)

        if bssid and channel is not None:
            if action != "pineapple_deauth_and_capture":
                return False
            if str(tool_call.get("bssid", "")).upper() != bssid.upper():
                return False
            if int(tool_call.get("channel", -1)) != int(channel):
                return False
            if requested_target:
                actual_target = str(tool_call.get("target_mac", "")).upper()
                if actual_target != requested_target.upper():
                    return False

    return True


def _force_live_request_tool_call(
    cfg: dict[str, Any],
    user_text: str,
    store: SessionStore,
    session_id: str,
) -> dict[str, Any] | None:
    hard_routed = _route_request(cfg, user_text, store, session_id)
    if hard_routed:
        return hard_routed

    registry = build_registry(cfg)

    count = _requested_count(user_text)
    if "pineapple_nearby_ssids" in registry:
        return {"action": "pineapple_nearby_ssids", "limit": count or 5}

    if "pineapple_wifi_snapshot" in registry:
        return {"action": "pineapple_wifi_snapshot"}

    if "pineapple_scan" in registry:
        return {"action": "pineapple_scan", "duration": 10}

    return None


def _repair_for_tool(
    cfg: dict[str, Any],
    system_prompt: str,
    conversation: str,
    reason: str,
    suggested_actions: list[str],
) -> str:
    registry = build_registry(cfg)
    allowed_actions = [name for name in suggested_actions if name in registry]
    if not allowed_actions:
        allowed_actions = sorted(registry.keys())

    conversation_tail = conversation.split("User:", maxsplit=-1)[-1]

    # HCX must be checked first - it overrides deauth routing.
    if _looks_like_hcx_capture_intent(conversation_tail) and "hcxdumptool_capture" in registry:
        bssid = _extract_bssid(conversation_tail)
        channel = _extract_channel(conversation_tail)
        if bssid and channel is not None:
            return json.dumps({"action": "hcxdumptool_capture", "bssid": bssid, "channel": channel})

    if _is_find_ssid_request(conversation_tail) and "pineapple_nearby_ssids" in registry:
        requested = _requested_count(conversation_tail) or 20
        return json.dumps({"action": "pineapple_nearby_ssids", "limit": max(10, requested)})

    if (
        _looks_like_deauth_capture_intent(conversation_tail)
        and not _looks_like_hcx_capture_intent(conversation_tail)
        and "pineapple_deauth_and_capture" in registry
    ):
        # Defer to the same builder that handles session-known-client reuse.
        payload = _build_deauth_capture_tool_call_from_text(
            user_text=conversation_tail,
            store=SessionStore(),  # repair path has no direct session - best-effort
            session_id="default",
        )
        if payload:
            return json.dumps(payload)
        bssid = _extract_bssid(conversation_tail)
        channel = _extract_channel(conversation_tail)
        if bssid and channel is not None:
            return json.dumps({
                "action": "pineapple_deauth_and_capture",
                "bssid": bssid,
                "channel": channel,
            })

    prompt = build_repair_prompt(
        system_prompt=system_prompt,
        conversation=conversation,
        reason=reason,
        allowed_actions=allowed_actions,
    )
    return _ask_model(
        cfg,
        prompt,
        temperature=float(_cfg_get(cfg, "config", "agent", "planner_temperature", default=0.0)),
    )


def _repair_mixed_tool_call(
    cfg: dict[str, Any],
    system_prompt: str,
    conversation: str,
) -> str:
    prompt = (
        build_followup_prompt(system_prompt=system_prompt, conversation=conversation)
        + "\nSystem correction: The previous reply was invalid because it mixed prose with JSON or used the wrong schema. "
          "Reply with ONLY one valid JSON object. Use key 'action', not 'type'. Use only supported actions.\nAssistant:"
    )
    return _ask_model(cfg, prompt, temperature=0.0)


def _classify_turn(
    cfg: dict[str, Any],
    system_prompt: str,
    conversation: str,
    user_text: str,
    known_ssids: list[str],
    active_ssid: str | None = None,
) -> dict[str, Any]:
    # Fast-path: direct hashcat against an existing hash file. The user has
    # already extracted, so we should not call crack_wifi_pcap (which would
    # re-extract). Route directly.
    if _looks_like_direct_hashcat_intent(user_text):
        return {
            'requires_tool': True,
            'reason': 'heuristic_direct_hashcat',
            'suggested_actions': ['hashcat'],
        }

    # Hard downgrade: a conceptual / definition question never requires a tool.
    # This protects against the LLM classifier returning requires_tool=True for
    # questions like "what are the major concepts in wireless security".
    if _is_definition_question(user_text) and not _looks_like_connect_intent(user_text):
        return {
            'requires_tool': False,
            'reason': 'definition_question',
            'suggested_actions': [],
        }

    # Fast-path: HCX intent is explicit - always takes priority over deauth.
    if _looks_like_hcx_capture_intent(user_text):
        return {
            "requires_tool": True,
            "reason": "heuristic_hcx_capture",
            "suggested_actions": ["hcxdumptool_capture"],
        }

    # Fast-path: connect/join intent - deterministic, skip the LLM classifier.
    if _looks_like_connect_intent(user_text):
        return {
            "requires_tool": True,
            "reason": "heuristic_connect_intent",
            "suggested_actions": ["pineapple_connect"],
        }

    # Fast-path: if we can clearly determine this is a deauth+bssid+channel request,
    # skip the LLM classifier entirely - it adds latency and can mis-classify.
    if _looks_like_deauth_capture_intent(user_text) and _extract_bssid(user_text) and _extract_channel(user_text) is not None:
        return {
            "requires_tool": True,
            "reason": "heuristic_deauth_capture",
            "suggested_actions": ["pineapple_deauth_and_capture"],
        }

    # Fast-path: nmap / network scan (defaults to Pineapple).
    if _looks_like_nmap_intent(user_text):
        if _looks_like_subnet_map_intent(user_text) and not _looks_like_local_execution_intent(user_text):
            return {
                "requires_tool": True,
                "reason": "heuristic_subnet_map",
                "suggested_actions": ["pineapple_subnet_map"],
            }
        return {
            "requires_tool": True,
            "reason": "heuristic_nmap_scan",
            "suggested_actions": ["pineapple_nmap_scan"],
        }

    # Fast-path: stop arpspoof.
    if _looks_like_stop_arpspoof_intent(user_text):
        local = _looks_like_local_execution_intent(user_text)
        return {
            "requires_tool": True,
            "reason": "heuristic_stop_arpspoof",
            "suggested_actions": ["stop_arpspoof" if local else "pineapple_stop_arpspoof"],
        }

    # Fast-path: start arpspoof.
    if _looks_like_arpspoof_intent(user_text):
        local = _looks_like_local_execution_intent(user_text)
        return {
            "requires_tool": True,
            "reason": "heuristic_arpspoof",
            "suggested_actions": ["arpspoof" if local else "pineapple_arpspoof"],
        }

    # Fast-path: live unencrypted / plaintext traffic scan.
    if _looks_like_live_unencrypted_scan_intent(user_text):
        return {
            "requires_tool": True,
            "reason": "heuristic_live_unencrypted_scan",
            "suggested_actions": ["live_unencrypted_scan"],
        }

    prompt = build_classifier_prompt(
        system_prompt=system_prompt,
        conversation=conversation,
        user_text=user_text,
    )
    raw = _ask_model(
        cfg,
        prompt,
        temperature=float(_cfg_get(cfg, "config", "agent", "classifier_temperature", default=0.0)),
    )
    parsed = _extract_json_object(raw)
    analysis_request = _is_ssid_analysis_request(user_text, known_ssids, active_ssid)

    if not parsed:
        likely_live = _request_requires_live_tool(user_text, known_ssids)
        fallback_actions: list[str] = []

        if likely_live:
            if _looks_like_hcx_capture_intent(user_text):
                fallback_actions = ["hcxdumptool_capture"]
            elif _looks_like_deauth_capture_intent(user_text) and _extract_bssid(user_text) and _extract_channel(user_text) is not None:
                fallback_actions = ["pineapple_deauth_and_capture"]
            elif _is_find_ssid_request(user_text):
                fallback_actions = ["pineapple_nearby_ssids"]
            elif analysis_request and analysis_request[0] == "clients":
                fallback_actions = ["pineapple_client_activity_report"]
            elif analysis_request and analysis_request[0] == "deep":
                fallback_actions = ["pineapple_deep_analyze_ssid"]
            elif analysis_request:
                fallback_actions = ["pineapple_analyze_ssid"]
            else:
                fallback_actions = ["pineapple_nearby_ssids"]

        return {
            "requires_tool": likely_live,
            "reason": "classifier_parse_failed",
            "suggested_actions": fallback_actions,
        }

    suggested_actions = parsed.get("suggested_actions") or []
    if not isinstance(suggested_actions, list):
        suggested_actions = []

    requires_tool = bool(parsed.get("requires_tool", False))
    if _request_requires_live_tool(user_text, known_ssids):
        requires_tool = True

    # Override suggested_actions with deterministic heuristics.
    # HCX must be checked first - it overrides deauth even when both terms appear.
    if _looks_like_hcx_capture_intent(user_text):
        suggested_actions = ["hcxdumptool_capture"]
    elif _looks_like_deauth_capture_intent(user_text) and _extract_bssid(user_text) and _extract_channel(user_text) is not None:
        suggested_actions = ["pineapple_deauth_and_capture"]
    elif _is_find_ssid_request(user_text):
        suggested_actions = ["pineapple_nearby_ssids"]
    elif analysis_request:
        if analysis_request[0] == "clients":
            suggested_actions = ["pineapple_client_activity_report"]
        elif analysis_request[0] == "deep":
            suggested_actions = ["pineapple_deep_analyze_ssid"]
        else:
            suggested_actions = ["pineapple_analyze_ssid"]

    return {
        "requires_tool": requires_tool,
        "reason": str(parsed.get("reason", "")).strip(),
        "suggested_actions": [str(x) for x in suggested_actions],
    }


def _plan_reply(cfg: dict[str, Any], system_prompt: str, conversation: str) -> str:
    prompt = build_followup_prompt(system_prompt=system_prompt, conversation=conversation)
    return _ask_model(
        cfg,
        prompt,
        temperature=float(_cfg_get(cfg, "config", "agent", "planner_temperature", default=0.0)),
    )


def _extract_network_entries(result: Any) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []

    if isinstance(result, dict):
        networks = result.get("networks")
        if isinstance(networks, list):
            for item in networks:
                if isinstance(item, dict):
                    entries.append(item)

    def maybe_add(d: dict[str, Any]) -> None:
        lowered = {str(k).lower(): v for k, v in d.items()}
        if "ssid" in lowered or "channel" in lowered or "bssid" in lowered or "signal_dbm" in lowered:
            entries.append(d)

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            maybe_add(obj)
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(result)

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, Any]] = set()
    for entry in entries:
        key = (str(entry.get("ssid", "")), entry.get("bssid"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
    return deduped


def _format_nearby_ssids_result(result: dict[str, Any], user_text: str) -> str:
    if not result.get("ok"):
        return f"Nearby network scan failed: {result.get('error') or result.get('stderr') or 'unknown error'}"

    requested = _requested_count(user_text) or 5
    entries = _extract_network_entries(result)

    target_find_ssid = _is_find_ssid_request(user_text)
    if target_find_ssid:
        matched = None
        for entry in entries:
            ssid = str(entry.get("ssid", "")).strip()
            if ssid == target_find_ssid or ssid.lower() == target_find_ssid.lower():
                matched = entry
                break
        if not matched and entries:
            known = [str(x.get("ssid", "")).strip() for x in entries if str(x.get("ssid", "")).strip()]
            fuzzy = _match_known_ssid_in_text(target_find_ssid, known)
            if fuzzy:
                matched = next((e for e in entries if str(e.get("ssid", "")).strip() == fuzzy), None)

        if matched:
            parts = [f'Yes - I observed "{matched.get("ssid")}".']
            if matched.get("bssid"):
                parts.append(f'BSSID: {matched["bssid"]}')
            if matched.get("channel") is not None:
                parts.append(f'Channel: {matched["channel"]}')
            if matched.get("signal_dbm") is not None:
                parts.append(f'Signal: {matched["signal_dbm"]} dBm')
            if matched.get("security"):
                parts.append(f'Security: {matched["security"]}')
            return "\n".join(parts)

        return f'I did not observe "{target_find_ssid}" in the current nearby scan.'

    lines: list[str] = []
    used_names: set[str] = set()
    used_bssids: set[str] = set()

    for entry in entries:
        ssid = entry.get("ssid")
        if not isinstance(ssid, str) or not ssid.strip():
            continue
        name = ssid.strip()
        # Skip hidden/placeholder SSIDs
        if name.lower() in ("<hidden>", "hidden", ""):
            continue
        if name in used_names:
            continue
        # Deduplicate by BSSID - one canonical entry per physical AP
        bssid_val = str(entry.get("bssid", "")).strip().upper()
        if bssid_val and bssid_val in used_bssids:
            continue
        if bssid_val:
            used_bssids.add(bssid_val)
        used_names.add(name)

        parts = [name]
        extras: list[str] = []
        if entry.get("channel") is not None:
            extras.append(f"channel {entry['channel']}")
        if entry.get("signal_dbm") is not None:
            extras.append(f"{entry['signal_dbm']} dBm")
        if entry.get("security"):
            extras.append(str(entry["security"]))
        if extras:
            parts.append(", ".join(extras))
        lines.append(" - ".join(parts))

        if len(lines) >= requested:
            break

    if not lines:
        raw_ssids = [x for x in result.get("ssids", []) if isinstance(x, str) and x.strip()]
        for ssid in raw_ssids[:requested]:
            lines.append(ssid.strip())

    if not lines:
        return "No confirmed SSIDs were observed in the scan results."

    if len(lines) == 1:
        return f"I found 1 confirmed SSID:\n{lines[0]}"

    return f"I found {len(lines)} confirmed SSIDs:\n" + "\n".join(lines)


def _format_ssid_analysis_result(result: dict[str, Any]) -> str:
    if not result.get("ok"):
        return f"SSID analysis failed: {result.get('error') or result.get('stderr') or 'unknown error'}"

    ssid = result.get("ssid", "<unknown>")
    lines: list[str] = [f"Summary for {ssid}:"]

    if result.get("bssid"):
        lines.append(f"- BSSID: {result['bssid']}")
    if result.get("channel") is not None:
        lines.append(f"- Channel: {result['channel']}")
    if result.get("signal_dbm") is not None:
        lines.append(f"- Signal: {result['signal_dbm']} dBm")
    if result.get("security"):
        lines.append(f"- Security: {result['security']}")
    if result.get("wps_present") is not None:
        lines.append(f"- WPS present: {result['wps_present']}")
    if result.get("pmf_present") is not None:
        lines.append(f"- PMF present: {result['pmf_present']}")
    if result.get("interface"):
        lines.append(f"- Scan interface: {result['interface']}")

    if len(lines) == 1:
        lines.append("- No additional confirmed details were parsed from the current observation.")

    return "\n".join(lines)


def _format_deep_ssid_analysis_result(result: dict[str, Any]) -> str:
    if not result.get("ok"):
        return f"Deep SSID analysis failed: {result.get('error') or result.get('stderr') or 'unknown error'}"

    ssid = result.get("ssid", "<unknown>")
    lines: list[str] = [f"In-depth analysis for {ssid}:"]

    identity: list[str] = []
    if result.get("bssid"):
        identity.append(f"- BSSID: {result['bssid']}")
    if result.get("vendor_guess"):
        identity.append(f"- Vendor guess: {result['vendor_guess']}")
    if result.get("hidden_ssid") is not None:
        identity.append(f"- Hidden SSID: {result['hidden_ssid']}")
    if identity:
        lines.append("")
        lines.append("Identity")
        lines.extend(identity)

    radio: list[str] = []
    if result.get("channel") is not None:
        radio.append(f"- Channel: {result['channel']}")
    if result.get("band"):
        radio.append(f"- Band: {result['band']}")
    if result.get("channel_width_mhz") is not None:
        radio.append(f"- Channel width: {result['channel_width_mhz']} MHz")
    if result.get("signal_dbm") is not None:
        radio.append(f"- Signal: {result['signal_dbm']} dBm")
    if result.get("beacon_interval_tu") is not None:
        radio.append(f"- Beacon interval: {result['beacon_interval_tu']} TU")
    if result.get("capture_duration"):
        radio.append(f"- Capture duration: {result['capture_duration']}")
    if result.get("packet_count") is not None:
        radio.append(f"- Packet count: {result['packet_count']}")
    if radio:
        lines.append("")
        lines.append("Radio details")
        lines.extend(radio)

    security: list[str] = []
    if result.get("security"):
        security.append(f"- Security: {result['security']}")
    if result.get("wps_present") is not None:
        security.append(f"- WPS present: {result['wps_present']}")
    if result.get("pmf_present") is not None:
        security.append(f"- PMF present: {result['pmf_present']}")
    if security:
        lines.append("")
        lines.append("Security posture")
        lines.extend(security)

    clients: list[str] = []
    focus_pkt = result.get("focus_bssid_packet_count")
    total_pkt = result.get("packet_count")
    if focus_pkt is not None and total_pkt is not None:
        clients.append(f"- Frames involving target BSSID: {focus_pkt} (of {total_pkt} total on channel)")
    if result.get("eapol_frames_seen") is not None:
        clients.append(f"- EAPOL frames seen: {result['eapol_frames_seen']}")
    if result.get("handshake_like_activity_seen") is not None:
        clients.append(f"- Handshake-like activity observed: {result['handshake_like_activity_seen']}")

    # Show client confidence tiers separately
    confirmed = result.get("confirmed_clients") or []
    high_conf = result.get("high_confidence_clients") or []
    low_conf = result.get("low_confidence_clients") or []

    def _fmt_client(c: dict) -> str:
        parts = []
        if c.get("mac"):
            parts.append(str(c["mac"]))
        if c.get("frames_seen") is not None:
            parts.append(f'{c["frames_seen"]} frames')
        if c.get("data_frames") is not None:
            parts.append(f'{c["data_frames"]} data')
        if c.get("locally_administered") is True:
            parts.append("randomized/local")
        return ', '.join(parts)

    if confirmed:
        clients.append(f"- Confirmed clients ({len(confirmed)}):")
        for c in confirmed[:8]:
            if isinstance(c, dict):
                clients.append(f"  - {_fmt_client(c)}")
    if high_conf:
        clients.append(f"- High-confidence client candidates ({len(high_conf)}):")
        for c in high_conf[:8]:
            if isinstance(c, dict):
                clients.append(f"  - {_fmt_client(c)}")
    if low_conf:
        clients.append(f"- Low-confidence client candidates ({len(low_conf)}):")
        for c in low_conf[:6]:
            if isinstance(c, dict):
                clients.append(f"  - {_fmt_client(c)}")
    if not confirmed and not high_conf and not low_conf:
        clients.append("- No client candidates observed during the dwell window.")

    if clients:
        lines.append("")
        lines.append("Observed clients and activity (BSSID-filtered)")
        lines.extend(clients)

    # L3/L4 channel-wide data (protocol counts, TCP/UDP ports, IP sources/
    # destinations, DNS, TLS SNI, plaintext, conversations) is intentionally
    # excluded from the deep SSID analysis report.  That data comes from an
    # unfiltered channel capture and may include traffic from unrelated
    # networks, the Pineapple's own upstream connection, and management-side
    # traffic.  Including it here would misrepresent channel noise as
    # target-BSSID intelligence.  Use scan_and_analyze or tshark_deep_review
    # for channel-wide traffic analysis instead.

    risk = result.get("credential_risk_estimate")
    if isinstance(risk, dict):
        lines.append("")
        lines.append("Credential-risk heuristic")
        if risk.get("level"):
            lines.append(f"- Level: {risk['level']}")
        if risk.get("reason"):
            lines.append(f"- Basis: {risk['reason']}")
        if isinstance(risk.get("ssid_profile"), dict):
            profile = risk["ssid_profile"]
            if profile.get("looks_default") is not None:
                lines.append(f"- Default-style SSID pattern: {profile['looks_default']}")
            if profile.get("looks_isp_default") is not None:
                lines.append(f"- ISP-style default naming: {profile['looks_isp_default']}")
        if risk.get("warning"):
            lines.append(f"- Note: {risk['warning']}")

    notes = result.get("assessment_notes")
    if isinstance(notes, list) and notes:
        lines.append("")
        lines.append("Assessment notes")
        for note in notes:
            lines.append(f"- {note}")

    # Filter observation limits to L2-relevant items only.
    _L3_LIMIT_KEYWORDS = ('protocol counts', 'dns quer', 'tls sni', 'port activity', 'ip source', 'ip dest')
    limits = result.get("observation_limits")
    if isinstance(limits, list) and limits:
        l2_limits = [lim for lim in limits if not any(k in lim.lower() for k in _L3_LIMIT_KEYWORDS)]
        if l2_limits:
            lines.append("")
            lines.append("Observation limits")
            for limit in l2_limits:
                lines.append(f"- {limit}")

    if result.get("pcap_path"):
        lines.append("")
        lines.append(f"Capture file: {result['pcap_path']}")

    return "\n".join(lines)


def _format_client_activity_result(result: dict[str, Any]) -> str:
    if not result.get("ok"):
        return f"Client activity report failed: {result.get('error') or result.get('stderr') or 'unknown error'}"

    ssid = result.get("ssid", "<unknown>")
    lines: list[str] = [f"Client activity report for {ssid}:"]

    if result.get("bssid"):
        lines.append(f"- BSSID: {result['bssid']}")
    if result.get("channel") is not None:
        lines.append(f"- Channel: {result['channel']}")
    if result.get("eapol_frames_seen") is not None:
        lines.append(f"- EAPOL frames seen during dwell: {result['eapol_frames_seen']}")
    if result.get("handshake_like_activity_seen") is not None:
        lines.append(f"- Handshake-like activity observed: {result['handshake_like_activity_seen']}")

    def _fmt_cl(c: dict) -> str:
        parts = []
        if c.get("mac"):
            parts.append(str(c["mac"]))
        if c.get("frames_seen") is not None:
            parts.append(f'{c["frames_seen"]} frames')
        if c.get("data_frames") is not None:
            parts.append(f'{c["data_frames"]} data')
        if c.get("locally_administered") is True:
            parts.append("randomized/local")
        return ', '.join(parts)

    confirmed = result.get("confirmed_clients") or []
    high_conf = result.get("high_confidence_clients") or []
    low_conf = result.get("low_confidence_clients") or []
    if confirmed:
        lines.append(f"- Confirmed clients ({len(confirmed)}):")
        for c in confirmed[:8]:
            if isinstance(c, dict):
                lines.append(f"  - {_fmt_cl(c)}")
    if high_conf:
        lines.append(f"- High-confidence client candidates ({len(high_conf)}):")
        for c in high_conf[:8]:
            if isinstance(c, dict):
                lines.append(f"  - {_fmt_cl(c)}")
    if low_conf:
        lines.append(f"- Low-confidence client candidates ({len(low_conf)}):")
        for c in low_conf[:6]:
            if isinstance(c, dict):
                lines.append(f"  - {_fmt_cl(c)}")
    if not confirmed and not high_conf and not low_conf:
        lines.append("- No client candidates observed during the dwell window.")

    # L3/L4 channel-wide data excluded from client activity report for the
    # same reason as deep SSID analysis: it is not filtered to the target BSSID.

    limits = result.get("observation_limits")
    if isinstance(limits, list) and limits:
        lines.append("- Limits:")
        for limit in limits:
            lines.append(f"  - {limit}")

    if result.get("pcap_path"):
        lines.append(f"- Capture file: {result['pcap_path']}")

    return "\n".join(lines)


def _format_deauth_result(result: dict[str, Any]) -> str:
    outcome = result.get("outcome", "")
    failure_type = result.get("failure_type")
    eapol_count = result.get("eapol_count", 0)
    ack_summary = result.get("aireplay_ack_summary", [])
    used_broadcast = result.get("used_broadcast")
    target_mac = result.get("target_mac")
    bssid = result.get("bssid")
    size_bytes = result.get("size_bytes")

    if not result.get("ok"):
        # PMF pre-check rejection - give actionable guidance
        if result.get("pmf_detected"):
            return (
                f"Deauth blocked: {result.get('error')}\n"
                f"Suggestion: use hcxdumptool_capture against BSSID {bssid} "
                f"to capture a PMKID without needing to deauth clients."
            )

        # Distinguish remote-side execution failures from real wireless failures
        # so the operator can fix the root cause rather than chasing ghosts.
        if failure_type == 'remote_shell_dependency_missing' or outcome == 'remote_shell_dependency_missing':
            return (
                "Deauth and capture FAILED at the script layer:\n"
                "- The Pineapple shell is missing the `timeout` command, so the deauth bursts never executed.\n"
                "- This is a script-side bug, NOT a real wireless failure.\n"
                "- The capture file is essentially empty because no deauth was actually transmitted.\n"
                "Action: this build of Companion Huginn already removes the `timeout` dependency. "
                "Re-run the same request - the deauth loop will now execute correctly."
            )
        if failure_type == 'deauth_loop_failed' or outcome == 'deauth_loop_failed':
            return (
                "Deauth and capture FAILED at the deauth loop:\n"
                "- aireplay-ng never produced any output on the Pineapple.\n"
                "- The capture file is header-only.\n"
                "Action: run pineapple_wifi_snapshot and verify that the monitor interface is up "
                "and that aireplay-ng is on the Pineapple PATH."
            )
        if failure_type == 'empty_filtered_capture' or outcome == 'empty_filtered_capture':
            return (
                f"Deauth and capture produced an empty filtered PCAP ({size_bytes} bytes - pcap header only).\n"
                "- Filter matched no frames involving the target BSSID.\n"
                "- This typically means: wrong channel locked, monitor interface drifted, or the AP is not on-air.\n"
                "Action: re-run pineapple_analyze_ssid to confirm the BSSID/channel are still current, then retry."
            )
        if failure_type == 'monitor_mode_failure':
            return f"Deauth and capture failed (monitor mode): {result.get('error')}"
        if failure_type == 'dependency_missing':
            return (
                f"Deauth and capture failed: missing dependency `{result.get('dependency')}` on the Pineapple. "
                f"{result.get('error') or ''}".strip()
            )
        return f"Deauth and capture failed: {result.get('error') or result.get('stderr') or 'unknown error'}"

    lines: list[str] = ["Deauth and capture completed."]

    if used_broadcast is True:
        lines.append("Note: broadcast deauth was used (no specific target client was supplied or remembered).")
    elif target_mac:
        lines.append(f"Targeted deauth against client {target_mac}.")

    if outcome == "handshake_captured":
        lines.append(f"Outcome: WPA handshake captured ({eapol_count} EAPOL frame(s) from target BSSID).")
        lines.append("The PCAP is ready for handshake extraction and cracking.")
    elif outcome == "partial_eapol":
        lines.append(f"Outcome: Partial - only {eapol_count} EAPOL frame(s) captured (need >= 2 for a usable handshake).")
        lines.append("Consider running again or increasing capture_seconds.")
    elif outcome == "reconnect_observed":
        lines.append("Outcome: Reconnect activity observed (assoc/auth) but no EAPOL frames from target BSSID.")
    elif outcome == "deauth_transmitted_no_reconnect":
        lines.append("Outcome: Deauth transmitted but no client reconnect or EAPOL captured.")
        lines.append("Possible causes: AP has PMF enabled, no clients were connected, or clients reconnected on a different channel.")
        lines.append("Suggestion: try hcxdumptool_capture against the same BSSID to attempt PMKID capture.")
    else:
        lines.append(f"Outcome: {outcome or 'insufficient capture'}.")

    if ack_summary:
        total_acked = sum(a.get("acked", 0) for a in ack_summary)
        total_sent = sum(a.get("sent", 0) for a in ack_summary)
        lines.append(f"Deauth ACKs: {total_acked}/{total_sent} across {len(ack_summary)} burst(s).")

    if result.get("pcap_path"):
        lines.append(f"Capture file: {result['pcap_path']}")

    if eapol_count >= 2:
        lines.append("Next step: run crack_wifi_pcap to extract the handshake hash and attempt to crack it.")

    return "\n".join(lines)


def _format_crack_result(result: dict[str, Any]) -> str:
    if not result.get("ok"):
        stage = result.get("stage", "unknown")
        return f"Password crack failed at stage '{stage}': {result.get('error') or 'unknown error'}"

    stage = result.get("stage", "")
    cracked_password = result.get("cracked_password")
    cracked_passwords = result.get("cracked_passwords", [])

    if cracked_password:
        lines = [f"Password cracked: {cracked_password}"]
        if len(cracked_passwords) > 1:
            lines.append(f"All cracked entries: {', '.join(cracked_passwords)}")
        if stage == "potfile_hit":
            lines.append("(Found in hashcat potfile - previously cracked.)")
        if result.get("hash_path"):
            lines.append(f"Hash file: {result['hash_path']}")
        return "\n".join(lines)

    # No password found
    if stage == "hashcat":
        wordlist = result.get("wordlist")
        if wordlist:
            return (
                f"Hashcat ran against the wordlist ({wordlist}) but did not crack the password.\n"
                "The password may not be in the wordlist. Try a different wordlist or mask attack."
            )
        return "Hashcat ran but did not find the password with the available wordlist."

    return f"Crack completed (stage: {stage}) but no password was recovered."


def _format_hcx_result(result: dict[str, Any]) -> str:
    failure_type = result.get("failure_type")
    outcome = result.get("outcome", "")
    eapol_count = result.get("eapol_count", 0) or 0
    pcap_path = result.get("pcap_path")
    capture_ok = result.get("capture_ok", False)
    extraction = result.get("extraction") or {}
    extraction_ok = result.get("extraction_ok", False)
    usable_hash = result.get("usable_hash_material", False)
    hash_path = result.get("hash_path")
    bssid_filtered = result.get("bssid_filter_applied", False)
    used_mon = result.get("used_mon_interface", False)

    # Hard failures: dependency missing, transport failure, or radio failure.
    if failure_type == 'dependency_missing':
        return (
            f"HCX/PMKID capture failed: missing dependency `{result.get('dependency')}` on the Pineapple. "
            f"{result.get('error') or ''}".strip()
        )
    if failure_type == 'transport_failure':
        return f"HCX/PMKID capture failed (SSH transport): {result.get('error') or 'unknown transport error'}"
    if failure_type == 'radio_failure':
        indicators = result.get('radio_failure_indicators', [])
        log_tail = result.get('hcx_log_tail', '')
        lines = [
            f"HCX/PMKID capture failed: radio/driver failure on interface {result.get('interface', '?')}.",
            f"Indicators: {'; '.join(indicators[:3])}." if indicators else "",
            "This is an execution-level failure - hcxdumptool could not transmit or receive frames.",
            "Possible causes: interface is down, driver does not support hcxdumptool, interface is busy "
            "(another process may be using it), or the wireless hardware is not compatible.",
        ]
        if log_tail:
            lines.append(f"Log excerpt: {log_tail[-300:]}")
        return "\n".join(ln for ln in lines if ln)

    if not capture_ok and outcome == 'empty_capture':
        return (
            "HCX/PMKID capture failed: hcxdumptool produced an empty capture file. "
            "Verify that the physical interface is available and the channel is correct, then retry."
        )

    if not capture_ok:
        return f"HCX/PMKID capture failed: {result.get('error') or result.get('stderr') or 'unknown error'}"

    # Capture succeeded - build result report
    lines: list[str] = ["HCX/PMKID capture completed."]

    if result.get("bssid"):
        lines.append(f"Target BSSID: {result['bssid']}")
    lines.append(f"Interface: {result.get('interface', '?')}")

    # Mon-interface warning
    if used_mon:
        lines.append(
            "Warning: the requested interface had a 'mon' suffix and was stripped to the physical interface. "
            "hcxdumptool manages its own monitor mode internally - using virtual monitor interfaces "
            "created by airmon-ng is discouraged and can cause silent capture failures."
        )

    # Explicit 3-state AP-filter status
    if bssid_filtered:
        lines.append("AP filtering: applied - capture was restricted to the target BSSID via --filterlist_ap.")
    else:
        lines.append(
            "AP filtering: unavailable - this hcxdumptool version does not support --filterlist_ap. "
            "The capture may include frames from other networks on the same channel, not only the target BSSID."
        )

    if outcome == "handshake_captured":
        lines.append(f"Capture outcome: WPA material captured ({eapol_count} EAPOL frame(s) from target BSSID).")
    elif outcome == "partial_eapol":
        lines.append(f"Capture outcome: Partial - only {eapol_count} EAPOL frame(s) (need >= 2 for a usable handshake).")
    else:
        lines.append("Capture outcome: No EAPOL frames from target BSSID, but PMKID may be present in beacon/probe frames.")

    if pcap_path:
        lines.append(f"Capture file: {pcap_path}")

    # Extraction results (auto-performed)
    lines.append("")
    if extraction_ok and usable_hash:
        lines.append(f"Extraction: usable hash material found ({result.get('hash_line_count', 0)} hash line(s)).")
        if hash_path:
            lines.append(f"Hash file: {hash_path}")
        lines.append("Next step: run crack_wifi_pcap to attempt to crack the password.")
    elif extraction:
        lines.append("Extraction: attempted automatically but no usable WPA handshake or PMKID material was found.")
        ext_err = extraction.get('error')
        if ext_err:
            lines.append(f"Extraction detail: {ext_err}")
    else:
        lines.append("Extraction: not attempted (capture was empty or failed).")

    return "\n".join(lines)


def _format_connect_result(result: dict[str, Any]) -> str:
    if not result.get("ok"):
        error = result.get("error") or result.get("stderr") or "unknown error"
        return f"Connect failed: {error}"

    stdout = result.get("stdout", "") or ""
    ssid = result.get("ssid", "")
    iface = result.get("interface", "wlan2")
    already = result.get("already_connected", False)

    lines: list[str] = []
    if already:
        lines.append(f"Pineapple is already connected to {ssid} on {iface}.")
    else:
        lines.append(f"Connect to {ssid} completed on {iface}.")

    # Extract ESSID from iwinfo output for confirmation
    m = re.search(r'ESSID:\s*"([^"]*)"', stdout)
    if m and m.group(1) != ssid:
        lines.append(f"Reported ESSID: {m.group(1)}")

    # Extract IP address
    ip_m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', stdout)
    if ip_m:
        lines.append(f"IP address: {ip_m.group(1)}")

    # Extract gateway
    gw_m = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', stdout)
    if gw_m:
        lines.append(f"Gateway: {gw_m.group(1)}")

    # Extract subnet for nmap hint
    subnet_m = re.search(r'(\d+\.\d+\.\d+)\.\d+/(\d+)', stdout)
    if subnet_m:
        lines.append(f"Subnet: {subnet_m.group(1)}.0/{subnet_m.group(2)}")
        lines.append(f"You can now scan the network with nmap_scan targeting {subnet_m.group(1)}.0/{subnet_m.group(2)}.")

    return "\n".join(lines)


def _format_nmap_result(result: dict[str, Any]) -> str:
    """Format nmap scan output into a structured report.

    Parses the raw nmap stdout to extract hosts, ports, services, OS guesses,
    and highlights risky/legacy services.
    """
    if not result.get("ok"):
        parts: list[str] = ["Nmap scan failed."]
        origin = result.get('scan_origin')
        iface = result.get('scan_interface')
        if origin or iface:
            origin_bits = [b for b in (origin, iface) if b]
            parts.append(f"Origin: {' / '.join(str(b) for b in origin_bits)}")
        target = result.get('target')
        if target:
            parts.append(f"Target: {target}")
        ftype = result.get('failure_type')
        if ftype:
            parts.append(f"Failure type: {ftype}")
        rc = result.get('returncode')
        if rc is not None and rc != 0:
            parts.append(f"Return code: {rc}")
        err = (result.get('error') or '').strip()
        stderr = (result.get('stderr') or '').strip()
        stdout = (result.get('stdout') or '').strip()
        if err:
            parts.append(f"Error: {err}")
        if stderr and stderr not in err:
            parts.append(f"Stderr tail: {stderr[-600:]}")
        if not err and not stderr and stdout:
            parts.append(f"Output tail: {stdout[-600:]}")
        if not err and not stderr and not stdout and rc is None and not ftype:
            parts.append(
                "The tool returned no output and no error. "
                "Check logs/action_log.jsonl for the last tool invocation."
            )
        cmd = result.get('cmd')
        if cmd:
            parts.append(f"Command: {cmd}")
        timeout_sec = result.get('timeout_sec')
        if ftype == 'timeout' and timeout_sec:
            parts.append(
                f"Hint: the scan exceeded {timeout_sec}s. For broad subnet work, "
                "use pineapple_subnet_map - it discovers live hosts first and "
                "only scans those, which is much faster than a single aggressive pass."
            )
        return "\n".join(parts)

    stdout = result.get("stdout", "") or ""
    if not stdout.strip():
        return "Nmap scan completed but produced no output."

    # Scan-origin banner
    origin = result.get("scan_origin", "unknown")
    if origin == "pineapple":
        iface = result.get("scan_interface", "wlan2")
        origin_label = f"Scan executed on: WiFi Pineapple ({iface})"
    elif origin == "local_kali":
        origin_label = "Scan executed on: local Kali machine"
    else:
        origin_label = f"Scan executed on: {origin}"

    # Known risky / legacy services and ports
    RISKY_PORTS = {
        '21': 'FTP', '23': 'Telnet', '25': 'SMTP', '53': 'DNS',
        '80': 'HTTP (unencrypted)', '110': 'POP3', '135': 'MS-RPC',
        '139': 'NetBIOS', '143': 'IMAP', '161': 'SNMP', '445': 'SMB',
        '514': 'Syslog', '515': 'LPD', '1433': 'MS-SQL', '1521': 'Oracle',
        '2049': 'NFS', '3306': 'MySQL', '3389': 'RDP', '5432': 'PostgreSQL',
        '5900': 'VNC', '5985': 'WinRM', '6379': 'Redis', '8080': 'HTTP-Proxy',
        '8443': 'HTTPS-Alt', '9200': 'Elasticsearch', '27017': 'MongoDB',
    }
    LEGACY_KEYWORDS = [
        'windows xp', 'windows 2000', 'windows 2003', 'windows 7',
        'windows server 2008', 'windows server 2003',
        'ubuntu 14', 'ubuntu 12', 'debian 7', 'debian 8',
        'centos 6', 'centos 5', 'apache/2.2', 'apache/2.0',
        'openssh 5.', 'openssh 6.', 'proftpd 1.3.3', 'vsftpd 2.',
        'samba 3.', 'smbd 3.', 'php/5.', 'iis/6', 'iis/7',
    ]

    lines: list[str] = ["Nmap scan results:", origin_label]
    hosts_found = 0
    risky_findings: list[str] = []
    legacy_findings: list[str] = []

    # Parse host blocks from nmap output
    current_host = None
    host_lines: list[str] = []
    stdout_lower = stdout.lower()

    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # New host block
        if stripped.startswith('Nmap scan report for '):
            if current_host and host_lines:
                lines.append("")
                lines.append(current_host)
                lines.extend(host_lines)
            current_host = stripped
            host_lines = []
            hosts_found += 1
            continue

        # Port lines (e.g., "22/tcp  open  ssh  OpenSSH 8.9p1")
        port_match = re.match(r'^(\d+)/(tcp|udp)\s+(\S+)\s+(.*)', stripped)
        if port_match:
            port_num, proto, state, service_info = port_match.groups()
            entry = f"  - {port_num}/{proto} {state}: {service_info}"
            host_lines.append(entry)

            # Flag risky ports
            if state == 'open' and port_num in RISKY_PORTS:
                risky_findings.append(f"{current_host or '?'}: {port_num}/{proto} ({RISKY_PORTS[port_num]}) - {service_info}")

            # Flag legacy services
            svc_lower = service_info.lower()
            for keyword in LEGACY_KEYWORDS:
                if keyword in svc_lower:
                    legacy_findings.append(f"{current_host or '?'}: {service_info} (legacy: {keyword})")
                    break
            continue

        # OS detection lines
        if stripped.startswith('OS details:') or stripped.startswith('Running:') or stripped.startswith('OS CPE:'):
            host_lines.append(f"  - {stripped}")
            for keyword in LEGACY_KEYWORDS:
                if keyword in stripped.lower():
                    legacy_findings.append(f"{current_host or '?'}: {stripped} (legacy OS)")
                    break
            continue

        # Aggressive OS guess
        if stripped.startswith('Aggressive OS guesses:'):
            host_lines.append(f"  - {stripped}")
            continue

        # MAC address line
        if stripped.startswith('MAC Address:'):
            host_lines.append(f"  - {stripped}")
            continue

        # Service Info line
        if stripped.startswith('Service Info:'):
            host_lines.append(f"  - {stripped}")
            continue

    # Flush last host
    if current_host and host_lines:
        lines.append("")
        lines.append(current_host)
        lines.extend(host_lines)

    # Summary section
    lines.append("")
    lines.append(f"Hosts discovered: {hosts_found}")

    if risky_findings:
        lines.append("")
        lines.append("Risky / sensitive open services:")
        for finding in risky_findings[:20]:
            lines.append(f"  - {finding}")

    if legacy_findings:
        lines.append("")
        lines.append("Legacy / outdated software detected:")
        for finding in legacy_findings[:15]:
            lines.append(f"  - {finding}")

    # Append any Nmap summary footer
    for line in stdout.splitlines()[-5:]:
        if 'Nmap done' in line:
            lines.append("")
            lines.append(line.strip())
            break

    return "\n".join(lines)


def _format_subnet_map_result(result: dict[str, Any]) -> str:
    """Format a pineapple_subnet_map result into a structured report."""
    iface = result.get('scan_interface') or 'wlan2'
    origin = result.get('scan_origin') or 'pineapple'
    target = result.get('target') or '?'
    aggressive = bool(result.get('aggressive'))

    if not result.get('ok'):
        parts: list[str] = ['Subnet map failed.']
        stage = result.get('stage') or 'preflight'
        parts.append(f'Origin: {origin} / {iface}')
        parts.append(f'Target: {target}')
        parts.append(f'Failed stage: {stage}')
        ftype = result.get('failure_type')
        if ftype:
            parts.append(f'Failure type: {ftype}')
        err = (result.get('error') or '').strip()
        if err:
            parts.append(f'Error: {err}')
        preflight = result.get('preflight') or {}
        checks = preflight.get('checks') or []
        failing = [c for c in checks if not c.get('ok')]
        if failing:
            parts.append('Failing preflight checks:')
            for c in failing:
                detail = c.get('detail') or ''
                parts.append(f"  - {c.get('check')}: {detail}")
        failed_stages = result.get('failed_stages') or []
        if failed_stages:
            parts.append('Failed stages: ' + ', '.join(failed_stages))
        warnings = result.get('warnings') or []
        if warnings:
            parts.append('Warnings:')
            for w in warnings[:8]:
                parts.append(f'  - {w}')
        cmds = result.get('commands_run') or []
        if cmds:
            parts.append('Commands attempted:')
            for cmd in cmds[-10:]:
                parts.append(f'  - {cmd}')
        report_md = result.get('report_markdown_path')
        report_html = result.get('report_html_path')
        summary_json = result.get('summary_json_path')
        capture_dir = result.get('capture_dir')
        log_path = result.get('log_path')
        if any([report_md, report_html, summary_json, capture_dir, log_path]):
            parts.append('Reports and artifacts (partial):')
            if report_md:
                parts.append(f'  - Markdown report: {report_md}')
            if report_html:
                parts.append(f'  - HTML report: {report_html}')
            if summary_json:
                parts.append(f'  - Summary JSON: {summary_json}')
            if capture_dir:
                parts.append(f'  - Raw Nmap outputs: {capture_dir}/')
            if log_path:
                parts.append(f'  - Log: {log_path}')
        return '\n'.join(parts)

    connected_ip = result.get('connected_ip') or '?'
    connected_gateway = result.get('connected_gateway') or '?'
    connected_subnet = result.get('connected_subnet') or '?'
    live_hosts = result.get('live_hosts') or []
    port_scan_results = result.get('port_scan_results') or []
    service_results = result.get('service_results') or []
    os_results = result.get('os_results') or []
    warnings = result.get('warnings') or []
    failed_stages = result.get('failed_stages') or []
    commands_run = result.get('commands_run') or []
    stages_run = result.get('stages_run') or []

    lines: list[str] = []
    header = f'Subnet map completed from the {origin.replace("_", " ")} on {iface}'
    if aggressive:
        header += ' (aggressive per-host scan on live hosts)'
    lines.append(header + '.')
    lines.append(f'Target: {target}')
    if stages_run:
        lines.append(f'Stages run: {", ".join(stages_run)}')
    lines.append('')
    lines.append('Connected network:')
    lines.append(f'  Interface: {iface}')
    lines.append(f'  Pineapple IP: {connected_ip}')
    lines.append(f'  Gateway: {connected_gateway}')
    lines.append(f'  Subnet: {connected_subnet}')
    lines.append('')

    if result.get('note'):
        lines.append(str(result['note']))
        lines.append('')

    lines.append(f'Live hosts ({len(live_hosts)}):')
    if not live_hosts:
        lines.append('  - none')
    else:
        for h in live_hosts:
            ip = h.get('ip') or '?'
            extras: list[str] = []
            if h.get('hostname'):
                extras.append(str(h['hostname']))
            if h.get('mac'):
                extras.append(str(h['mac']))
            if h.get('vendor'):
                extras.append(str(h['vendor']))
            if h.get('reason'):
                extras.append(f'reason={h["reason"]}')
            suffix = f' - {" / ".join(extras)}' if extras else ''
            lines.append(f'  - {ip}{suffix}')
    lines.append('')

    if port_scan_results:
        lines.append('Open ports:')
        for pr in port_scan_results:
            host = pr.get('host') or '?'
            ports = pr.get('ports') or []
            if not ports:
                lines.append(f'  - {host}: no open ports')
                continue
            bits: list[str] = []
            for p in ports:
                svc = (p.get('service') or {}).get('name') or ''
                label = f"{p.get('port')}/{p.get('protocol')}"
                if svc:
                    label += f' {svc}'
                bits.append(label)
            lines.append(f'  - {host}: ' + ', '.join(bits))
        lines.append('')
    else:
        lines.append('Open ports: none found.')
        lines.append('')

    if service_results:
        lines.append('Services:')
        for sr in service_results:
            host = sr.get('host') or '?'
            svcs = sr.get('services') or []
            for svc in svcs[:40]:
                port = svc.get('port')
                proto = svc.get('protocol')
                label_bits = [n for n in (
                    svc.get('name'), svc.get('product'),
                    svc.get('version'), svc.get('extrainfo'),
                ) if n]
                line_suffix = ' '.join(str(b) for b in label_bits)
                lines.append(f'  - {host}: {port}/{proto} {line_suffix}'.rstrip())
        lines.append('')

    if os_results:
        lines.append('OS guesses:')
        for osr in os_results:
            host = osr.get('host') or '?'
            best = osr.get('best')
            if best and best.get('name'):
                acc = best.get('accuracy', '?')
                lines.append(f"  - {host}: {best['name']} (accuracy {acc}%)")
            elif osr.get('note'):
                lines.append(f"  - {host}: {osr['note']}")
            else:
                lines.append(f"  - {host}: OS not reliably detected")
        lines.append('')

    if failed_stages:
        lines.append('Failed stages:')
        for s in failed_stages:
            lines.append(f'  - {s}')
        lines.append('')

    if warnings:
        lines.append('Warnings:')
        for w in warnings:
            lines.append(f'  - {w}')
        lines.append('')

    if commands_run:
        lines.append('Commands run:')
        for cmd in commands_run:
            lines.append(f'  - {cmd}')
        lines.append('')

    # Artifact paths
    report_md = result.get('report_markdown_path')
    report_html = result.get('report_html_path')
    summary_json = result.get('summary_json_path')
    capture_dir = result.get('capture_dir')
    log_path = result.get('log_path')
    if any([report_md, report_html, summary_json, capture_dir, log_path]):
        lines.append('Reports and artifacts:')
        if report_md:
            lines.append(f'  - Markdown report: {report_md}')
        if report_html:
            lines.append(f'  - HTML report: {report_html}')
        if summary_json:
            lines.append(f'  - Summary JSON: {summary_json}')
        if capture_dir:
            lines.append(f'  - Raw Nmap outputs: {capture_dir}/')
        if log_path:
            lines.append(f'  - Log: {log_path}')

    # General caveats
    lines.append('')
    lines.append('Notes:')
    lines.append('  - OS detection is a guess - Nmap infers from TCP/IP fingerprints.')
    lines.append('  - Hosts behind firewalls or with ICMP blocked may not appear.')
    lines.append(f'  - Results originate from the Pineapple path ({iface}), not local Kali eth0.')

    return "\n".join(lines).rstrip()


def _format_live_unencrypted_scan_result(result: dict[str, Any]) -> str:
    """Format live unencrypted scan results into a concise user-facing summary.

    Never emits ``"unknown error"`` - every failure path surfaces the
    ``failure_type``, the specific error, and (when available) the command
    that failed.
    """
    if not result.get("ok"):
        parts: list[str] = ["Unencrypted traffic scan failed."]
        ftype = result.get("failure_type")
        if ftype:
            parts.append(f"Failure type: {ftype}")
        iface = result.get("interface")
        if iface:
            origin = "Pineapple" if result.get("pineapple_path") else "local Kali"
            parts.append(f"Origin: {origin} / {iface}")
        err = (result.get("error") or "").strip()
        if err:
            parts.append(f"Error: {err}")
        cmd = result.get("cmd")
        if cmd:
            parts.append(f"Command: {cmd}")
        report_dir = result.get("report_dir")
        if report_dir:
            parts.append(f"Partial artifacts may be under: {report_dir}")
        if not err and not ftype:
            parts.append(
                "The tool returned no output and no error. Check logs/action_log.jsonl."
            )
        return "\n".join(parts)

    lines: list[str] = []
    iface = result.get("interface") or "?"
    if result.get("pineapple_path"):
        lines.append(f"Unencrypted-traffic scan completed on the Pineapple ({iface}).")
    else:
        lines.append(f"Unencrypted-traffic scan completed locally on Kali ({iface}).")

    iface_ip = result.get("interface_ip")
    if iface_ip:
        lines.append(f"Interface IP: {iface_ip}")
    lines.append(f"Duration: {result.get('duration', '?')} seconds")
    lines.append(f"Packets captured: {result.get('packet_count', 0)}")
    if result.get("pcap_path"):
        lines.append(f"PCAP: {result['pcap_path']}")
    if result.get("report_dir"):
        lines.append(f"Report dir: {result['report_dir']}")
    if result.get("report_html_path"):
        lines.append(f"HTML report: {result['report_html_path']}")
    if result.get("report_markdown_path"):
        lines.append(f"Markdown report: {result['report_markdown_path']}")

    # Plaintext protocols
    protos = result.get("plaintext_protocols_observed") or []
    lines.append("")
    if protos:
        lines.append("Plaintext protocols observed: " + ", ".join(protos))
    else:
        lines.append("Plaintext protocols observed: none.")

    # HTTP summary
    req_count = len(result.get("http_requests") or [])
    resp_count = len(result.get("http_responses") or [])
    obj_count = len(result.get("http_objects") or [])
    lines.append(f"HTTP: {req_count} request(s), {resp_count} response(s), {obj_count} object(s) exported.")

    # Media
    images = result.get("extracted_images") or []
    videos = result.get("extracted_videos") or []
    lines.append(f"Media extracted: {len(images)} image(s), {len(videos)} video(s).")
    for m in images + videos:
        size_kb = (m.get("size_bytes") or 0) / 1024.0
        source = m.get("source_host") or ""
        if m.get("source_uri"):
            source = f'{source}{m["source_uri"]}'
        sha16 = (m.get("sha256") or "")[:16]
        label = f"  - {m.get('mime_type','?')} {m.get('filename','?')} "
        label += f"({size_kb:.1f} KB, sha256:{sha16}"
        if source:
            label += f", source {source}"
        label += ")"
        lines.append(label)

    # Credentials
    creds = result.get("credentials") or []
    lines.append("")
    if creds:
        lines.append(f"Credential indicators: {len(creds)} item(s) - see report for details.")
    else:
        lines.append("Credential indicators: none observed.")

    # MITM state
    arp_state = result.get("arp_spoof_active")
    ipfwd_state = result.get("ip_forwarding")
    if arp_state is not None or ipfwd_state is not None:
        lines.append(
            "Pineapple MITM state: "
            f"arpspoof={'active' if arp_state else 'not detected'}, "
            f"ip_forwarding={'on' if ipfwd_state else 'off'}"
        )

    warnings = result.get("warnings") or []
    if warnings:
        lines.append("")
        lines.append("Warnings:")
        for w in warnings:
            lines.append(f"  - {w}")

    errors = result.get("errors") or []
    if errors:
        lines.append("")
        lines.append("Errors (non-fatal):")
        for e in errors:
            lines.append(f"  - {e}")

    lines.append("")
    lines.append("Open report.html in a browser to see extracted images and video previews.")

    return "\n".join(lines)


def _format_arpspoof_result(result: dict[str, Any]) -> str:
    if not result.get("ok"):
        lines = [f"ARP spoof failed: {result.get('error') or 'unknown error'}"]
        diag = result.get("diagnostics") or {}
        avail = diag.get("available_tools") or result.get("available_tools") or []
        miss = diag.get("missing_tools") or result.get("missing_tools") or []
        if avail or miss:
            lines.append(
                f"Available ARP tools on Pineapple: {avail or 'none'}; "
                f"missing: {miss or 'none'}."
            )
        if diag.get("dsniff_in_opkg_feed") is False:
            lines.append("Note: dsniff is NOT in the Pineapple's opkg feeds - `opkg install dsniff` will fail.")
        if result.get("suggestion"):
            lines.append(f"Next step: {result['suggestion']}")
        return "\n".join(lines)
    origin = result.get("scan_origin", "unknown")
    second = result.get("peer_ip") or result.get("gateway_ip")
    headline = (
        "ARP spoof started from the Pineapple."
        if origin == "pineapple"
        else f"ARP spoof started locally on Kali."
    )
    lines = [
        headline,
        f"Target: {result.get('target_ip')} ↔ Peer: {second}",
        f"Interface: {result.get('interface')}",
        f"IP forwarding: {'enabled' if result.get('ip_forwarding') else 'unknown'}",
        "Mode: bidirectional",
    ]
    if result.get("method"):
        lines.append(f"Method: {result['method']}")
    pids = result.get("pids")
    if pids:
        lines.append(f"PIDs: {pids}")
    if result.get("remote_log_paths"):
        lines.append(f"Remote logs: {', '.join(result['remote_log_paths'])}")
    lines.append("Use 'stop arpspoof' to terminate.")
    return "\n".join(lines)


def _format_stop_arpspoof_result(result: dict[str, Any]) -> str:
    if not result.get("ok"):
        return f"Stop ARP spoof failed: {result.get('error') or 'unknown error'}"
    return result.get("msg", "ARP spoof stopped.")


def _deterministic_answer_for_tool(tool_call: dict[str, Any], result: dict[str, Any], user_text: str) -> str | None:
    action = tool_call.get("action")
    if action == "pineapple_nearby_ssids":
        return _format_nearby_ssids_result(result, user_text)
    if action == "pineapple_analyze_ssid":
        return _format_ssid_analysis_result(result)
    if action == "pineapple_deep_analyze_ssid":
        return _format_deep_ssid_analysis_result(result)
    if action == "pineapple_client_activity_report":
        return _format_client_activity_result(result)
    if action == "pineapple_deauth_and_capture":
        return _format_deauth_result(result)
    if action == "hcxdumptool_capture":
        return _format_hcx_result(result)
    if action == "crack_wifi_pcap":
        return _format_crack_result(result)
    if action == "pineapple_connect":
        return _format_connect_result(result)
    if action == "nmap_scan":
        return _format_nmap_result(result)
    if action == "pineapple_nmap_scan":
        return _format_nmap_result(result)
    if action == "pineapple_subnet_map":
        return _format_subnet_map_result(result)
    if action == "live_unencrypted_scan":
        return _format_live_unencrypted_scan_result(result)
    if action == "unencrypted_scan":
        return _format_live_unencrypted_scan_result(result)
    if action in ("pineapple_arpspoof", "arpspoof"):
        return _format_arpspoof_result(result)
    if action in ("pineapple_stop_arpspoof", "stop_arpspoof"):
        return _format_stop_arpspoof_result(result)
    return None


def _save_session_context_from_result(
    store: SessionStore,
    session_id: str,
    tool_call: dict[str, Any],
    result: dict[str, Any],
) -> None:
    """Persist key state from tool results into session context for future turns."""
    action = tool_call.get("action", "")

    # Track active BSSID and channel from deauth, capture, and analysis actions
    bssid = result.get("bssid") or tool_call.get("bssid")
    channel = result.get("channel") or tool_call.get("channel")
    if bssid:
        store.set_context(session_id, "active_bssid", str(bssid).upper())
    if channel is not None:
        store.set_context(session_id, "active_channel", int(channel))

    # Only update active_ssid when the user explicitly targeted an SSID.
    # Do NOT set active_ssid from pineapple_nearby_ssids - taking the first
    # scanned network as the "active" SSID would poison follow-up routing.
    _SSID_TARGETING_ACTIONS = {
        "pineapple_analyze_ssid",
        "pineapple_deep_analyze_ssid",
        "pineapple_client_activity_report",
        "pineapple_connect",
    }
    if action in _SSID_TARGETING_ACTIONS:
        ssid = result.get("ssid") or str(tool_call.get("ssid", "")).strip()
        if ssid:
            store.set_context(session_id, "active_ssid", str(ssid))

    # Track connected network info from pineapple_connect for nmap/arpspoof chaining.
    # Save as both active_* and connected_* for compatibility.
    if action == "pineapple_connect" and result.get("ok"):
        import ipaddress as _ipaddr
        stdout = result.get("stdout", "") or ""
        ip_cidr_m = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', stdout)
        if ip_cidr_m:
            try:
                addr = _ipaddr.ip_interface(ip_cidr_m.group(1))
                net = addr.network
                store.set_context(session_id, "connected_subnet", str(net))
                store.set_context(session_id, "active_subnet", str(net))
                store.set_context(session_id, "active_ip", str(addr.ip))
                store.set_context(session_id, "active_cidr", ip_cidr_m.group(1))
            except ValueError:
                subnet_m = re.search(r'(\d+\.\d+\.\d+)\.\d+/(\d+)', stdout)
                if subnet_m:
                    sn = f"{subnet_m.group(1)}.0/{subnet_m.group(2)}"
                    store.set_context(session_id, "connected_subnet", sn)
                    store.set_context(session_id, "active_subnet", sn)
        gw_m = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', stdout)
        if gw_m:
            store.set_context(session_id, "connected_gateway", gw_m.group(1))
            store.set_context(session_id, "active_gateway", gw_m.group(1))
        # Save interface under both keys so _build_pineapple_subnet_map_tool_call
        # and other downstream builders can look it up either way.
        store.set_context(session_id, "active_interface", "wlan2")
        store.set_context(session_id, "connected_interface", "wlan2")
        store.set_context(session_id, "active_scan_origin", "pineapple")
        if result.get("ssid"):
            store.set_context(session_id, "active_ssid", str(result["ssid"]))

    # Track last PCAP path
    pcap_path = result.get("pcap_path") or result.get("local_pcap")
    if pcap_path:
        store.set_context(session_id, "last_pcap_path", str(pcap_path))

    # Track last hash path
    hash_path = result.get("hash_path") or result.get("output_hash_path")
    if hash_path:
        store.set_context(session_id, "last_hash_path", str(hash_path))

    # Track cracked password
    cracked = result.get("cracked_password")
    if cracked:
        store.set_context(session_id, "cracked_password", str(cracked))


_PROMPT_LEAK_MARKERS = [
    # Prompt-structure fragments the LLM sometimes echoes back.
    "Instructions for this turn:",
    "Instructions for next turn:",
    "Conversation so far:",
    "Current user message:",
    "Reply with ONLY one valid JSON",
    "Correction:\nThe current request",
    "Task:\nDecide whether",
    # Tool-call / schema leaks appended to prose answers.
    "\nAction:",
    "\nAction :",
    '\n{"action"',
    "\nTool schema:",
    "\nHardware Context",
    # Example JSON leaks from the tool schema.
    "\nExample:",
    "\nExample :",
    "\nexample:",
    # Instruction-boundary tokens from chat-template models.
    "[/INST]",
    "[INST]",
    "<|im_end|>",
    "</s>",
]

# Regex: a line starting with Action: followed by JSON-like content.
_ACTION_LINE_RE = re.compile(
    r'\n\s*Action\s*:\s*\{.*', re.DOTALL | re.IGNORECASE
)

# Regex: a trailing JSON/config block that starts on its own line after prose.
# Matches a newline, optional whitespace, then a '{' followed by at least 30
# characters (to skip tiny inline fragments) all the way to the end of string.
_TRAILING_JSON_BLOCK_RE = re.compile(
    r'\n\s*\{.{30,}\s*$', re.DOTALL
)


def _sanitize_display_text(text: str) -> str:
    """Strip internal prompt fragments that the LLM sometimes echoes back."""
    t = (text or "").strip()
    for marker in _PROMPT_LEAK_MARKERS:
        idx = t.find(marker)
        if idx != -1:
            t = t[:idx].strip()
    # Strip trailing Action: {...} blocks that leak from the tool schema.
    t = _ACTION_LINE_RE.sub('', t).strip()
    # Strip trailing JSON/config blocks (e.g. {"type":"program",...}) that
    # sometimes get appended after an otherwise-normal prose answer.
    t = _TRAILING_JSON_BLOCK_RE.sub('', t).strip()
    return t


def _grounded_followup(
    cfg: dict[str, Any],
    system_prompt: str,
    conversation: str,
    last_observation: dict[str, Any],
    user_text: str,
) -> str:
    prompt = build_grounded_answer_prompt(
        system_prompt=system_prompt,
        conversation=conversation,
        last_observation=last_observation,
        user_text=user_text,
    )
    return _ask_model(
        cfg,
        prompt,
        temperature=float(_cfg_get(cfg, "config", "agent", "answer_temperature", default=0.0)),
    )


def _run_turn(
    cfg: dict[str, Any],
    store: SessionStore,
    session_id: str,
    user_text: str,
) -> str:
    normalized_user_text = _normalize_user_text(user_text)
    store.append_message(session_id, "user", user_text)

    # Greeting gate: use the broader _is_greeting_or_smalltalk check (not just the
    # narrow _smalltalk_reply check) so "Good evening!" and similar variants with
    # punctuation are caught correctly and never reach the LLM tool pipeline.
    known_ssids_now = _known_ssids_from_session(store, session_id)
    if _is_greeting_or_smalltalk(normalized_user_text) and not _request_requires_live_tool(normalized_user_text, known_ssids_now):
        smalltalk = _smalltalk_reply(normalized_user_text)
        reply = smalltalk if smalltalk is not None else "Hello."
        store.append_message(session_id, "assistant", reply)
        return reply

    # Conceptual / educational question gate. Must run BEFORE _route_request,
    # otherwise fuzzy SSID matching against session history can route a plain
    # "what is X" question into pineapple_nearby_ssids or pineapple_analyze_ssid.
    if _is_definition_question(normalized_user_text) and not _looks_like_connect_intent(normalized_user_text):
        system_prompt = build_system_prompt(cfg)
        conversation = store.render_for_prompt(session_id)
        reply = _plan_reply(cfg, system_prompt, conversation)
        # If the LLM produced a tool-call JSON despite the conceptual gate, drop
        # it and ask the LLM again with an explicit "no tools" instruction.
        if _looks_like_attempted_tool_call(reply):
            forced_prose_prompt = (
                build_followup_prompt(system_prompt=system_prompt, conversation=conversation)
                + "\nSystem correction: this is a conceptual / educational question. "
                  "Answer in plain natural language. Do NOT output JSON. Do NOT call any tool.\nAssistant:"
            )
            reply = _ask_model(cfg, forced_prose_prompt, temperature=0.2)
        reply = _sanitize_display_text(reply) or reply
        store.append_message(session_id, "assistant", reply)
        return reply

    hard_routed = _route_request(cfg, normalized_user_text, store, session_id)
    # Sentinel: connect intent detected but SSID/password missing - fall through to LLM.
    if hard_routed and hard_routed.get("action") == "__connect_params_needed__":
        hard_routed = None
    # Sentinel: nmap intent detected but no target/subnet known.
    if hard_routed and hard_routed.get("action") == "__nmap_target_needed__":
        reply = (
            "I detected a network scan request but I don't have a target subnet. "
            "Connect the Pineapple to a network first, or provide a target like 192.168.X.0/24."
        )
        store.append_message(session_id, "assistant", reply)
        return reply
    # Sentinel: arpspoof intent detected but missing target/gateway.
    if hard_routed and hard_routed.get("action") == "__arpspoof_params_needed__":
        reply = (
            "I detected an ARP spoof request but need both a target IP and a gateway IP. "
            "Example: start arpspoof on 192.168.X.X and 192.168.X.X"
        )
        store.append_message(session_id, "assistant", reply)
        return reply
    if hard_routed:
        planned_reply = json.dumps(hard_routed)
        store.append_message(session_id, "assistant", planned_reply)
        result = execute_tool_call(hard_routed, cfg)
        store.append_tool_result(session_id, hard_routed, result)
        _save_session_context_from_result(store, session_id, hard_routed, result)

        deterministic_answer = _deterministic_answer_for_tool(hard_routed, result, normalized_user_text)
        if deterministic_answer is not None:
            store.append_message(session_id, "assistant", deterministic_answer)
            return deterministic_answer

        system_prompt = build_system_prompt(cfg)
        grounded = _grounded_followup(
            cfg=cfg,
            system_prompt=system_prompt,
            conversation=store.render_for_prompt(session_id),
            last_observation=result,
            user_text=normalized_user_text,
        )
        grounded = _sanitize_display_text(grounded) or grounded
        store.append_message(session_id, "assistant", grounded)
        return grounded

    system_prompt = build_system_prompt(cfg)
    max_tool_rounds = int(_cfg_get(cfg, "config", "agent", "max_tool_rounds_per_user_turn", default=4))
    enforce_live_gate = bool(_cfg_get(cfg, "config", "agent", "enforce_live_observation_gate", default=True))

    for _ in range(max_tool_rounds):
        conversation = store.render_for_prompt(session_id)
        known_ssids = _known_ssids_from_session(store, session_id)
        active_ssid = store.get_context(session_id, "active_ssid")

        classification = _classify_turn(
            cfg=cfg,
            system_prompt=system_prompt,
            conversation=conversation,
            user_text=normalized_user_text,
            known_ssids=known_ssids,
            active_ssid=active_ssid,
        )

        # Fast-path: skip the LLM planner for clearly deterministic intents.
        if classification.get("reason") == "heuristic_hcx_capture":
            forced = _build_hcx_capture_tool_call_from_text(normalized_user_text, store, session_id)
            if forced:
                planned_reply = json.dumps(forced)
                tool_call: dict[str, Any] | None = forced
            else:
                planned_reply = _plan_reply(cfg, system_prompt, conversation)
                tool_call = _validate_tool_call(cfg, _extract_pure_json_tool_call(planned_reply))
        elif classification.get("reason") == "heuristic_connect_intent":
            forced = _build_connect_tool_call_from_text(normalized_user_text, store, session_id)
            if forced:
                planned_reply = json.dumps(forced)
                tool_call: dict[str, Any] | None = forced
            else:
                # SSID or password missing - let LLM ask the user
                planned_reply = _plan_reply(cfg, system_prompt, conversation)
                tool_call = _validate_tool_call(cfg, _extract_pure_json_tool_call(planned_reply))
        elif classification.get("reason") == "heuristic_deauth_capture":
            forced = _build_deauth_capture_tool_call_from_text(normalized_user_text, store, session_id)
            if forced:
                planned_reply = json.dumps(forced)
                tool_call: dict[str, Any] | None = forced
            else:
                planned_reply = _plan_reply(cfg, system_prompt, conversation)
                tool_call = _validate_tool_call(cfg, _extract_pure_json_tool_call(planned_reply))
        elif classification.get("reason") == "heuristic_subnet_map":
            forced = _build_pineapple_subnet_map_tool_call(normalized_user_text, store, session_id)
            if forced:
                planned_reply = json.dumps(forced)
                tool_call: dict[str, Any] | None = forced
            else:
                reply = (
                    "I detected a subnet-map request but I don't have a target subnet. "
                    "Connect the Pineapple to the target network first, or provide a target like 192.168.X.0/24."
                )
                store.append_message(session_id, "assistant", reply)
                return reply
        elif classification.get("reason") == "heuristic_nmap_scan":
            forced = _build_nmap_tool_call(normalized_user_text, store, session_id)
            if forced:
                planned_reply = json.dumps(forced)
                tool_call: dict[str, Any] | None = forced
            else:
                reply = (
                    "I detected a network scan request but I don't have a target subnet. "
                    "Connect the Pineapple first, or specify a target like 192.168.X.0/24."
                )
                store.append_message(session_id, "assistant", reply)
                return reply
        elif classification.get("reason") == "heuristic_live_unencrypted_scan":
            forced = _build_live_unencrypted_scan_tool_call(normalized_user_text)
            planned_reply = json.dumps(forced)
            tool_call = forced
        elif classification.get("reason") == "heuristic_arpspoof":
            forced = _build_arpspoof_tool_call(normalized_user_text, store, session_id)
            if forced:
                planned_reply = json.dumps(forced)
                tool_call = forced
            else:
                reply = (
                    "I need both a target IP and a gateway IP for ARP spoofing. "
                    "Example: start arpspoof on 192.168.X.X and 192.168.X.X"
                )
                store.append_message(session_id, "assistant", reply)
                return reply
        elif classification.get("reason") == "heuristic_stop_arpspoof":
            local = _looks_like_local_execution_intent(normalized_user_text)
            forced = {"action": "stop_arpspoof" if local else "pineapple_stop_arpspoof"}
            planned_reply = json.dumps(forced)
            tool_call = forced
        else:
            planned_reply = _plan_reply(cfg, system_prompt, conversation)
            tool_call = _validate_tool_call(cfg, _extract_pure_json_tool_call(planned_reply))

        if tool_call and not _tool_call_matches_user_intent(tool_call, normalized_user_text):
            deterministic_tool_call = _force_live_request_tool_call(cfg, normalized_user_text, store, session_id)
            if deterministic_tool_call:
                planned_reply = json.dumps(deterministic_tool_call)
                tool_call = deterministic_tool_call

        if not tool_call and classification["requires_tool"] and enforce_live_gate:
            repaired = _repair_for_tool(
                cfg=cfg,
                system_prompt=system_prompt,
                conversation=conversation + f"\nUser: {normalized_user_text}",
                reason=classification["reason"] or "requires_live_tool",
                suggested_actions=classification["suggested_actions"],
            )
            repaired_tool_call = _validate_tool_call(cfg, _extract_pure_json_tool_call(repaired))
            if repaired_tool_call:
                planned_reply = repaired
                tool_call = repaired_tool_call

        if not tool_call and classification["requires_tool"] and enforce_live_gate:
            deterministic_tool_call = _force_live_request_tool_call(cfg, normalized_user_text, store, session_id)
            if deterministic_tool_call:
                planned_reply = json.dumps(deterministic_tool_call)
                tool_call = deterministic_tool_call

        if not tool_call:
            if classification["requires_tool"] and enforce_live_gate:
                if _looks_like_attempted_tool_call(planned_reply):
                    repaired = _repair_mixed_tool_call(
                        cfg=cfg,
                        system_prompt=system_prompt,
                        conversation=conversation,
                    )
                    repaired_tool_call = _validate_tool_call(cfg, _extract_pure_json_tool_call(repaired))
                    if repaired_tool_call:
                        planned_reply = repaired
                        tool_call = repaired_tool_call
                    else:
                        deterministic_tool_call = _force_live_request_tool_call(cfg, normalized_user_text, store, session_id)
                        if deterministic_tool_call:
                            planned_reply = json.dumps(deterministic_tool_call)
                            tool_call = deterministic_tool_call
                        else:
                            safe_fail = (
                                "This request requires a real live observation, but I could not produce a valid supported tool call."
                            )
                            store.append_message(session_id, "assistant", safe_fail)
                            return safe_fail
                else:
                    deterministic_tool_call = _force_live_request_tool_call(cfg, normalized_user_text, store, session_id)
                    if deterministic_tool_call:
                        planned_reply = json.dumps(deterministic_tool_call)
                        tool_call = deterministic_tool_call
                    else:
                        safe_fail = (
                            "This request requires a live scan or status check, but no valid supported tool call was produced."
                        )
                        store.append_message(session_id, "assistant", safe_fail)
                        return safe_fail
            else:
                clean_reply = _sanitize_display_text(planned_reply) or planned_reply
                store.append_message(session_id, "assistant", clean_reply)
                return clean_reply

        if tool_call and not _tool_call_matches_user_intent(tool_call, normalized_user_text):
            deterministic_tool_call = _force_live_request_tool_call(cfg, normalized_user_text, store, session_id)
            if deterministic_tool_call:
                planned_reply = json.dumps(deterministic_tool_call)
                tool_call = deterministic_tool_call

        store.append_message(session_id, "assistant", planned_reply)
        result = execute_tool_call(tool_call, cfg)
        store.append_tool_result(session_id, tool_call, result)
        _save_session_context_from_result(store, session_id, tool_call, result)

        deterministic_answer = _deterministic_answer_for_tool(tool_call, result, normalized_user_text)
        if deterministic_answer is not None:
            store.append_message(session_id, "assistant", deterministic_answer)
            return deterministic_answer

        grounded = _grounded_followup(
            cfg=cfg,
            system_prompt=system_prompt,
            conversation=store.render_for_prompt(session_id),
            last_observation=result,
            user_text=normalized_user_text,
        )
        next_tool_call = _validate_tool_call(cfg, _extract_pure_json_tool_call(grounded))

        if next_tool_call:
            if not _tool_call_matches_user_intent(next_tool_call, normalized_user_text):
                forced = _force_live_request_tool_call(cfg, normalized_user_text, store, session_id)
                if forced:
                    store.append_message(session_id, "assistant", json.dumps(forced))
                    continue
            store.append_message(session_id, "assistant", grounded)
            continue

        if _looks_like_attempted_tool_call(grounded) and not next_tool_call:
            repaired = _repair_mixed_tool_call(
                cfg=cfg,
                system_prompt=system_prompt,
                conversation=store.render_for_prompt(session_id),
            )
            repaired_tool_call = _validate_tool_call(cfg, _extract_pure_json_tool_call(repaired))
            if repaired_tool_call:
                if not _tool_call_matches_user_intent(repaired_tool_call, normalized_user_text):
                    forced = _force_live_request_tool_call(cfg, normalized_user_text, store, session_id)
                    if forced:
                        store.append_message(session_id, "assistant", json.dumps(forced))
                        continue
                store.append_message(session_id, "assistant", repaired)
                continue

        grounded = _sanitize_display_text(grounded) or grounded
        store.append_message(session_id, "assistant", grounded)
        return grounded

    fallback = (
        "I stopped because the tool loop limit was reached for this turn. "
        "The last completed observation is in memory, so you can continue from there."
    )
    store.append_message(session_id, "assistant", fallback)
    return fallback


def interactive_loop(session_id: str) -> None:
    ensure_runtime_dirs()
    cfg = load_all_config()
    store = SessionStore()

    print("Companion Huginn")
    print("Type 'exit' or 'quit' to leave.\n")

    while True:
        try:
            user_text = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not user_text:
            continue

        if user_text.lower() in {"exit", "quit"}:
            break

        try:
            answer = _run_turn(cfg, store, session_id, user_text)
            print(answer)
        except Exception as exc:
            print(f"Error: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Companion Huginn CLI")
    parser.add_argument("--session", default="default", help="Session ID to use for memory/context")
    parser.add_argument(
        "--once",
        metavar="INPUT",
        default=None,
        help="Run a single turn with the given input text and exit (non-interactive)",
    )
    args = parser.parse_args()

    if args.once is not None:
        import sys
        try:
            ensure_runtime_dirs()
            cfg = load_all_config()
            store = SessionStore()
            answer = _run_turn(cfg, store, args.session, args.once)
            print(answer)
        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        return

    interactive_loop(session_id=args.session)


if __name__ == "__main__":
    main()
