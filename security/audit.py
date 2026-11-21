#!/usr/bin/env python3
"""Full tracked-file inventory and conservative static privacy/security signal scanner.

This is triage, NOT proof of absence of malicious behavior. All tracked files are
hashed; all decodable text files are scanned; binary contents and dependencies
require independent analysis.
"""
import collections
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
from urllib.parse import urlsplit

ROOT = pathlib.Path(__file__).resolve().parent.parent
paths = [pathlib.Path(p.decode()) for p in subprocess.check_output(
    ["git", "ls-files", "-z"], cwd=ROOT).split(b"\0") if p]
rules = {
    "network_calls": r"\b(?:HttpURLConnection|HttpsURLConnection|URLConnection|OkHttpClient|Retrofit|Request\.Builder|RequestBody|MultipartBody|WebSocket|Socket\s*\(|ServerSocket\s*\(|openConnection\s*\(|openUrl\s*\(|openStream\s*\(|java\.net\.URL|new\s+URL\s*\(|\.newCall\s*\(|\.enqueue\s*\(|\.execute\s*\()",
    "external_communication": r"\b(?:sendBroadcast\s*\(|sendOrderedBroadcast\s*\(|bindService\s*\(|startService\s*\(|startActivity\s*\(|Intent\.ACTION_SEND|Intent\.ACTION_VIEW|Intent\.ACTION_SENDTO|ContentResolver|contentResolver\.query|contentResolver\.insert|contentResolver\.update)\b",
    "dynamic_code_and_exec": r"\b(?:DexClassLoader|PathClassLoader|InMemoryDexClassLoader|Class\.forName|loadClass\s*\(|Runtime\.getRuntime|ProcessBuilder|System\.loadLibrary|System\.load\s*\(|getDeclaredMethod|java\.lang\.reflect|dalvik\.system|JavascriptInterface|addJavascriptInterface|Base64\.decode)\b",
    "message_access": r"\b(?:READ_SMS|RECEIVE_SMS|SEND_SMS|SMS_DELIVER|WAP_PUSH_DELIVER|Telephony\.Sms|Telephony\.Mms|SmsManager|MmsManager|messageRepo|getMessages\s*\(|getBlockedConversations|backupMessages|SmsMessage)\b",
    "logging_and_storage": r"\b(?:Timber\.[vdiwe]\s*\(|Log\.[vdiwe]\s*\(|FileLoggingTree|openOutputStream|FileOutputStream|Environment\.getExternalStorageDirectory|getExternalStoragePublicDirectory|MediaStore\.Downloads|RoomDatabase|RealmConfiguration|writeText\s*\(|writeBytes\s*\()\b",
    "permissions_and_exports": r"(?:android\.permission\.[A-Z_]+|android:exported\s*=|android:grantUriPermissions\s*=|android:usesCleartextTraffic\s*=|android:allowBackup\s*=|android:permission\s*=)",
    "build_and_supply_chain": r"(?:\bclasspath\s+['\"]|\bimplementation\s*[\(\s]['\"]|\bkapt\s+['\"]|\bmaven\s*\{|\bjcenter\s*\(|\bapply plugin:|\bplugins\s*\{|\buses:\s+|\bcurl\s+|\bwget\s+|\bsdkmanager\s+)",
    "external_identifiers": r"(?:com\.google\.firebase|crashlytics|analytics|datashare|callcontrol|org\.mistergroup|com\.cuiet|play\.google\.com|gitlab\.com)",
    "secrets_signals": r"(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{25,}|AIza[0-9A-Za-z\-_]{35})",
}
compiled = {k: re.compile(v, re.I) for k,v in rules.items()}
url_pattern = re.compile(r"https?://[^\s<>\"'()]+", re.I)
records = []
hits = collections.defaultdict(list)
domains = collections.Counter()
binary = []
decode_errors = []
interesting_suffixes = {".jar",".aar",".so",".dex",".class",".apk",".aab",".enc",".keystore",".jks",".p12",".zip",".exe",".dll"}
num_source = 0
for path in paths:
    full = ROOT / path
    if not full.is_file():
        decode_errors.append({"path":str(path),"reason":"tracked file missing"})
        continue
    content = full.read_bytes()
    kind = "text"
    if b"\0" in content[:8192] or path.suffix.lower() in interesting_suffixes or path.suffix.lower() in {".png",".jpg",".jpeg",".webp",".gif",".ico",".woff",".woff2",".ttf"}:
        kind = "binary"
    data = {"path":str(path),"bytes":len(content),"sha256":hashlib.sha256(content).hexdigest(),"kind":kind}
    records.append(data)
    if kind == "binary":
        binary.append(data)
        continue
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        decode_errors.append({"path":str(path),"reason":"not UTF-8"})
        continue
    if path.suffix.lower() in {".kt",".java",".gradle",".xml",".yml",".yaml",".json",".properties",".sh",".py",".bat"}:
        num_source += 1
    for i,line in enumerate(text.splitlines(),1):
        line_strip = line.strip()
        if not line_strip or line_strip.startswith(("*","//","#")):
            continue
        for key,rx in compiled.items():
            if rx.search(line):
                hits[key].append({"path":str(path),"line":i,"excerpt":line_strip[:200]})
        # URLs in code/config, ignoring obvious XML namespaces, license boilerplate
        for match in url_pattern.finditer(line):
            url = match.group(0).rstrip(".,;")
            try: host = urlsplit(url).netloc.lower()
            except ValueError: host = "invalid"
            if host and host not in {"www.w3.org","schemas.android.com","www.apache.org","www.gnu.org"}:
                domains[host]+=1
                hits["literal_urls"].append({"path":str(path),"line":i,"excerpt":url[:200]})

report = {
    "audit_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "git_commit":subprocess.check_output(["git","rev-parse","HEAD"], cwd=ROOT).decode().strip(),
    "tracked_files":len(paths),
    "scanned_text_files":sum(r["kind"]=="text" for r in records),
    "textual_code_or_config_files":num_source,
    "binary_files":len(binary),
    "decode_errors":decode_errors,
    "signals":{"counts":{k:len(v) for k,v in hits.items()},"matches":dict(hits)},
    "domains":domains.most_common(),
    "binaries":binary,
    "files":records,
    "caveat":"Static pattern scanning cannot rule out hidden backdoors, transitive dependencies, binary payloads, or runtime abuse.",
}
(ROOT/"security-inventory.json").write_text(json.dumps(report,indent=2)+"\n")
lines = ["# SynAck SMS — Automated whole-repository source audit","",
"**Important: findings are review signals, NOT confirmed malware or a clean bill of health.**","",
f"- Commit: \`{report['git_commit']}\`",
f"- Tracked files inventoried/hashed: **{len(paths)}**",
f"- Text files read: **{report['scanned_text_files']}**",
f"- Source/config files counted: **{num_source}**",
f"- Binary/non-text files identified: **{len(binary)}**",
f"- Decode issues: **{len(decode_errors)}**","",
"## Signals by category","",
"| Category | Matches |","|---|---:|"]
for k in rules:
    lines.append(f"| {k} | {len(hits[k])} |")
lines.append(f"| literal_urls | {len(hits['literal_urls'])} |")
lines.extend(["","## External URL host inventory",""])
for k,n in domains.most_common(100):
    lines.append(f"- \`{k}\`: {n} literal references")
lines.extend(["","## Binary/opaque artifacts (not verified by textual scan)",""])
for b in binary:
    lines.append(f"- \`{b['path']}\` ({b['bytes']} bytes; SHA256 {b['sha256'][:18]}...)")
for k in [*rules,"literal_urls"]:
    vals=hits[k]
    lines.extend(["",f"## {k} ({len(vals)} matches)",""])
    if not vals:
        lines.append("No matches to this pattern.")
    else:
        for x in vals[:120]:
            escaped=x["excerpt"].replace("|",r"\|").replace("\`","'")
            lines.append(f"- \`{x['path']}:{x['line']}\`: \`{escaped}\`")
        if len(vals)>120:
            lines.append(f"- *{len(vals)-120} additional matches in security-inventory.json.*")
lines.extend(["","## Limitations","",
"- Pattern matches can be benign; absence of matches is not proof of safety.",
"- Binary contents, encryption, compiled libraries and Gradle transitive dependencies require separate verification.",
"- A final merged Android manifest and the APK itself must be checked.",
"- Actual behavior needs a controlled runtime test, especially SMS/MMS, logging and exported components.",
""])
(ROOT/"security-report.md").write_text("\n".join(lines)+"\n")
print("AUDIT COMMIT:",report["git_commit"])
print("TRACKED FILES:",len(paths),"TEXT SCANNED:",report["scanned_text_files"],"BINARY:",len(binary))
print("SIGNAL COUNTS:",json.dumps({k:len(v) for k,v in hits.items()},sort_keys=True))
print("DOMAINS:",json.dumps(domains.most_common(35)))
for k in ["network_calls","external_communication","dynamic_code_and_exec","external_identifiers","secrets_signals"]:
    print("\nCATEGORY",k,"COUNT",len(hits[k]))
    for v in hits[k][:55]:
        print(v["path"]+":"+str(v["line"])+": "+v["excerpt"])
print("\nOPAQUE/BINARY artifacts:")
for x in binary:
    if x["path"].endswith(tuple(interesting_suffixes)):
        print(x["path"],x["bytes"],x["sha256"])
print("\nReport saved to security-report.md and security-inventory.json")
