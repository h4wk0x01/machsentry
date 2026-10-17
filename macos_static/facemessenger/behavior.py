"""Explainable hypotheses over byte evidence; names alone never establish behavior."""

import re

RULESET_VERSION = "1.0.0"
SIGNATURE_CATEGORIES = ('credential_prompt', 'keychain_access', 'outbound_upload', 'wallet_collection', 'browser_collection')

# The interpretation owner supplies exact anchor ranges to downstream detection.
ANCHORS = {
    'credential_prompt': ('hidden answer', 'display dialog'),
    'keychain_access': ('find-generic-password', 'find-internet-password', 'dump-keychain'),
    'browser_collection': ('Login Data', 'logins.json', 'cookies.sqlite', '/Cookies', 'key4.db'),
    'wallet_collection': ('exodus.wallet', '.electrum/wallets', 'Coinomi/wallets', 'walletwasabi', 'Local Extension Settings'),
    'outbound_upload': ('POST /', 'curl -F', 'curl --form', '--data-binary', 'CURLOPT_POSTFIELDS',
                        'multipart/form-data', 'Content-Disposition: form-data', '/sendlog', 'application/zip'),
    'persistence': ('/LaunchAgents/', '/LaunchDaemons/', 'RunAtLoad', 'launchctl load', 'launchctl bootstrap'),
    'system_discovery': ('system_profiler', 'SPHardwareDataType'),
}


def find_behaviors(strings: list[dict], slice_ids: list[int]) -> list[dict]:
    findings = []
    for slice_id in slice_ids:
        records = [r for r in strings if r['slice'] == slice_id]

        def select(*needles):
            return [r for r in records if any(n.lower() in r['text'].lower() for n in needles)]

        def add(code, title, interpretation, weight, selected):
            if selected:
                spans = []
                for record in {r['id']: r for r in selected}.values():
                    for rank, anchor in enumerate(ANCHORS[code]):
                        start = record['text'].lower().find(anchor.lower())
                        if start >= 0:
                            spans.append({"evidence_id": record['id'], "character_offset": start, "character_length": len(anchor), "priority": rank})
                findings.append({"id": f"s{slice_id}:{code}", "category": code, "slice": slice_id,
                    "title": title, "interpretation": interpretation, "kind": "static_inference",
                    "weight": weight, "evidence_ids": sorted({r['id'] for r in selected}),
                    "indicator_spans": spans,
                    "confidence": "medium", "function_addresses": []})

        dialog = [r for r in select('display dialog') if 'hidden answer' in r['text'].lower()]
        add('credential_prompt', 'Diálogo solicita senha oculta',
            'AppleScript embutido solicita entrada oculta; em conjunto com coleta de credenciais, é compatível com phishing de senha.', 20, dialog)
        keychain = select('find-generic-password', 'find-internet-password', 'dump-keychain')
        add('keychain_access', 'Consulta de credenciais no Keychain',
            'Comandos embutidos consultam segredos do Keychain; a autorização e a execução não foram observadas.', 20, keychain)
        browser = select('Login Data', 'logins.json')
        cookies = select('cookies.sqlite', '/Cookies', 'key4.db')
        add('browser_collection', 'Alvos de credenciais e sessão de navegadores',
            'A combinação de bancos de login e cookies indica possível coleta de credenciais/sessões.', 15, browser + cookies if browser and cookies else [])
        wallets = select('exodus.wallet', '.electrum/wallets', 'Coinomi/wallets', 'walletwasabi', 'Local Extension Settings')
        add('wallet_collection', 'Múltiplos diretórios de carteiras',
            'Referências a múltiplas carteiras são compatíveis com coleta de arquivos de carteiras.', 15,
            wallets if len({r['text'] for r in wallets}) >= 2 else [])
        outbound = select('POST /', 'curl -F', 'curl --form', '--data-binary', 'CURLOPT_POSTFIELDS')
        payload = select('multipart/form-data', 'Content-Disposition: form-data', '/sendlog', 'application/zip')
        add('outbound_upload', 'Preparação de envio de dados',
            'Marcadores de envio HTTP e de corpo/payload sugerem upload; combinados à coleta, sugerem exfiltração.', 20,
            outbound + payload if outbound and payload else [])
        persistence = select('/LaunchAgents/', '/LaunchDaemons/')
        activation = select('RunAtLoad', 'launchctl load', 'launchctl bootstrap')
        add('persistence', 'Configuração de inicialização automática',
            'Strings indicam possível instalação de agente/daemon; também ocorre em software legítimo.', 10,
            persistence + activation if persistence and activation else [])
        add('system_discovery', 'Coleta de informações do sistema',
            'Comandos de inventário do sistema; sinal de contexto, insuficiente para classificar malware.', 5,
            select('system_profiler', 'SPHardwareDataType'))
    return findings


def attribute_functions(images, findings, strings) -> list[dict]:
    by_evidence: dict[str, list[dict]] = {}
    for finding in findings:
        for evidence_id in finding['evidence_ids']:
            by_evidence.setdefault(evidence_id, []).append(finding)
    result = []
    for image in images:
        for function in image.functions:
            relevant = [ref for ref in function.references if ref['evidence_id'] in by_evidence]
            if not relevant:
                continue
            linked = {f['id']: f for ref in relevant for f in by_evidence[ref['evidence_id']]}
            for finding in linked.values():
                if hex(function.address) not in finding['function_addresses']:
                    finding['function_addresses'].append(hex(function.address))
                finding['confidence'] = 'medium_with_direct_code_references'
            result.append({"slice": image.index, "architecture": image.architecture,
                "address": hex(function.address), "end_upper_bound": hex(function.end),
                "file_offset": function.offset, "names": function.names, "boundary_basis": function.basis,
                "classification": "suspected_behavior_related", "finding_ids": sorted(linked),
                "references": relevant, "direct_calls": function.calls,
                "limitation": "A reference associates code with an indicator; it does not prove execution or malicious intent by itself"})
    return result


def risk_score(findings, coverage_limited: bool) -> dict:
    # Score each slice independently; unrelated slices must not corroborate each other.
    per_slice = {}
    for finding in findings:
        contribution = per_slice.setdefault(finding.get('slice', 0), {})
        contribution[finding['category']] = max(contribution.get(finding['category'], 0), finding['weight'])
    contributions = max(per_slice.values(), key=lambda c: sum(c.values()), default={})
    points = min(100, sum(contributions.values()))
    strong = {'credential_prompt', 'keychain_access', 'browser_collection', 'wallet_collection', 'outbound_upload'}
    corroborated = {sid: {f['category'] for f in findings if f.get('slice', 0) == sid and f['function_addresses']} & strong for sid in per_slice}
    likely = any(sum(values.values()) >= 70 and len(corroborated[sid]) >= 3 for sid, values in per_slice.items())
    verdict = 'likely_malicious' if likely else 'suspicious' if points >= 30 else 'inconclusive'
    return {"value": points, "maximum": 100, "verdict": verdict,
            "method": "facemessenger-static-heuristic-v1", "calibrated_probability": False,
            "contributions": contributions, "per_slice": per_slice, "coverage_limited": coverage_limited,
            "explanation": "Maior score entre slices; categorias contadas uma vez por slice. >=70 com referências de código em >=3 categorias fortes na mesma slice: likely_malicious; >=30: suspicious; restante: inconclusive. Nenhum resultado certifica arquivo benigno."}


def scripts_and_iocs(strings: list[dict]) -> tuple[list[dict], list[dict]]:
    scripts, iocs = [], []
    url = re.compile(r'https?://[^\s\x00<>"\x27]+')
    ipv4 = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
    for record in strings:
        text = record['text']
        if 'osascript' in text.lower() or 'do shell script' in text.lower() or 'display dialog' in text.lower():
            scripts.append({"evidence_id": record['id'], "slice": record['slice'], "offset": record['offset'],
                            "address": record['address'], "language": "applescript_or_launcher",
                            "content": text, "completeness": "embedded_fragment_not_reconstructed_program"})
        for kind, pattern in (('url', url), ('ipv4', ipv4)):
            for match in pattern.finditer(text):
                if kind == 'ipv4' and any(int(part) > 255 for part in match.group().split('.')):
                    continue
                iocs.append({"kind": kind, "value": match.group(), "evidence_id": record['id'],
                             "offset": record['offset'] + match.start() * (2 if record['encoding'] == 'utf-16le' else 1),
                             "classification": "unverified_candidate", "contacted": False})
    return scripts, iocs
