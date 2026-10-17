"""Render plain Markdown evidence; extracted content is never interpreted as code."""

import json
import html
from .evidence import decoder


def _inline(text: str) -> str:
    # Keep target-controlled strings from injecting Markdown links/tables.
    return html.escape(text).replace('`', '\\`').replace('|', '\\|').replace('[', '\\[').replace(']', '\\]').replace('\n', ' ').replace('\r', ' ')


def markdown(report: dict) -> str:
    artifact, risk = report['artifact'], report['risk']
    lines = ['# facemessenger — relatório estático', '',
             f"**Veredito:** `{risk['verdict']}` · **Score:** {risk['value']}/100 (heurístico, não probabilístico).", '',
             f"SHA-256: `{artifact['sha256']}`  ", f"Tamanho: {artifact['size_bytes']} bytes  ",
             f"Arquiteturas: {', '.join(s['architecture'] for s in report['slices'])}  ",
             'Cobertura: parcial. A amostra não foi executada e nenhum endereço de rede foi contatado.', '',
             '## Comportamento inferido', '']
    for summary in report['behavior_summary']:
        finding = next(f for f in report['findings'] if f['id'] == summary['finding_ids'][0])
        lines.append(f"- **{summary['title']}:** {finding['interpretation']} Evidências: {', '.join(summary['finding_ids'])}.")
    if not report['behavior_summary']:
        lines.append('Nenhuma combinação coberta pelas heurísticas foi encontrada. Isso não estabelece benignidade.')
    lines += ['', '## Funções relacionadas aos indicadores', '',
              'Endereços virtuais sem ASLR; a arquitetura identifica a slice. As referências associam código aos indicadores, sem provar execução.', '',
              '| Arquitetura | Endereço | Símbolos | Achados |', '|---|---|---|---|']
    for function in report['functions']:
        names = '<br>'.join(_inline(name) for name in function['names']) or '(sem símbolo)'
        lines.append(f"| {function['architecture']} | `{function['address']}` | {names} | {', '.join(function['finding_ids'])} |")
    lines += ['', '## AppleScript / lançadores embutidos', '']
    for script in report['scripts']:
        lines += [f"Evidência `{script['evidence_id']}` · VA `{script['address']}` · offset `{script['offset']}` · fragmento, não programa reconstruído:", '',
                  '```text', script['content'].replace('```', '` ` `'), '```', '']
    lines += ['## Candidatos a indicadores de rede', '', 'Valores extraídos; não há confirmação de C2 ativo.']
    for ioc in report['ioc_candidates']:
        # JSON quoting preserves source values in text while avoiding clickable links.
        lines.append(f"- `{_inline(json.dumps(ioc['value'], ensure_ascii=False))}` ({ioc['evidence_id']})")
    validation = report['yara']['validation']
    lines += ['', '## YARA', '', f"Estado: `{report['yara']['status']}`."]
    if validation:
        lines += [f"Compilação: {validation['compiled']}. Match na amostra: {validation['sample_matched']}. "
                  f"Matches em negativos: {validation['negative_matches']}/{validation['negative_count']}."]
        related = validation.get('related_samples', [])
        lines += [f"Modo efetivo: `{report['yara'].get('effective_mode', 'strings')}`. "
                  f"Amostras relacionadas: {sum(item['matched'] for item in related)}/{len(related)} correspondências."]
        opcode_analysis = report['yara'].get('opcode_analysis') or {}
        if opcode_analysis.get('patterns'):
            lines += ['', 'Padrões de instruções derivados de referências às evidências:', '',
                      '| Slice | Função | Offset | Padrão hexadecimal |', '|---|---|---|---|']
            for pattern in opcode_analysis['patterns']:
                lines.append(f"| {pattern['slice']} | `{pattern['function_address']}` | `{pattern['file_offset']}` | `{pattern['hex_pattern']}` |")
            lines += ['', 'Curingas modelam operandos variáveis decodificados; não comprovam cobertura de variantes reais.']
    lines += ['A regra detecta combinações de bytes. Não há garantia de zero falsos positivos, nem validação de cobertura da família.', '',
              '## Limites e métricas', '']
    lines += [f'- {item}' for item in report['limitations']]
    lines += ['', '```json', json.dumps(report['metrics'], ensure_ascii=False, indent=2), '```', '',
              'O JSON contém strings completas, offsets, referências de instruções, contribuições do score e cobertura por slice.', '']
    return '\n'.join(lines)


def function_assembly(data: bytes, report: dict, max_bytes: int = 2 * 1024 * 1024) -> tuple[str, bool]:
    chunks, total = [], 0
    for function in report['functions']:
        engine = decoder(function['architecture'])
        if engine is None:
            continue
        header = f"\n; slice {function['slice']} {function['architecture']} {function['address']} {' '.join(function['names'])}\n"
        chunks.append(header)
        total += len(header.encode('utf-8'))
        start, end = int(function['address'], 16), int(function['end_upper_bound'], 16)
        body = data[function['file_offset']:function['file_offset'] + end - start]
        for insn in engine.disasm(body, start):
            line = f"{insn.address:#x}  {bytes(insn.bytes).hex():24} {insn.mnemonic} {insn.op_str}\n"
            total += len(line.encode('utf-8'))
            if total > max_bytes:
                return ''.join(chunks), True
            chunks.append(line)
    return ''.join(chunks), False
