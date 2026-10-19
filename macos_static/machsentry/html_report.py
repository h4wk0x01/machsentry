"""Fixed, offline HTML template. All sample-controlled values are rendered as text."""

import base64
from hashlib import sha256
from html import escape

from .analyst_view import SECTIONS
from .report_schema import validate_view
from .report_style import CSS, UNPACKED_CSS


def text(value):
    return escape('Não disponível' if value is None else str(value), quote=True)


def code(value):
    return '<code>' + text(value) + '</code>'


def listing(items):
    return '<ul>' + ''.join('<li>' + text(item) + '</li>' for item in items) + '</ul>'


def table(headings, rows):
    return ('<div class="table-wrap"><table><thead><tr>' + ''.join('<th scope="col">' + text(item) + '</th>' for item in headings)
            + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td>' + item + '</td>' for item in row) + '</tr>' for row in rows)
            + '</tbody></table></div>')


def empty(message):
    return '<p class="empty">' + text(message) + '</p>'


def location(architecture, address=None, offset=None):
    return '<p class="meta">' + text(architecture or 'Arquitetura não avaliada') + (
        ' · VA ' + code(address) if address is not None else '') + (
        ' · offset ' + code(hex(offset)) if offset is not None else ' · offset indisponível') + '</p>'


def summary(view):
    assessment = view['assessment']
    label = {'high_risk_indicators': 'Indicadores de alto risco', 'suspicious': 'Indicadores suspeitos',
             'inconclusive': 'Resultado inconclusivo'}[assessment['verdict']]
    if assessment['status'] == 'failed':
        label = 'Análise não concluída'
    score = assessment['score']
    score_markup = ('<strong>' + str(score) + '</strong><small> / 100</small><meter min="0" max="100" value="'
                    + str(score) + '" aria-label="Score heurístico"></meter>') if score is not None else '<strong>—</strong>'
    factors = ''.join('<span class="factor">' + text(item['title']) + ' +' + text(item['points']) + '</span>'
                      for item in assessment['factors'])
    return ('<div class="summary-grid"><div class="score">' + score_markup + '<p>Score heurístico<br>Não é probabilidade</p></div>'
            + '<div><h3>' + text(label) + '</h3><p>' + text(assessment['summary']) + '</p>'
            + '<span class="pill warn">' + ('Maliciosidade não avaliada' if score is None else 'Maliciosidade não confirmada')
            + '</span><div class="factors">' + factors + '</div></div></div>')


def identity(view):
    sample = view['sample']
    rows = [('Arquivo', text(sample['name'])), ('Formato', text(sample['format'])),
            ('Arquiteturas', text(', '.join(sample['architectures']) or 'Não avaliadas')),
            ('Tamanho', text(f"{sample['size_bytes']:,}".replace(',', '.') + ' bytes')),
            ('SHA-256', code(sample['sha256'])), ('Membro do ZIP', text(sample['archive_member'] or 'Não se aplica')),
            ('SHA-256 do ZIP', code(sample['container_sha256']) if sample['container_sha256'] else 'Não se aplica'),
            ('Data da análise', text(view['created_at']))]
    return '<dl>' + ''.join('<dt>' + text(key) + '</dt><dd>' + value + '</dd>' for key, value in rows) + '</dl>'


def behaviors(view):
    if not view['behaviors']:
        return empty('Comportamentos não avaliados: análise indisponível.' if view['assessment']['score'] is None else
                     'Nenhum indicador coberto identificado. Ausência de achados não confirma benignidade.')
    cards = []
    for finding in view['behaviors']:
        evidence = ''.join('<div class="evidence">' + location(finding['architecture'], item['address'], item['file_offset'])
                           + '<pre>' + text(item['text']) + '</pre></div>' for item in finding['evidence'])
        confidence = {'medium': 'moderada', 'low': 'baixa', 'high': 'alta', 'unknown': 'não avaliada'}[finding['confidence']]
        cards.append('<article class="card"><div class="card-head"><h3>' + text(finding['title'])
                     + '</h3><span class="meta">' + text(finding['architecture']) + ' · inferência estática</span></div>'
                     + '<p>' + text(finding['interpretation']) + '</p><p class="meta">Confiança: ' + text(confidence)
                     + '. Funções associadas: ' + (', '.join(code(address) for address in finding['functions']) or 'nenhuma atribuída')
                     + '.</p><details><summary>Examinar evidências (' + str(len(finding['evidence'])) + ')</summary>'
                     + evidence + '</details></article>')
    return ''.join(cards)


def functions(view):
    intro = '<p class="muted">Funções associadas aos indicadores. A relação não confirma que a função seja maliciosa. Endereços virtuais sem ASLR.</p>'
    rows = [[text(item['architecture']) + '<br><span class="meta">slice ' + text(item['slice']) + '</span>',
             code(item['address']), code(', '.join(item['names']) or 'Sem símbolo'), text('; '.join(item['behaviors']))]
            for item in view['functions']]
    return intro + (table(['Arquitetura', 'Endereço', 'Símbolo', 'Comportamento associado'], rows) if rows else
                    empty('Nenhuma função atribuída aos indicadores nesta análise.'))


def scripts(view):
    intro = '<p class="muted">Fragmentos recuperados do arquivo; não foram executados e podem não representar um script completo.</p>'
    cards = ['<article class="card"><h3>Fragmento ' + str(index + 1) + '</h3>'
             + location(item['architecture'], item['address'], item['file_offset'])
             + '<p>' + text('; '.join(item['behaviors']) or 'Sem comportamento atribuído ao fragmento.')
             + '</p><pre>' + text(item['content']) + '</pre></article>' for index, item in enumerate(view['scripts'])]
    return intro + (''.join(cards) or empty('Scripts não avaliados: análise indisponível.' if view['assessment']['score'] is None
                                           else 'Nenhum fragmento de script foi recuperado nesta análise.'))


def network(view):
    intro = '<p class="muted">Candidatos extraídos do arquivo, sem confirmação de comunicação ou de C2 ativo. Valores apresentados como texto.</p>'
    rows = [[text(item['kind']), code(item['value']), text(item['architecture']),
             code(hex(item['file_offset'])) if item['file_offset'] is not None else 'Não disponível'] for item in view['network']]
    return intro + (table(['Tipo', 'Indicador', 'Arquitetura', 'Offset'], rows) if rows else
                    empty('Indicadores de rede não avaliados: análise indisponível.' if view['assessment']['score'] is None
                          else 'Nenhum candidato de rede foi recuperado nesta análise.'))


def _criteria(detection):
    if not detection['criteria']:
        return empty('Nenhum critério foi incluído em uma regra.')
    cards = []
    for item in detection['criteria']:
        heading = item['symbol'] + ' · ' + ('String' if item['kind'] == 'string' else 'Padrão de instruções')
        explanation = '<p>' + text(item['meaning']) + '</p><p class="small muted">Por que foi escolhido: ' + text(item['selection_reason']) + '</p>'
        masks = ('<details><summary>O que os curingas representam</summary>' + listing([
            field['address'] + ': ' + field['meaning'] for field in item['wildcards']])
            + '<p class="small muted">?? aceita qualquer byte; ? representa um nibble variável. O padrão preserva início e fim concretos. Isso não comprova estabilidade entre variantes.</p></details>') if item['wildcards'] else ''
        stats = ('<p class="meta">' + text(item['fixed_bytes']) + ' bytes inteiramente fixos em ' + text(item['length'])
                 + ' bytes de padrão.</p>') if item['kind'] == 'opcodes' else '<p class="meta">Codificação: ' + text(item['encoding']) + '.</p>'
        cards.append('<article class="card"><h3>' + text(heading) + '</h3>'
                     + location(item['architecture'], item['function_address'], item['file_offset'])
                     + explanation + '<pre>' + text(item['value']) + '</pre>' + stats + masks + '</article>')
    return ''.join(cards)


def _validation(detection):
    validation = detection['validation']
    if validation['compiled'] is None:
        return empty('Sem validação YARA: nenhuma candidata foi gerada.')
    negatives, related = validation['negatives'], validation['related']
    def stat(number, label):
        return '<div class="stat"><strong>' + text(number) + '</strong><span>' + text(label) + '</span></div>'
    stats = '<div class="stats">' + stat('Detectada' if validation['sample_matched'] else 'Não detectada', 'Amostra analisada')
    stats += stat(str(sum(row['matched'] for row in negatives)) + ' / ' + str(len(negatives)) if negatives else 'Não testado',
                  'Correspondências em arquivos declarados benignos')
    stats += stat(str(sum(row['matched'] for row in related)) + ' / ' + str(len(related)) if related else 'Não testado', 'Amostras relacionadas detectadas') + '</div>'
    rows = [[text(kind), text(row['name']), code(row['sha256']), 'Sim' if row['matched'] else 'Não']
            for kind, items in [('Declarado benigno', negatives), ('Relacionado', related)] for row in items]
    return stats + ('<details><summary>Ver corpus utilizado</summary>' + table(['Grupo', 'Arquivo', 'SHA-256', 'Match'], rows)
                    + '<p class="small muted">Rótulos fornecidos pelo operador; benignidade e família não autenticadas.</p></details>' if rows else '')


def detection(view):
    item = view['detection']
    ready = item['download'] is not None
    mode = {'hybrid': 'Strings + opcodes', 'strings': 'Strings', 'opcodes': 'Opcodes', 'auto': 'Seleção automática'}[item['mode']]
    result = '<span class="pill' + ('' if ready else ' warn') + '">' + ('Candidata disponível' if ready else 'Sem regra liberada')
    result += '</span><p class="meta">Modo: ' + text(mode) + '</p><p>' + text(item['reason']) + '</p>'
    if ready:
        result += '<a class="button" href="detection.yar" download="detection.yar">Baixar regra YARA</a>'
    elif item['rule'] is not None:
        result += '<p class="notice">A candidata abaixo não foi liberada. Revise a avaliação e a validação antes de qualquer uso.</p>'
    if item['rule'] is not None:
        result += '<pre class="rule" aria-label="Regra YARA">' + text(item['rule']) + '</pre>'
    condition = item['condition']
    if condition:
        conditions = ['O cabeçalho deve corresponder a um dos formatos Mach-O admitidos.']
        if condition['all_strings_required']:
            conditions.append('Todas as strings devem corresponder: ' + ', '.join(row['symbol'] for row in item['criteria'] if row['kind'] == 'string') + '.')
        if condition['opcode_groups_any']:
            conditions.append('Além disso, basta atender a um dos grupos de padrões abaixo; em cada grupo são exigidos pelo menos dois padrões.')
            conditions.extend('Grupo da slice ' + str(group['slice']) + ': ' + ', '.join(group['symbols'])
                              for group in condition['opcode_groups_any'])
        result += '<h3>Como a regra decide</h3>' + listing(conditions)
    result += '<h3>Validação</h3>' + _validation(item)
    result += '<h3>Por que estes critérios foram selecionados</h3>' + _criteria(item)
    return result + '<div class="notice">' + listing(item['limitations']) + '</div>'


def coverage(view):
    coverage = view['coverage']
    rows = [[text(item['architecture']), text({'analyzed': 'Analisada', 'failed': 'Falhou', 'not_selected': 'Não selecionada'}.get(item['status'], item['status'])),
             text(item['functions_inspected']), text(item['functions_omitted']),
             'Recebido integralmente' if item['strings_complete'] is True else 'Parcial' if item['strings_complete'] is False else 'Não avaliado',
             'Limite atingido' if item['reference_limit_reached'] is True else 'Não avaliado' if item['reference_limit_reached'] is None else 'Dentro do limite']
            for item in coverage['slices']]
    result = ('<p class="notice">A análise não foi concluída com sucesso. Os dados disponíveis são parciais e não constituem um resultado final de avaliação.</p>'
              if coverage['publication_failed'] else '<p class="muted">Cobertura parcial por seleção de funções. O relatório não representa engenharia reversa de todo o arquivo.</p>')
    return result + (table(['Arquitetura', 'Estado', 'Funções examinadas', 'Candidatas omitidas', 'Inventário de strings', 'Referências'], rows) if rows else
                     empty('Nenhuma arquitetura foi avaliada.')) + listing(coverage['limitations'])


# The Unpacked mark as in the unpackedlab.com header: the biohazard glyph in the brand purple,
# beside the UNPACKED wordmark. Inline SVG needs no network and passes the page CSP.
UNPACKED_LOGO = (
    '<svg viewBox="0 0 24 24" role="img" aria-label="Unpacked" xmlns="http://www.w3.org/2000/svg" fill="none" '
    'stroke="#BA71FF" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">'
    '<circle cx="12" cy="11.9" r="2"/><path d="M6.7 3.4c-.9 2.5 0 5.2 2.2 6.7C6.5 9 3.7 9.6 2 11.6"/>'
    '<path d="m8.9 10.1 1.4.8"/><path d="M17.3 3.4c.9 2.5 0 5.2-2.2 6.7 2.4-1.2 5.2-.6 6.9 1.5"/>'
    '<path d="m15.1 10.1-1.4.8"/><path d="M16.7 20.8c-2.6-.4-4.6-2.6-4.7-5.3-.2 2.6-2.1 4.8-4.7 5.2"/>'
    '<path d="M12 13.9v1.6"/><path d="M13.5 5.4c-1-.2-2-.2-3 0"/><path d="M17 16.4c.7-.7 1.2-1.6 1.5-2.5"/>'
    '<path d="M5.5 13.9c.3.9.8 1.8 1.5 2.5"/></svg>'
)

# Product names shown around the fixed sections. The engine and its evidence are
# the same; only the header, title, footer and styling change.
BRANDS = {
    'machsentry': {'name': 'MachSentry', 'mark': 'Mach<span>Sentry</span>', 'tag': 'Análise estática · macOS',
                   'footer': 'MachSentry · Modelo de relatório 1.0 · Análise estática', 'css': ''},
    'unpacked': {'name': 'Unpacked',
                 'mark': UNPACKED_LOGO + '<span>UNPACKED</span>',
                 'tag': '<b>Análise estática de Mach-O</b>macOS · unpackedlab.com',
                 'footer': '<strong>UNPACKED</strong> · unpackedlab.com · Análise estática feita com MachSentry '
                           '(REA e Ghidra) · Modelo de relatório 1.0',
                 'css': UNPACKED_CSS},
}


def html_report(view, brand='machsentry'):
    validate_view(view)
    if brand not in BRANDS:
        raise ValueError(f'unknown report brand: {brand}')
    look = BRANDS[brand]
    css = CSS + look['css']
    renderers = {'summary': summary, 'identity': identity, 'behaviors': behaviors, 'functions': functions,
                 'scripts': scripts, 'network': network, 'yara': detection, 'coverage': coverage}
    sections = ''.join('<section class="panel" id="' + key + '" data-section="' + key + '"><h2>' + title
                       + '</h2>' + renderers[key](view) + '</section>' for key, title in SECTIONS)
    navigation = ''.join('<a href="#' + key + '"><span>' + f'{index:02d}' + '</span>' + title + '</a>'
                         for index, (key, title) in enumerate(SECTIONS, 1))
    css_hash = base64.b64encode(sha256(css.encode('utf-8')).digest()).decode('ascii')
    policy = "default-src 'none'; style-src 'sha256-" + css_hash + "'; base-uri 'none'; form-action 'none'; object-src 'none'"
    return ('<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            + '<meta http-equiv="Content-Security-Policy" content="' + escape(policy, quote=True) + '">'
            + '<title>' + look['name'] + ' · ' + text(view['sample']['name']) + '</title><style>' + css + '</style></head><body>'
            + '<header class="top"><div class="brand">' + look['mark'] + '</div><div class="tag">' + look['tag'] + '</div></header>'
            + '<div class="layout"><nav aria-label="Seções do relatório"><p>Neste relatório</p>' + navigation + '</nav><main>'
            + '<div class="hero"><p class="eyebrow">Relatório de análise</p><h1>' + text(view['sample']['name']) + '</h1>'
            + '<p class="muted">Comportamentos, evidências e critérios de detecção em um único relatório.</p></div>' + sections
            + '<footer class="footer">' + look['footer'] + '</footer></main></div></body></html>\n')
