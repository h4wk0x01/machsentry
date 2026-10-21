"""Versioned analyst-facing projection of retained analysis; no binary interpretation."""

from pathlib import PurePosixPath, PureWindowsPath

from .detection import rule_export_name

SECTIONS = (
    ('summary', 'Resumo da análise'), ('identity', 'Identificação do arquivo'),
    ('behaviors', 'Comportamentos e evidências'), ('functions', 'Funções relacionadas'),
    ('scripts', 'Scripts embutidos'), ('network', 'Indicadores de rede'),
    ('yara', 'Detecção YARA'), ('coverage', 'Cobertura e limitações'),
)

MASK_MEANINGS = {
    'rip_relative_displacement': 'Deslocamento relativo ao RIP: pode mudar quando o código ou os dados mudam de posição.',
    'relative_control_flow': 'Destino relativo de salto ou chamada: pode variar com a disposição do código.',
    'evidence_linked_pointer': 'Operando de endereço associado à evidência: o endereço pode variar entre disposições do binário.',
    'pc_relative_address': 'Imediato de ADR/ADRP que forma um endereço relativo ao PC; os bits de opcode preservados continuam fixos.',
    'evidence_linked_address_add': 'Imediato de ADD associado à formação do endereço referenciado; os bits conhecidos da instrução são preservados.',
}


def filename(path):
    # Display a name in either producer OS without rewriting the retained source path.
    return PureWindowsPath(path).name if '\\' in path else PurePosixPath(path).name


def _detection(report, evidence, findings, architectures):
    yara = report['yara']
    selection = yara['selection']
    criteria = []
    for selected in selection['strings']:
        record, finding = evidence[selected['evidence_id']], findings[selected['finding_id']]
        offset = record['offset']
        if offset is not None:
            offset += selected['character_offset'] * (2 if selected['encoding'] == 'utf-16le' else 1)
        criteria.append({
            'symbol': selected['symbol'], 'kind': 'string', 'value': selected['literal'],
            'encoding': selected['encoding'], 'architecture': architectures.get(record['slice']),
            'slice': record['slice'], 'function_address': None, 'file_offset': offset,
            'meaning': finding['interpretation'], 'behaviors': [finding['title']],
            'selection_reason': 'Texto presente nos bytes do arquivo e associado a uma função por referência estática. A combinação com os demais critérios aumenta a especificidade.',
            'evidence_ids': [record['id']], 'fixed_bytes': None, 'length': None, 'wildcards': [],
        })
    patterns = {pattern['id']: pattern for pattern in (yara.get('opcode_analysis') or {}).get('patterns', [])}
    for selected in selection['opcodes']:
        pattern = patterns[selected['pattern_id']]
        references = {reference['evidence_id'] for reference in pattern['references']}
        linked = [findings[identifier] for identifier in pattern['finding_ids'] if identifier in findings
                  and references.intersection(findings[identifier]['evidence_ids'])]
        titles = list(dict.fromkeys(finding['title'] for finding in linked))
        criteria.append({
            'symbol': selected['symbol'], 'kind': 'opcodes', 'value': pattern['hex_pattern'],
            'encoding': None, 'architecture': pattern['architecture'], 'slice': pattern['slice'],
            'function_address': pattern['function_address'], 'file_offset': pattern['file_offset'],
            'meaning': 'Sequência de instruções que inclui uma referência aos indicadores: ' + '; '.join(titles) + '.' if titles
                       else 'Sequência de instruções ao redor de uma referência estática; não há categoria comportamental atribuída nesta seleção.',
            'behaviors': titles,
            'selection_reason': 'Janela de código com bytes conferidos na amostra e contexto fixo suficiente. A regra exige padrões de pelo menos duas funções distintas de uma mesma arquitetura de origem; uma função isolada não basta.',
            'evidence_ids': sorted(references), 'fixed_bytes': pattern['fixed_bytes'], 'length': pattern['length'],
            'wildcards': [{'kind': field['kind'], 'address': field['instruction_address'],
                           'meaning': MASK_MEANINGS.get(field['kind'], 'Campo variável identificado na instrução; sem explicação adicional disponível.'),
                           'mask': field['masked_bits_hex']} for field in pattern['masked_fields']],
        })
    validation = yara.get('validation')
    def corpus(rows):
        return [{'name': filename(row['name']), 'sha256': row['sha256'], 'matched': row['matched']} for row in rows]
    negative = corpus(validation.get('negatives', [])) if validation else []
    related = corpus(validation.get('related_samples', [])) if validation else []
    available = rule_export_name(yara, report['analysis_status']) == 'detection.yar'
    reasons = {
        'not_generated': 'Os indicadores ou padrões disponíveis não atendem aos critérios para gerar uma regra neste modo.',
        'rejected': 'A candidata não detectou a própria amostra ou correspondeu a um arquivo declarado benigno. Não está liberada para uso.',
        'related_samples_missed': 'A candidata deixou de detectar uma ou mais amostras relacionadas fornecidas. Não está liberada para uso.',
        'positive_only': 'A regra detectou a amostra. Nenhum arquivo benigno foi fornecido para comparação.',
        'validated_candidate': 'A regra detectou a amostra e não correspondeu aos arquivos declarados benignos fornecidos.',
    }
    return {'status': yara['status'], 'mode': yara.get('effective_mode', yara['requested_mode']),
            'reason': 'A análise não foi concluída. A candidata parcial não está liberada para uso.' if report['analysis_status'] == 'failed'
                      else reasons.get(yara['status'], 'Estado da candidata indisponível.'),
            'rule': yara['rule'], 'download': 'detection.yar' if available else None,
            'criteria': criteria, 'condition': selection['condition'],
            'validation': {'compiled': validation['compiled'] if validation else None,
                           'sample_matched': validation['sample_matched'] if validation else None,
                           'negatives': negative, 'related': related},
            'limitations': ['YARA compara bytes; a correspondência não comprova execução ou intenção maliciosa.',
                            'A validação cobre somente os arquivos listados. Não garante zero falsos positivos nem cobertura da família.',
                            'Os curingas toleram operandos variáveis identificados; a estabilidade entre versões precisa de amostras relacionadas.',
                            'Em arquivos universais, os matches não são obrigados a ficar na mesma slice do arquivo examinado.']}


def analyst_view(report):
    if report['schema_version'] != '2.1':
        raise ValueError('Analyst report requires analysis schema 2.1 with explicit YARA selection provenance')
    artifact, risk = report['artifact'], report['risk']
    evidence = {record['id']: record for record in report['evidence']}
    findings = {finding['id']: finding for finding in report['findings']}
    architectures = {item['index']: item['architecture'] for item in report['slices']}
    behaviors = []
    for finding in report['findings']:
        behaviors.append({'id': finding['id'], 'title': finding['title'], 'interpretation': finding['interpretation'],
                          'architecture': architectures.get(finding['slice']), 'slice': finding['slice'],
                          'confidence': {'medium_with_provider_code_references': 'medium', 'medium': 'medium',
                                         'high': 'high', 'low': 'low'}.get(finding['confidence'], 'unknown'),
                          'functions': finding['function_addresses'],
                          'evidence': [{'id': identifier, 'text': evidence[identifier]['text'],
                                        'address': evidence[identifier]['address'], 'file_offset': evidence[identifier]['offset']}
                                       for identifier in finding['evidence_ids']]})
    functions = [{'architecture': function['architecture'], 'slice': function['slice'], 'address': function['address'],
                  'names': function['names'], 'behaviors': [findings[key]['title'] for key in function['finding_ids']]}
                 for function in report['functions']]
    scripts = [{'content': script['content'], 'architecture': architectures.get(script['slice']),
                'address': script['address'], 'file_offset': script['offset'],
                'behaviors': [finding['title'] for finding in report['findings'] if script['evidence_id'] in finding['evidence_ids']]}
               for script in report['scripts']]
    network = [{'kind': item['kind'], 'value': item['value'], 'file_offset': item['offset'],
                'architecture': architectures.get(evidence[item['evidence_id']]['slice'])}
               for item in report['ioc_candidates']]
    titles = {finding['category']: finding['title'] for finding in report['findings']}
    available = risk['assessment_available']
    summary = ('A análise não pôde avaliar o arquivo. O risco permanece desconhecido.' if not available else
               'Foram encontrados indicadores compatíveis com os comportamentos abaixo. A intenção maliciosa não está confirmada.'
               if any(finding['weight'] > 0 for finding in report['findings']) else
               'Foram identificadas capacidades que orientam a revisão do código. A classificação depende do uso dessas funções.'
               if behaviors else 'As regras atuais ficaram sem achados. Consulte o código selecionado e a cobertura da análise.')
    coverage_rows = {item['slice']: item for item in report['coverage']['slices']}
    slices = []
    for item in report['slices']:
        coverage = coverage_rows.get(item['index'], {})
        slices.append({'slice': item['index'], 'architecture': item['architecture'], 'status': item['status'],
                       'functions_inspected': coverage.get('functions_inspected'), 'functions_omitted': coverage.get('functions_omitted'),
                       'strings_complete': coverage.get('strings_complete_over_provider_inventory'),
                       'reference_limit_reached': coverage.get('reference_budget_exhausted')})
    return {
        'schema_version': '1.0', 'section_order': [key for key, _ in SECTIONS], 'created_at': report['created_at'],
        'sample': {'name': filename(artifact['archive_member'] or artifact['path']),
                   'archive_member': artifact['archive_member'], 'sha256': artifact['sha256'],
                   'container_sha256': artifact['carrier_sha256'] if artifact['archive_member'] else None,
                   'size_bytes': artifact['size_bytes'], 'format': 'Mach-O' if any(
                       item.get('header_observation', {}).get('format') == 'mach-o' for item in report['slices']) else None,
                   'architectures': list(dict.fromkeys(architectures.values()))},
        'assessment': {'score': risk['value'], 'maximum': risk['maximum'], 'verdict': risk['verdict'],
                       'maliciousness': risk['maliciousness'], 'status': report['analysis_status'], 'summary': summary,
                       'factors': [{'title': titles.get(category, category), 'points': points}
                                   for category, points in risk['contributions'].items()] if available else []},
        'behaviors': behaviors, 'functions': functions, 'scripts': scripts, 'network': network,
        'detection': _detection(report, evidence, findings, architectures),
        'coverage': {'analyzed_slices': report['coverage']['analyzed_slice_count'], 'slices': slices,
                     'publication_failed': report['analysis_status'] == 'failed',
                     'limitations': ['Análise estática: o arquivo e os scripts não foram executados; os endereços de rede não foram contatados.',
                                     'Foram examinadas funções selecionadas por referências a indicadores; código não selecionado, dados construídos ou conteúdo empacotado podem permanecer desconhecidos.',
                                     'Associações entre código e strings sustentam hipóteses, sem provar intenção maliciosa ou execução.',
                                     'Endereços de função são virtuais, sem ASLR, e dependem da arquitetura. Offsets apontam para os bytes do arquivo ou do membro ZIP selecionado.',
                                     'O score prioriza investigação; não é probabilidade de malware. Usa o maior score por arquitetura e não soma arquiteturas.']},
    }
