"""AI output schema and validation rules (contract section 8)."""

import copy
import unittest

import worker_support as support
from machsentry_worker.ai_schema import OUTPUT_SCHEMA, text_format, validate, writing_issues
from machsentry_worker.evidence import function_keys

EVIDENCE = {'s0:str:0', 's0:str:1'}
FINDINGS = {'s0:credential_prompt', 's1:keychain_access'}


class SchemaTests(unittest.TestCase):
    def setUp(self):
        self.keys = function_keys(support.report())
        self.output = support.valid_output()

    def errors(self, output):
        return validate(output, EVIDENCE, FINDINGS, self.keys)

    def test_strict_schema_shape(self):
        fmt = text_format()
        self.assertEqual((fmt['type'], fmt['strict']), ('json_schema', True))
        self.assertRegex(fmt['name'], r'^[A-Za-z0-9_-]{1,64}$')

        def walk(node):
            if node.get('type') == 'object':
                self.assertFalse(node['additionalProperties'])
                self.assertEqual(set(node['required']), set(node['properties']))
                for child in node['properties'].values():
                    walk(child)
            elif node.get('type') == 'array':
                self.assertIn('maxItems', node)
                walk(node['items'])
        walk(OUTPUT_SCHEMA)

    def test_valid_output(self):
        self.assertEqual(self.errors(self.output), [])

    def test_unknown_evidence_ids_are_rejected(self):
        output = copy.deepcopy(self.output)
        output['behaviors'][0]['evidence_ids'] = ['s0:str:99']
        output['techniques'][0]['evidence_ids'] = []
        errors = self.errors(output)
        self.assertIn('behaviors[0].evidence_ids[0]: unknown evidence id', errors)
        self.assertIn('techniques[0].evidence_ids: needs at least one evidence id', errors)

    def test_wrong_architecture_address_pairs_are_rejected(self):
        output = copy.deepcopy(self.output)
        output['behaviors'][0]['functions'] = [{'architecture': 'arm64', 'address': '0x100000999'}]
        output['functions'][0]['architecture'] = 'x86'
        output['functions'].append({**output['functions'][0], 'architecture': ['arm64']})
        errors = self.errors(output)
        self.assertIn('behaviors[0].functions[0]: unknown function (architecture, address)', errors)
        self.assertIn('functions[0]: unknown function (architecture, address)', errors)
        self.assertIn('functions[1]: unknown function (architecture, address)', errors)

    def test_lengths_counts_and_technique_ids(self):
        output = copy.deepcopy(self.output)
        output['summary'] = 'x' * 1501
        output['behaviors'][0]['title'] = 'y' * 801
        output['techniques'][0]['id'] = 'T15555'
        output['gaps'] = ['g'] * 13
        output['behaviors'][0]['confidence'] = 'certain'
        errors = self.errors(output)
        self.assertIn('summary: exceeds 1500 characters', errors)
        self.assertIn('behaviors[0].title: exceeds 800 characters', errors)
        self.assertIn('techniques[0].id: must match T0000 or T0000.000', errors)
        self.assertIn('gaps: has more than 12 items', errors)
        self.assertIn('behaviors[0].confidence: must be low, medium or high', errors)

    def test_lengths_match_the_site(self):
        # The site's validateAi counts JavaScript string length and caps names and titles at 200.
        output = copy.deepcopy(self.output)
        output['techniques'][0]['name'] = 'n' * 201
        output['functions'][0]['title'] = 't' * 201
        output['behaviors'][0]['title'] = 'b' * 800
        output['gaps'] = ['\U0001F50D' * 401]
        output['next_steps'] = ['\U0001F50D' * 400]
        self.assertEqual(self.errors(output), ['techniques[0].name: exceeds 200 characters',
                                               'functions[0].title: exceeds 200 characters',
                                               'gaps[0]: exceeds 800 characters'])

    def test_shape_errors(self):
        self.assertEqual(self.errors([]), ['$: must be an object'])
        extra = {**self.output, 'verdict': 'malicious'}
        self.assertEqual(len(self.errors(extra)), 1)
        output = copy.deepcopy(self.output)
        output['functions'][0].pop('title')
        self.assertTrue(any(error.startswith('functions[0]: must have exactly the keys') for error in self.errors(output)))




class WritingTests(unittest.TestCase):
    TERMS = frozenset({'positive_only', 'high_risk_indicators', 'partial', 'evidence_ids'})

    def test_clean_output_has_no_issues(self):
        self.assertEqual(writing_issues(support.valid_output(), 'pt-BR', self.TERMS), [])

    def test_pt_br_glossary_grammar_dashes_negations_and_raw_terms(self):
        output = copy.deepcopy(support.valid_output())
        output['summary'] = 'A amostra tem indicadores high_risk_indicators — e a regra está positive_only.'
        output['gaps'] = ['As pseudocódigos estão curtos.', 'Não há IOC candidates.']
        output['next_steps'] = ['A string por si só não prova a coleta.']
        output['behaviors'][0]['explanation'] = 'A análise é partial.'
        issues = writing_issues(output, 'pt-BR', self.TERMS)
        joined = '\n'.join(issues)
        for expected in ('summary: em dash', 'summary: write "o sample"', 'summary: "high_risk_indicators"',
                         'summary: "positive_only"', 'gaps[0]: pseudocódigo is masculine',
                         'gaps[1]: write "candidatos a IOC"', 'next_steps[0]: drop the phrase "não prova"',
                         'next_steps[0]: drop the phrase "por si só"', 'behaviors[0].explanation: "partial"'):
            self.assertIn(expected, joined)

    def test_english_keeps_plain_engine_words_and_official_technique_names(self):
        output = copy.deepcopy(support.valid_output())
        output['summary'] = 'The static report is partial by design; the rule is positive_only.'
        output['techniques'][0]['name'] = 'Credentials from Password Stores — Keychain'
        issues = writing_issues(output, 'en-US', self.TERMS)
        self.assertEqual(issues, ['summary: "positive_only" is an input key or engine value; say what it means'])

    def test_quotes_prepositions_and_adjectives_are_left_alone(self):
        output = copy.deepcopy(support.valid_output())
        output['summary'] = 'O sample mostra a string "Senha — partial amostra" e a malícia não comprovada.'
        output['gaps'] = ['Comparado a pseudocódigos de outros samples, falta o trecho de rede.']
        self.assertEqual(writing_issues(output, 'pt-BR', self.TERMS), [])
        output['gaps'] = ['Pseudocódigo curto. A pseudocódigo termina cedo.']
        self.assertEqual(writing_issues(output, 'pt-BR', self.TERMS),
                         ['gaps[0]: pseudocódigo is masculine: "o pseudocódigo", "os pseudocódigos"'])

    def test_sustentar_slice_and_repeated_templates(self):
        output = copy.deepcopy(support.valid_output())
        output['functions'][0]['explanation'] = 'Isso sustenta o indício de coleta no slice arm64.'
        output['gaps'] = ['Falta a rede. O artefato que fecha isso é o PCAP.',
                          'Falta o arquivo. O artefato que fecha isso é o trace.',
                          'Falta a UI. O artefato que fecha isso é a função de diálogo.']
        issues = '\n'.join(writing_issues(output, 'pt-BR'))
        self.assertIn('functions[0].explanation: avoid "sustentar"', issues)
        self.assertIn('functions[0].explanation: write "arquitetura"', issues)
        self.assertIn('gaps: "o artefato que fecha" repeats in several items', issues)
        output['gaps'] = ['Falta o tráfego do envio para ver o destino.', 'Um trace de arquivos mostra a leitura do Login Data.']
        output['functions'][0]['explanation'] = 'Isso mostra o pedido de senha na arquitetura arm64.'
        self.assertEqual(writing_issues(output, 'pt-BR'), [])

    def test_issue_count_is_capped(self):
        output = copy.deepcopy(support.valid_output())
        output['gaps'] = ['amostra — não prova'] * 12
        self.assertEqual(len(writing_issues(output, 'pt-BR')), 16)

if __name__ == '__main__':
    unittest.main()
