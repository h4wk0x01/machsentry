# facemessenger

Núcleo portátil para análise **estática e local** de malware Mach-O, desenvolvido
neste fork do REA para futura integração ao Unpacked. Funciona no Windows sem
macOS, Xcode, `otool`, Ghidra ou execução da amostra.

## Instalação e uso

Python 3.12 ou posterior. As três dependências de análise têm versões fixas em
`pyproject.toml`; use um ambiente virtual. Não é necessário instalar o REA npm.

```powershell
python -m venv .venv-unpack
.\.venv-unpack\Scripts\python.exe -m pip install -e ./macos_static
.\.venv-unpack\Scripts\python.exe -m facemessenger analyze C:\entrada\arquivo.macho --output reports/macos/analise-001
```

Para a referência histórica, sem escrever o executável no disco:

```powershell
.\.venv-unpack\Scripts\python.exe macos_static/fetch_reference_sample.py
.\.venv-unpack\Scripts\python.exe -m facemessenger analyze amostras/AtomicStealer-2023.zip --member "AtomicStealer/Trading View" --zip-password infect3d --output reports/macos/atomic-001
```

Acrescente `--benign-file CAMINHO` para cada arquivo do corpus negativo e `--json`
para retornar o relatório completo em stdout. O diretório de saída deve ser novo;
execuções nunca sobrescrevem resultados anteriores. No Linux, use
`.venv-unpack/bin/python`. Download é uma etapa explícita e separada; a análise
não usa rede, modelo de linguagem, subprocesso nem execução da amostra.

Para testar assinaturas de instruções em amostras relacionadas selecionadas:

```powershell
.\.venv-unpack\Scripts\python.exe -m facemessenger analyze amostra.macho --yara-mode opcodes --related-file variante.macho --benign-file controle.dylib --output reports/macos/opcodes-001
```

`--related-file` é repetível e recebe arquivos já descompactados explicitamente
selecionados pelo analista. O conjunto positivo/negativo é limitado a 128 arquivos
e 64 MiB totais. Os hashes e cada match/miss são preservados. O programa não presume
que arquivos relacionados pertencem à mesma família e não altera curingas para
forçar correspondência. Use `auto` (padrão), `hybrid`, `strings` ou `opcodes`.
Modos explícitos falham em produzir regra quando faltam evidências suficientes;
`auto` informa o modo efetivo e usa strings quando faltam padrões de código fortes.

## Entregas

- `report.json`: contrato versionado, identidade SHA-256, slices, fatos e
  inferências, cobertura, evidências, funções, score, scripts, IOCs e validação YARA.
- `report.md`: leitura humana em português, incluindo tabela de funções por arquitetura.
- `functions.asm.txt`: desassemblagem das funções associadas aos indicadores,
  limitada a 2 MiB; truncamento é registrado no JSON.
- `script-NNN.txt`: fragmentos literais de AppleScript/lançadores, nunca executados.
- `detection.yar`: candidata específica da amostra, quando há indicadores suficientes.
  Se um negativo corresponder ou um positivo relacionado não corresponder, a
  candidata incompleta fica em `candidate-rejected.yar.txt`.

O JSON é publicado por renomeação no mesmo diretório depois das exportações.
Uma falha pode deixar arquivos parciais para diagnóstico; a presença isolada de
um diretório não confirma sucesso. O consumidor deve exigir saída zero,
`ok: true` e um `report.json` completo. Não há retry ou cobrança automática na CLI.

## Contrato e confiança

O envelope de stdout é `{"ok":true,"value":...,"outputs":...}` ou
`{"ok":false,"error":{"code":"...","message":"..."}}`. Códigos de saída:
0 sucesso da análise (que pode ser parcial), 2 falha esperada, 3 falha da engine,
130 interrupção. O argumento inválido é rejeitado pelo argparse com saída 2.
`schema_version` é `1.0`; as versões da engine, regras, LIEF, Capstone e YARA
identificam o perfil do resultado. A senha do ZIP não é persistida nos relatórios.

Offsets são físicos no arquivo ou no membro descomprimido selecionado, conforme
`artifact.offset_space`. VAs são endereços virtuais sem ASLR e só têm identidade
com a slice. Instruções, bytes, endereços-alvo e IDs de evidência sustentam cada
associação. Símbolos são rótulos observados, não prova de intenção. Resultados
não reinterpretam endereços de strings como endereços de funções.

LIEF é o dono da interpretação do formato; antes dele há validação de admissão
de headers, FAT, comandos e limites físicos. Os consumidores usam as seções e
funções normalizadas. Capstone resolve referências diretas RIP-relative em
x86_64 e ADR/ADRP+ADD em arm64, invalidando bases em mudanças de registrador e
fronteiras de blocos. Não há execução simbólica, descompilação, recuperação de
dispatch Objective-C, decodificação de ofuscação ou resolução geral de ponteiros.

O score é uma heurística explicável: diálogo de senha 20, consulta de Keychain
20, dados de navegador 15, carteiras 15, upload 20, persistência 10 e inventário
5, limitado a 100. Usa-se o maior resultado entre slices, sem somar arquiteturas.
`likely_malicious` requer ao menos 70 pontos e referências de código em três
categorias fortes na mesma slice. `suspicious` começa em 30; o restante é
`inconclusive`. Nenhum resultado certifica benignidade e 95/100 não significa
95% de probabilidade. As regras ainda não foram calibradas num corpus amplo.

YARA exige magic Mach-O. O modo strings combina pelo menos três indicadores
distintos ligados a código na mesma slice analisada. O modo híbrido exige esses
indicadores e dois padrões de instruções de funções distintas de uma mesma slice
de origem. O modo opcodes exige apenas os dois padrões de código e o magic, sendo
uma candidata que exige validação mais ampla de especificidade. Cada grupo é
deduplicado: padrões idênticos não podem satisfazer o limiar duas vezes.

São selecionadas até três janelas por slice, priorizando funções ligadas a senha,
Keychain, envio de dados, carteiras e navegadores. As janelas contêm referências
às evidências e têm 24–128 bytes, ao menos 16 bytes fixos e quatro bytes concretos
consecutivos; no máximo 40% dos bytes podem conter curinga. Início e fim são
bytes concretos. Em x86_64, Capstone identifica deslocamentos RIP-relative,
operandos de branches/calls relativos e ponteiros comprovados. Em arm64, só são
mascarados nibbles inteiramente pertencentes ao imediato; bits compartilhados
com registradores/opcodes ficam fixos. Isso preserva semântica e pode perder
variantes, explicitamente indicado como tolerância parcial.

O JSON preserva a janela original, máscara, função, endereço, offsets e motivo
de cada máscara. A documentação do [YARA](https://yara.readthedocs.io/en/stable/writingrules.html#hexadecimal-strings)
define `??`, `A?` e `?F`. O YARA 4.5.4 aceita curingas nas extremidades, verificado
localmente; mantê-las concretas é um requisito deste gerador, não uma limitação
geral da sintaxe. Não se inferiu estabilidade de família a partir de uma amostra.

A regra usa os bytes e contextos observados, sem comentários supérfluos. Não observa comportamento em execução,
não garante ausência de falsos positivos e não estabelece cobertura de variantes.
`positive_only` significa teste apenas na amostra; `validated_candidate` exige
também negativos sem match; `production_ready` permanece falso.
`related_samples_missed` registra positivos relacionados
sem correspondência e impede exportar a candidata como `detection.yar`. Software de
pesquisa que embuta os mesmos bytes pode corresponder. O cabeçalho de arquivo
na regra não substitui um parser Mach-O e as ocorrências YARA não são correlacionadas
por slice durante o matching; essa é uma limitação da assinatura candidata.

Limites de admissão/retencão: 32 MiB de entrada e membro descomprimido, até 128
slices, 8.192 comandos por slice, 100 mil símbolos/funções por slice, nomes de
símbolo com até 4.096 bytes e 8 MiB de nomes expandidos antes do parser, 20 mil
strings e 2 MiB de texto no conjunto, 2 milhões de instruções e 50 mil referências
ou chamadas diretas por slice. São orçamentos de recursos, não limites do formato.
Excesso de entrada falha; interrupção de cobertura é registrada. Criptografia,
arquiteturas sem decoder e ausência de limites de funções mantêm incógnitas.
Nenhum cache de análises é usado nesta versão.

## Verificação

```powershell
.\.venv-unpack\Scripts\python.exe -m unittest discover -s macos_static/tests -v
```

Os testes usam bytes sintéticos, sem baixar ou executar malware. O teste real e
suas limitações estão em [validação](../docs/facemessenger-validation.md).
O contrato proposto de jobs, créditos e dashboard está em
[integração](../docs/facemessenger-integration.md). API HTTP, fila, créditos,
contenção de workers, autorização por conta e interface web não estão implantados.
O parser nativo processa bytes não confiáveis; antes de oferecer uploads pagos,
execute o worker em isolamento do servidor web, sem rede e com limites externos
de memória/tempo. Os limites Python não substituem essa contenção.

LIEF (Apache-2.0), Capstone (BSD) e yara-python/libyara (Apache-2.0) permanecem
dependências separadas com suas próprias licenças. O código e a atribuição MIT
do REA foram preservados. As amostras e resultados locais não fazem parte do pacote.
