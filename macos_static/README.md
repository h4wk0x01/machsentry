# MachSentry — relatórios sobre o REA/Ghidra

MachSentry usa o **REA pelo seu MCP oficial**, com o provedor Ghidra, para a
análise estática. O Python compõe os relatórios, score, scripts e regras YARA
sobre as evidências do REA. A interpretação Mach-O, a separação das slices,
as referências, os limites das funções e o pseudocódigo pertencem ao REA/Ghidra.
O parser LIEF e a análise independente anteriores foram removidos.

## Preparação e análise

Na raiz do clone, com Python 3.12 ou posterior:

```text
python scripts/machsentry_setup.py
python scripts/machsentry_run.py analyze CAMINHO/arquivo.macho --output reports/macos/analise-001
```

O setup instala as versões fixadas dos runtimes em `.tools`, compila o REA e
prepara `.venv-unpack`. Os binários instalados não são versionados no Git.
A configuração pertence ao sistema e à arquitetura onde o setup rodou; execute-o
novamente no Mac. O clone não traz amostras nem relatórios locais.

Para um ZIP explicitamente escolhido:

```text
python scripts/machsentry_run.py analyze amostras/AtomicStealer-2023.zip --member "AtomicStealer/Trading View" --zip-password infect3d --output reports/macos/atomic-001
```

O membro é descompactado em um arquivo temporário próprio para importação
estática pelo REA. O nome do membro não é usado como caminho de extração.
Um FAT é inventariado e separado pelo `inspect_artifact`/`extract_artifact`
do REA; cada slice selecionada recebe uma sessão Ghidra. A análise não executa
a amostra nem scripts, não abre URLs extraídas e não contata C2. Ghidra e REA
são subprocessos locais; no Windows o bridge Ghidra usa loopback autenticado.
Se o antivírus impedir a importação, a análise falha e registra a limitação;
não há desativação ou bypass de proteção.

Todas as slices disponíveis são selecionadas por padrão; `--architecture arm64`
ou `--architecture x86_64` restringe a análise. `--max-functions 64` é o orçamento
de descompilação por slice. Funções não selecionadas continuam desconhecidas.
`--rea-timeout 900` controla o prazo de cada chamada, incluindo a importação
inicial. As variáveis `GHIDRA_HEADLESS_MAXMEM` e
`REA_GHIDRA_STARTUP_TIMEOUT_MS` preservam os valores escolhidos pelo operador.
A memória real inclui Node, JVM, descompilador e Python; o heap da JVM não é o
limite da família inteira de processos.

Também é possível usar `python -m machsentry` com o ambiente virtual. Informe
`--rea-root CAMINHO` para outro checkout compilado e `--rea-node EXECUTAVEL`
para escolher o Node. Sem REA/Ghidra disponível, o comando falha; não troca para
um analisador independente. Senhas e o ambiente herdado não são persistidos.

## Evidência e entregas

- `report.html`: entrega principal para o analista, com oito seções fixas,
  explicação dos critérios YARA e download da candidata quando disponível.
- `report-view.json`, schema `1.0`: contrato de apresentação para o dashboard,
  validado na publicação pelo `report-view.schema.json` (JSON Schema 2020-12).
  Mantém campos e seções em achados, ausência de achados e falhas; valores
  desconhecidos permanecem `null` e coleções vazias permanecem listas.
- `report.json`, schema `2.1`: identidade original e por slice, score,
  inferências, funções, strings, scripts, validação YARA, erros e cobertura.
- `report.md`: resumo técnico mantido para compatibilidade.
- `function-NNN-ARQUITETURA.pseudo.c.txt`: pseudocódigo exato retornado pelo Ghidra.
- `functions.asm.txt`: assembly retornado pelo REA; exportação limitada a 2 MiB,
  com truncamento explícito. O Evidence completo permanece no JSON/bundle.
- `rea-evidence-NNN.json`: bundles completos exportados da sessão REA, com seus
  IDs, proveniência, perfil de análise e limitações, para reimportação pelo REA.
- `script-NNN.txt`: fragmentos de AppleScript/lançadores, nunca executados.
- `detection.yar`: candidata validada nos arquivos fornecidos. Candidatas com
  falso positivo observado ou variante não detectada ficam em
  `candidate-rejected.yar.txt`.

O pseudocódigo não é o fonte original nem possui garantia de compilação ou
fidelidade completa. As funções candidatas são selecionadas por referências
do REA às categorias de indicadores configuradas; não se promete engenharia
reversa completa de todo o binário. As associações não provam execução nem
intenção maliciosa isoladamente. Endereços são VAs sem ASLR, identificados pela
arquitetura. Offsets referem-se ao arquivo original ou membro descomprimido.
Offsets indisponíveis permanecem `null`, sem estimativa.

O HTML usa sempre esta ordem: resumo, identificação, comportamentos/evidências,
funções, scripts, rede, YARA e cobertura. Não inclui versões de ferramentas,
caminhos internos do worker, métricas de implementação ou pseudocódigo; esses
dados permanecem nos artefatos técnicos. Cada critério `$b...` ou `$op...` é
vinculado à seleção emitida pelo gerador, com valor, origem, interpretação e
motivo. Padrões de opcodes incluem VA, arquitetura e significado dos operandos
mascarados. As explicações não são inferidas novamente do texto da regra.

O arquivo é autossuficiente, sem JavaScript, fontes externas ou chamadas de
rede. Dados da amostra são escapados como texto e a CSP bloqueia conteúdo ativo.
Há estilos para impressão e telas menores. A regra continua sem comentários
explicativos extensos: a justificativa aparece no relatório. Candidatas
rejeitadas e relatórios com falha não exibem download de `detection.yar`.

O fluxo usa `open_binary`, `list_strings`, `xrefs`,
`resolve_containing_procedure`, `analyze_function`, `address_to_file_offset`,
`read_bytes`, `inspect_native_instruction`, `get_evidence_bundle` e
`close_binary`. A sessão REA é a proprietária do processo Ghidra e do banco
efêmero. Falhas de fechamento são registradas e tentadas novamente antes de
encerrar o transporte MCP; fechamento não confirmado impede sucesso.

O diretório de saída deve ser novo. O `report.json` é o registro de publicação,
gravado após as exportações. Um relatório de falha também pode existir: o
consumidor deve conferir saída zero, envelope `ok: true` e `analysis_status`.
Saída 2 indica falha esperada e inclui caminhos dos resultados parciais quando
retidos; 3 indica falha inesperada; 130 indica interrupção. Não existe cobrança
automática, retry de análise ou serviço HTTP neste módulo.

## Score e YARA

O score é heurístico: senha oculta 20, Keychain 20, dados de navegador 15,
carteiras 15, envio 20, persistência 10 e inventário 5, limitado a 100. Usa o
maior resultado por slice; não soma arquiteturas. `high_risk_indicators` exige 70
pontos e referências de código em três categorias fortes na mesma slice;
`suspicious` começa em 30; o restante é `inconclusive`. Não é probabilidade e
nenhum score certifica benignidade. A maliciosidade permanece `unconfirmed`: até
funções inertes que só retornem ponteiros para strings podem disparar os indicadores.
Referências e pseudocódigo disponibilizados permitem investigar o comportamento,
mas o score não substitui essa avaliação. Sem slice analisada, o score é `null`
e a maliciosidade fica `not_assessed`.

Use `--yara-mode auto|hybrid|strings|opcodes`, `--benign-file ARQUIVO` e
`--related-file ARQUIVO`. Os dois últimos são repetíveis e preservam os hashes
e cada match/miss. O conjunto de validação admite 128 arquivos e 64 MiB.
A origem benigna ou a família dos arquivos é declarada pelo operador.

Strings de detecção exigem o mapeamento do REA e igualdade com os bytes originais.
O modo strings combina três categorias fortes ligadas a código. O modo híbrido
combina strings e dois padrões de funções distintas da mesma slice de origem.
O modo opcodes exige esses padrões e o magic Mach-O. `auto` usa strings quando
não há padrões de código suficientes; modos explícitos não mudam silenciosamente.

Capstone serve apenas para construir máscaras sobre funções e referências já
atribuídas pelo REA, depois de conferir os bytes lidos pelo Ghidra com o original.
Janelas têm 24–128 bytes, pelo menos 16 bytes fixos, quatro concretos consecutivos
e até 40% de bytes com curinga; início e fim são concretos. Deslocamentos e
operandos variáveis são mascarados preservando os bits conhecidos do opcode.
Isso não prova estabilidade em variantes. Um positivo relacionado sem match
impede publicação como `detection.yar`; não se relaxa a regra para forçar match.

YARA observa bytes, não comportamento executado. Não existe garantia de zero
falsos positivos. `positive_only` informa validação só na amostra;
`validated_candidate` também exige negativos sem match; `production_ready`
continua falso. As ocorrências não são restringidas a uma slice no momento do
match, uma limitação explícita da candidata.

## Verificação e integração

```text
.venv-unpack/Scripts/python.exe -m unittest discover -s macos_static/tests -v
```

No macOS, use `.venv-unpack/bin/python`. Os testes determinísticos cobrem os
limites de entrada, contratos MCP simulados, retenção de Evidence, identidade,
falhas, fechamento, publicação, score e YARA. Eles não estabelecem funcionamento
do Ghidra real. Consulte [a validação](../docs/machsentry-validation.md) para os
ensaios reais e [a integração](../docs/machsentry-integration.md) para o worker
do Unpacked (`worker/` e `deploy/`). O setup cobre Windows, macOS e Linux x86_64.

REA mantém sua licença/atribuição MIT. Ghidra, o JDK, o SDK MCP, Capstone e YARA
mantêm suas respectivas licenças. Amostras, relatórios, bancos e runtimes locais
não fazem parte do pacote Python ou do histórico Git.
