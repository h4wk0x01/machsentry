# Validação do MachSentry

## Integração REA/Ghidra: 0.3.0

A versão 0.3.0 substitui o analisador independente pelo cliente do MCP do REA.
Funções, referências, assembly e pseudocódigo agora vêm do provedor Ghidra.
Os resultados 0.2 documentados abaixo são históricos e **não foram produzidos
pelo REA/Ghidra**. O contrato dos novos relatórios é `schema_version: "2.0"`.

Em 17 de outubro de 2026, no Windows x64, o preparo completo
`python scripts/machsentry_setup.py` terminou com sucesso: downloads verificados,
npm ci, build do REA, instalação do cliente e diagnóstico Ghidra saudável.
Foram usados Node 24.18.0, npm 11.16.0, Ghidra 12.1.4 e Temurin JDK 21.0.12.1.
As ferramentas ficam em `.tools/`, ignorada pelo Git. O comando foi verificado
neste checkout. A execução remota em macOS 15 arm64 também concluiu o preparo e
as verificações reais de CLI e MCP no commit `958e67f80`:
[job macOS](https://github.com/h4wk0x01/machsentry/actions/runs/39005863423/job/117318103533).
A CLI levou 26,37 s (x86_64) e 16,92 s (arm64); o relatório universal levou
27,07 s, com oito pseudocódigos, 61 evidências e a verificação YARA aprovada.
Esses testes usam os arquivos inertes descritos abaixo, sem executar seus bytes.

A CLI pública `rea decompile`, usando o provedor real, recuperou `return 0x2a;`
de dois Mach-O inertes codificados para o teste, x86_64 e arm64. Os tempos foram
30,97 s e 21,90 s, respectivamente; os SHA-256 das entradas ficaram iguais.
São importações novas, com estado de cache do sistema operacional não controlado,
e não programas compilados por uma toolchain Apple. O verificador reproduzível
é `scripts/verify-machsentry-ghidra.py`.

Pelo MCP real, um teste benigno sem indicadores terminou em 17,00 s, sem erros,
com resultado inconclusivo e sem regra YARA. Um Mach-O universal inerte com
literais artificiais percorreu `inspect_artifact`, `extract_artifact`, abertura
das slices, inventário, xrefs, resolução de funções e descompilação. Foram
retidas 61 evidências, oito funções com pseudocódigo, duas arquiteturas e uma
candidata híbrida. A regra compilou, detectou a fixture selecionada e não
correspondeu aos dois controles inertes de retorno constante. Fechamento das
sessões e remoção das slices temporárias foram confirmados no relatório.

Esse segundo teste levou 31,47 s e registrou 1,66 s de CPU do cliente Python e
197,1 MiB de pico de memória do Python. CPU e pico da família Node/JVM/descompilador
não foram medidos. O fluxo não chama LLM; tokens usados no desenvolvimento não
foram medidos. Esses números não são comparáveis aos benchmarks 0.2 abaixo:
o motor e a cobertura são diferentes, e não houve controle de cache frio/quente.

**A fixture é benigna:** suas funções retornam ponteiros para texto de teste.
O score 75 e a correspondência YARA são resultados intencionalmente induzidos
pelos indicadores; não validam precisão, intenção maliciosa ou taxa de falsos
positivos. Demonstram também a limitação da heurística atual. O pseudocódigo e
as evidências devem ser examinados antes de uma decisão. Não houve validação
com um corpus representativo de famílias ou software legítimo.

Esse resultado motivou uma correção do veredito: a heurística v2 retorna
`high_risk_indicators`, com `maliciousness: "unconfirmed"`, quando há muitos
indicadores ligados a código. Ela não transforma referências em confirmação de
malware. As pontuações são mantidas como prioridade de investigação.

Verificações locais adicionais: 50 testes Python passaram, com um teste de symlink ignorado no Windows; sete testes do preparo,
140 testes TypeScript focados (três exclusivos de macOS ignorados), typecheck/lint,
checagem de documentação e descoberta dos testes. Um teste preexistente separado
de criação de symlink não pôde passar nesta conta Windows por `EPERM`; não houve
mudança de privilégios. A CI inclui Ghidra real em Windows e macOS.

A tentativa de importar a referência Atomic Stealer foi impedida pelo Defender.
Os eventos 1116/1117 registraram `Trojan:MacOS/Amos.AO!MTB` e quarentena da cópia
temporária. O relatório retornou falha de abertura, e nenhum pseudocódigo dessa
amostra foi produzido pelo Ghidra neste computador. Não foram alteradas as
proteções. O código atual deixa o score indisponível quando nenhuma slice pode
ser analisada. A análise histórica dessa amostra permanece separada abaixo.

## Correção do nome: 0.2.1

O nome atual do produto é **MachSentry**; o pacote Python, o módulo e o comando
são `machsentry`. A mudança corrige o nome recebido por transcrição, sem alterar
as heurísticas, o parser ou a seleção de opcodes.

Os 48 testes passaram novamente no Windows após a instalação editável do novo
pacote. `machsentry --version` retornou `0.2.1`, inclusive após a remoção do
pacote anterior do ambiente virtual. A wheel foi construída a partir de uma
cópia limpa das fontes e inspecionada: seus 18 arquivos contêm apenas o novo
pacote, seus metadados e a licença, com o entry point `machsentry.cli:main`.

## Execução de referência 0.2.0

Os registros desta seção pertencem à versão anterior à correção do nome.
Os diretórios de evidências e identificadores históricos foram preservados.

Execução local em **17 de outubro de 2026**, Windows, Python 3.12, LIEF 1.0.0,
Capstone 5.0.9 e yara-python 4.5.4. O novo núcleo é Python independente; não foram
executados build, testes, typecheck ou verificadores npm do REA upstream. O host
não tinha npm nem node_modules. A configuração de CI Windows/Linux acompanha
o módulo; seu resultado remoto deve ser consultado no GitHub Actions.
Linux não foi validado localmente. A [CI do módulo no commit 82d2988fc](https://github.com/h4wk0x01/machsentry/actions/runs/39002576259)
passou no Windows e no Ubuntu, com os 48 testes em cada plataforma.

O formatter fixado no repositório (`oxfmt` 0.72.0) validou os arquivos ajustados.
Cinco verificações locais da paridade de documentação cobriram as 19 traduções,
a separação da introdução do fork, drift no conteúdo upstream e compatibilidade
com README sem o marcador, usando Node 24.18.0 portátil. Esse check isolado não
substitui a geração completa do catálogo npm, executada pela CI herdada.

## Verificações executadas

```powershell
.\.venv-unpack\Scripts\python.exe -m pip install -e ./macos_static
.\.venv-unpack\Scripts\python.exe -m unittest discover -s macos_static/tests -v
.\.venv-unpack\Scripts\python.exe -m compileall -q macos_static/facemessenger
git diff --check
```

**48 testes passaram**, tanto na instalação editável quanto na wheel instalada.
A wheel foi construída e inspecionada: contém somente o núcleo Python, metadados
e licença, sem amostras, relatórios ou dependências empacotadas. O comando
`facemessenger --version` retornou `0.2.0`. Os testes cobrem a CLI em processo real, relatório/manifesto de
exportação, correspondência de hashes, YARA positiva/negativa/rejeitada, ausência
de conclusão de benignidade, arquivo preservado, publicação interrompida,
seleção explícita e ambígua de membro ZIP, expansão de arquivo compactado,
headers e comandos truncados, payloads fora do arquivo, sobreposição e
inconsistência de endereços, expansão de nomes de símbolos antes do parser,
RIP-relative, ADRP+ADD, invalidação de aliases W/X e independência entre slices.
Incluem máscaras de operandos x86_64/arm64, extremidades concretas, preservação
dos bits de opcode/registrador, deduplicação, limites, procedência, múltiplas
funções por regra, variantes sintéticas detectadas e misses retidos como
candidatas incompletas. Nenhuma variante real adicional foi usada.
Fixtures são sintéticas e inertes. A fixture mínima da CLI gera dois avisos do
LIEF por não separar `__LINKEDIT`; isso não ocorre no teste da amostra real.

O uso de nomes definidos e limites de funções vem do parser, e não de correspondência
de nome com uma lista de funções maliciosas. O teste ARM64 revelou e corrigiu
uma atribuição falsa após escrita em W0 invalidar X0. A revisão também revelou
o risco de uma assinatura selecionar somente um prefixo benigno; agora o dono
da interpretação fornece spans dos indicadores para o gerador YARA.

## Referência real

A família Atomic Stealer/AMOS foi selecionada do
[relatório de 2023 da Objective-See](https://objective-see.org/blog/blog_0x77.html).
O rótulo de família vem dessa coleção, separadamente das conclusões locais.
ZIP adquirido da revisão `de63d2987a933197966b9778fdb746df0968938d`, datada de
2024-01-02; a revisão e os hashes estão em [amostras/README.md](../amostras/README.md).

Membro selecionado: `AtomicStealer/Trading View`, 790.688 bytes.

```text
SHA-256: ce3c57e6c025911a916a61a716ff32f2699f3e3a84eb0ebbe892a5d4b8fb9c7a
```

O Defender bloqueou o executável gravado na aquisição inicial. Não foi
desativado nem recebeu exclusões; as análises seguintes leem somente o membro
do ZIP criptografado em memória. O DMG da coleção não foi analisado. Nada da
amostra foi executado e nenhum candidato a C2 foi contatado.

Resultado observado: **95/100, `likely_malicious`**, heurístico e não calibrado.
555 strings em 49 seções; 14 funções relacionadas a seis categorias de indícios,
sete por arquitetura. Seis fragmentos AppleScript/lançadores foram exportados.

| Associação estática                  | x86_64        | arm64         |
| ------------------------------------ | ------------- | ------------- |
| Diálogo de senha (`GetUserPassword`) | `0x1000075c0` | `0x1000077c4` |
| Keychain (`keychain`)                | `0x100004040` | `0x100004964` |
| Chromium (`GrabChromium`)            | `0x100002360` | `0x1000033fc` |
| Firefox (`GrabFirefox`)              | `0x100004b30` | `0x100005284` |
| Carteiras (`ColdWallets`)            | `0x1000051e0` | `0x100005814` |
| Envio HTTP (`sendlog`)               | `0x100005f20` | `0x10000624c` |
| Inventário (`systeminfo`)            | `0x1000043e0` | `0x100004c34` |

São VAs sem ASLR. O JSON preserva os nomes mangled originais, offsets e
instruções que referenciam as evidências. O candidato de rede
`185.106.93.154` está embutido no arquivo; atividade atual permanece desconhecida.

Foram decodificadas 21.770 instruções x86_64 e 21.425 arm64. Permaneceram 393
bytes não decodificados nos intervalos de funções x86_64. Os intervalos arm64
examinados foram decodificados por completo, sem estabelecer a recuperação de
todas as funções, caminhos ou comportamentos. Pseudocódigo, execução simbólica,
decifração e análise dinâmica não foram realizados. A exportação de assembly
das funções relevantes não foi truncada.

## YARA e controles

Foram geradas e compiladas três candidatas: `strings`, `auto` (modo efetivo
`hybrid`) e `opcodes`. A híbrida exige magic Mach-O, cinco literais relativos a
Keychain, carteira, envio HTTP, resposta oculta e cookies, e duas janelas de
instruções de funções distintas de uma mesma arquitetura de origem. A candidata
de opcodes exige o magic e duas dessas janelas, sem depender dos literais.
Nenhuma usa hash como condição ou contém comentários.

Foram selecionadas seis janelas: três x86_64 e três arm64, com 96–104 bytes,
58–72 bytes completamente fixos e 30,8–39,6% de bytes contendo curinga. Todas
começam e terminam com bytes fixos. Campos variáveis são identificados pelo
decoder, com tolerância parcial em arm64 quando bits do imediato compartilham
nibbles com opcode ou registrador.

**As três candidatas corresponderam à amostra universal.** As regras híbrida e
de opcodes também corresponderam separadamente a cada slice x86_64 e arm64,
selecionadas em memória. Isso verifica as duas arquiteturas do mesmo arquivo,
sem estabelecer cobertura de outras variantes. Nenhuma candidata correspondeu
aos dois controles nativos abaixo, extraídos das wheels
macOS do Capstone 5.0.9 obtidas do PyPI, sem executá-los:

| Controle           | SHA-256                                                            | Match |
| ------------------ | ------------------------------------------------------------------ | ----- |
| libcapstone arm64  | `016084c6e70d929249a2abb22f1afda95095294e6cd70f509964ffc54006bf94` | não   |
| libcapstone x86_64 | `bbf3f4dac202c51c35a076145c480394056614bdbccc7300c8a44a834b5170cf` | não   |

Também foi executada uma análise completa do controle arm64: score 0,
`inconclusive`, nenhuma candidata YARA. Isso não certifica benignidade.

**0/2 matches em controles não prova ausência de falsos positivos.** Não foram
validados um corpus representativo de apps macOS, outros stealers, variantes
AMOS, binários empacotados ou taxa de falsos negativos. A regra é candidata
específica da amostra e `production_ready` continua falso. YARA reconhece bytes
associados a comportamentos; não observa execução nem restringe ocorrências a
uma mesma slice na aplicação da regra.

## Custo medido

O fluxo medido incluiu inicialização do interpretador, leitura do ZIP e dois
controles, análise, YARA e gravação do relatório/assembly. Usou o interpretador
base com as bibliotecas do venv explicitamente selecionadas, sem o redirector
de venv do Windows e sem processos filhos. Não há cache de análise. O estado
do cache do sistema operacional não foi esvaziado nem medido.

| Modo               | Execução                                     | Tempo total | CPU total | Pico working set observado |
| ------------------ | -------------------------------------------- | ----------- | --------- | -------------------------- |
| Strings            | Primeiro processo, cache do SO desconhecido  | 1,927 s     | 1,672 s   | 127.619.072 bytes          |
| Strings            | Repetição com arquivos aquecidos             | 1,454 s     | 1,406 s   | 127.995.904 bytes          |
| Híbrido automático | Primeiro processo do modo, arquivos já lidos | 1,436 s     | 1,391 s   | 127.762.432 bytes          |
| Híbrido automático | Repetição com arquivos aquecidos             | 1,378 s     | 1,328 s   | 127.348.736 bytes          |
| Opcodes            | Processo novo, arquivos já lidos             | 1,314 s     | 1,234 s   | 127.180.800 bytes          |

CPU: `GetProcessTimes`. Memória: `PeakWorkingSetSize` cumulativo consultado a
cada 10 ms; o pico final entre a última consulta e a saída pode não ter sido
capturado. Não é um benchmark de disco frio. Strings e híbrido usam o mesmo
arquivo, controles e exportações; a comparação isola a opção de geração YARA,
mas a pequena quantidade de execuções e a ordem não permitem atribuir ganho de
velocidade aos opcodes. O fluxo anterior 0.1.0 levou 1,592 s e 1,501 s; os
registros históricos foram preservados. Tamanho de JSON não é contagem de tokens.
O worker não chama LLM: zero tokens de LLM
em execução. Tokens do agente durante desenvolvimento não foram medidos.
Custos de integração web, isolamento de workers e corpus amplo não foram medidos.

## Artefatos locais e pendências

Artefatos finais, ignorados pelo Git:

- `reports/macos/facemessenger-0.2-auto-fresh/report.md`
- `reports/macos/facemessenger-0.2-auto-fresh/report.json`
- `reports/macos/facemessenger-0.2-auto-fresh/detection.yar`
- `reports/macos/facemessenger-0.2-auto-fresh/functions.asm.txt`
- `reports/macos/facemessenger-0.2-auto-fresh/script-000.txt` a `script-005.txt`
- `reports/macos/facemessenger-0.2-opcodes-fresh/detection.yar`
- `reports/macos/facemessenger-benchmark.json`
- `reports/macos/facemessenger-slice-matches.json`

Os relatórios de `atomic-2023-final` e `benchmark.json` pertencem à primeira
implementação 0.1.0 e permanecem preservados para comparação.

O pacote fornece a base funcional local, sem autenticação, upload HTTP,
fila, créditos ou integração visual implantada. Antes de produção paga,
precisa de isolamento externo de workers, validação em corpus amplo e uma
política de cobrança/retentativas implementada conforme o
[contrato de integração](machsentry-integration.md).
