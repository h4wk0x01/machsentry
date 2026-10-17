# Integração futura do facemessenger com o Unpacked

## Estado e fronteira do módulo

O facemessenger é um módulo de análise estática de arquivos Mach-O. O núcleo
Python fica em `macos_static/facemessenger`, separado dos adaptadores CLI/MCP do
REA e do servidor Next.js do Unpacked. A fronteira de entrada é um arquivo local
selecionado pelo operador; a saída é um relatório JSON de versão 1 e os artefatos
produzidos pela análise. LIEF concentra a interpretação estrutural do Mach-O,
Capstone fornece a desmontagem suportada e yara-python valida as regras.

O comando do núcleo, executado a partir de `macos_static` ou após a instalação do
pacote, é:

```text
python -m facemessenger analyze CAMINHO_DA_AMOSTRA --output DIRETORIO_DO_RESULTADO
```

Esta documentação propõe a integração comercial. Não implementa nem confirma
endpoints HTTP, uploads, fila, cobrança por créditos, interface do dashboard ou
deploy. A análise local não deve depender de sessão web, Stripe ou banco de
dados do Unpacked. O serviço web será responsável por autenticação, propriedade
dos arquivos, trabalhos, créditos e entrega dos relatórios.

As amostras são dados de entrada: não devem ser executadas, nem devem seus
scripts, URLs ou comandos recuperados ser acionados. Análise estática pode
identificar capacidades e indícios de comportamento; não observa execução e
não estabelece que todas as funções foram recuperadas.

## Pontos existentes no Unpacked

O projeto inspecionado está em
`C:\Users\mythic-user\Documents\projeto_mac_ma\unpacked`. Os caminhos abaixo
são relativos a essa raiz. O projeto usa Next.js, Auth.js, Drizzle/libsql e
Stripe. Não foi encontrado um sistema de créditos de análise, fila ou tabela
de trabalhos de análise no código inspecionado.

| Caminho                                    | Responsabilidade existente e uso na integração                                                                                                        |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `app/[locale]/track/page.tsx`              | Compõe o dashboard e seus painéis. É o ponto de composição para um futuro painel de análises.                                                         |
| `components/dashboard/views.ts`            | Define as abas e a seleção por `?view=`. Uma nova aba exige uma entrada nesse contrato.                                                               |
| `components/dashboard/dashboard-shell.tsx` | Prepara os textos e dados do quadro do dashboard.                                                                                                     |
| `components/dashboard/dashboard-frame.tsx` | Renderiza navegação, ícones e painéis.                                                                                                                |
| `lib/auth.ts`                              | Resolve a conta autenticada e seus dados por requisição.                                                                                              |
| `lib/access.ts`                            | Verifica acesso pago ativo e não expirado. Isso não representa saldo de créditos.                                                                     |
| `db/schema.ts`                             | Contém usuários, direitos de acesso, eventos Stripe e tentativas dos exercícios. Os relatórios de exercícios não são trabalhos de análise de malware. |
| `db/index.ts`                              | Compõe o acesso Drizzle/libsql; a configuração local usa SQLite.                                                                                      |
| `lib/config.ts`                            | Centraliza produtos e planos. Ainda não define franquia, preço ou validade de créditos de análise.                                                    |
| `lib/billing.ts`                           | Concede e atualiza acesso após checkout e pagamento de faturas.                                                                                       |
| `lib/stripe-webhook.ts`                    | Processa os eventos Stripe verificados.                                                                                                               |
| `app/api/stripe/webhook/route.ts`          | Recebe e verifica a assinatura do webhook Stripe.                                                                                                     |
| `app/api/artifacts/[id]/route.ts`          | Entrega artefatos de exercícios após verificar sessão, token, termos e acesso. Serve como referência de autorização, não como endpoint de upload.     |
| `lib/artifacts/signing.ts`                 | Implementa tokens de download com expiração e vínculo ao usuário.                                                                                     |

Uma futura aba de análises pode apresentar envio de arquivo, custo, saldo,
histórico e resultado. Textos devem acompanhar os idiomas já suportados. O
dashboard deve ler estados persistidos; fechar a página não cancela nem perde
um trabalho. Trechos de AppleScript, strings e nomes vindos da amostra devem
ser apresentados como texto, sem execução ou interpretação como HTML.

## Contrato proposto entre web e worker

O navegador recebe identificadores opacos. Caminhos do sistema de arquivos,
argumentos do processo, regras de custo e diretórios de saída são resolvidos
pelo servidor. O worker recebe uma referência privada ao arquivo, identidade
esperada, opções validadas e um identificador de trabalho; lê os bytes,
confirma SHA-256 e tamanho e chama o núcleo em um processo isolado.

Uma API possível, ainda não implementada, é:

| Operação proposta                          | Resultado e autorização                                                                                                                        |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /api/macos-analysis/uploads`         | Admite um upload privado e limitado, vinculado à conta. Não inicia análise nem consome créditos.                                               |
| `POST /api/macos-analysis/jobs`            | Recebe `upload_id`, opções e uma chave de idempotência. Valida acesso e saldo, reserva créditos e cria o trabalho. Retorna `202` com `job_id`. |
| `GET /api/macos-analysis/jobs/:id`         | Retorna estado e resumo apenas para o proprietário.                                                                                            |
| `GET /api/macos-analysis/jobs/:id/report`  | Entrega o relatório persistido de um trabalho concluído, após verificar propriedade.                                                           |
| `POST /api/macos-analysis/jobs/:id/cancel` | Solicita cancelamento; a resposta não deve declarar limpeza concluída antes de o worker confirmar.                                             |
| `GET /api/macos-analysis/jobs/:id/yara`    | Entrega a regra e o estado de sua validação quando disponíveis.                                                                                |

No relatório, preservar as identidades da amostra e de cada arquitetura,
evidências com posições na origem, achados, funções, scripts, score e veredito,
regra YARA, resultados de validação, cobertura, limitações e métricas. O
consumidor deve validar a versão e o formato do JSON antes de armazená-lo como
resultado concluído. Mudanças incompatíveis exigem nova versão do contrato.
Não reconstruir evidências no frontend a partir do resumo textual.

O endereço de uma função precisa informar arquitetura e coordenada virtual
estática; offsets de arquivo continuam offsets. Uma string suspeita não deve
ser promovida a função maliciosa sem evidência de atribuição. O score deve
expor os fatores que contribuíram para ele e suas limitações, sem representar
uma probabilidade calibrada. Cobertura parcial e resultado inconclusivo são
resultados válidos e precisam aparecer na interface.

## Trabalhos, créditos e idempotência

As novas entidades devem separar arquivo privado, trabalho, resultado e razão
de créditos. Um saldo editável sem histórico não é suficiente para conciliar
tentativas, cancelamentos, falhas e pagamentos repetidos.

1. **Admissão:** validar a sessão, propriedade do upload, acesso aplicável,
   opções, limites e custo. O custo e sua versão são calculados no servidor e
   registrados no trabalho.
2. **Reserva:** na mesma transação, conferir saldo disponível, reservar o
   custo, criar o trabalho e registrar a intenção durável de despacho. A
   restrição única `(user_id, idempotency_key)` deve devolver o mesmo trabalho
   para uma repetição idêntica. A mesma chave com entradas diferentes deve
   produzir conflito, sem nova reserva.
3. **Despacho:** publicar a intenção por uma outbox transacional ou mecanismo
   equivalente. Uma falha entre banco e fila não pode deixar uma reserva sem
   trabalho recuperável nem criar uma segunda cobrança.
4. **Execução:** usar aquisição exclusiva com lease, número de tentativa e
   token de posse. Um worker antigo não pode concluir o trabalho depois de
   perder a posse. Novas tentativas reutilizam a reserva existente.
5. **Liquidação:** publicar um resultado validado em armazenamento durável e
   concluir o trabalho junto com o consumo da reserva, em uma transação. A
   referência do resultado deve existir antes desse commit. Repetir a
   conclusão não consome créditos novamente.
6. **Liberação:** falha terminal ou cancelamento não faturável libera a
   reserva uma única vez, após o desfecho conhecido. Conciliar a corrida entre
   conclusão e cancelamento por transição condicional; somente um estado
   terminal vence.
7. **Estorno:** devolver um consumo já liquidado exige um lançamento
   compensatório com chave única e motivo. Isso é diferente de liberar uma
   reserva ainda não consumida. Nunca apagar o lançamento original.

Estados sugeridos para o trabalho são `queued`, `running`, `succeeded`,
`failed` e `cancelled`, com solicitação de cancelamento registrada
separadamente. Cada transição deve verificar o estado anterior e a posse
quando aplicável. A política comercial precisa definir quais resultados
parciais são faturáveis; o worker não deve decidir preço com base no score.

Concessões de créditos por pagamento devem ser únicas por compra ou fatura e
período de franquia, inclusive quando eventos diferentes descrevem o mesmo
pagamento. A chave do evento Stripe, sozinha, não identifica a concessão. No
código inspecionado, `processStripeEvent` registra o evento antes de executar
as alterações de negócio, sem transação abrangente nessa função. A concessão
de créditos precisa assegurar atomicidade entre deduplicação e lançamento,
para que uma falha após o registro não descarte a concessão na tentativa
seguinte.

Consultar, paginar e baixar um relatório já adquirido não deve criar um novo
trabalho nem consumir créditos novamente. Um cache de análise deve considerar
SHA-256, arquiteturas, opções, versão do núcleo, dependências relevantes,
regras de classificação e geração YARA. Cache compartilhado não autoriza
acesso ao relatório de outra conta. A política de custo para uma nova análise
que reutiliza cache precisa ser explícita.

## Lacunas antes de disponibilizar o serviço

- Definir franquia, renovação, expiração, preço por análise, elegibilidade de
  membros vitalícios e política para resultado parcial, cancelamento e estorno.
- Implementar migrações, razão de créditos, transações, outbox ou fila,
  worker, leases, reconciliação e autorização por proprietário em cada rota.
- Definir armazenamento privado, prazo de retenção e exclusão de amostras e
  relatórios. Manter amostras fora de `public/`, do bundle web e do Git.
- Fixar e testar dependências Python e imagens de implantação. LIEF, Capstone
  e YARA interpretam bytes não confiáveis; executar o worker com limites de
  tempo, memória, disco e concorrência, sem credenciais do servidor web e sem
  saída de rede durante a análise. Não reutilizar diretórios entre trabalhos.
- Validar bytes e estrutura do formato, não somente nome ou MIME. Limites de
  upload e expansão devem preceder alocação. Suporte futuro a arquivos
  compactados precisa de orçamento e regras de extração próprios.
- Testar submissões simultâneas, duplicação de eventos e mensagens, falta de
  saldo, falhas entre etapas, retomada após queda, perda de lease, cancelamento
  durante finalização e acesso entre contas.
- Medir tarefas completas com amostras e controles benignos representativos:
  tempo decorrido, CPU, pico de memória da família de processos e tamanho dos
  relatórios; separar execuções frias e quentes. Se um modelo for incorporado,
  medir também tokens e custo. O núcleo local não estabelece essas métricas
  para um futuro deploy web.
- Avaliar regras YARA contra a amostra, variantes disponíveis e um corpus
  benigno documentado. Informar quais arquivos foram testados e seus
  resultados; não anunciar ausência universal de falsos positivos. As regras
  reconhecem padrões estáticos associados aos achados, não observam o
  comportamento em execução.

As verificações locais do núcleo não substituem os testes de isolamento,
concorrência, cobrança e autorização do serviço. Esta proposta mantém a
integração futura separada do resultado da análise estática já disponível por
CLI.
