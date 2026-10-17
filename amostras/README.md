# Amostras locais

Esta pasta guarda entradas de pesquisa, ignoradas pelo Git. O código do produto
não inclui nem executa malware. Não publique estes arquivos no site ou no pacote.

A referência inicial é **Atomic Stealer / AMOS (2023)**, da coleção pública da
[Objective-See](https://objective-see.org/blog/blog_0x77.html), na revisão
`de63d2987a933197966b9778fdb746df0968938d` (2024-01-02).

```powershell
python macos_static/fetch_reference_sample.py
```

O script baixa apenas o ZIP criptografado, confere o SHA-256 fixo e preserva
arquivos existentes. `provenance.json` registra origem, revisão e identidades.
A senha pública da coleção é `infect3d`. Selecione o membro exato
`AtomicStealer/Trading View` na CLI. O cliente prepara uma cópia temporária para
importação estática pelo REA/Ghidra, preservando os hashes do ZIP, do membro e
das arquiteturas selecionadas. O DMG não faz parte dessa análise.

```text
python scripts/machsentry_run.py analyze amostras/AtomicStealer-2023.zip --member "AtomicStealer/Trading View" --zip-password infect3d --output reports/macos/atomic-ghidra-001
```

- ZIP: `20932399c098674c084f158e2f830e1961bb8ecc7f10e68476458e11a8f64413`
- Mach-O selecionado: `ce3c57e6c025911a916a61a716ff32f2699f3e3a84eb0ebbe892a5d4b8fb9c7a`
- Tamanho do Mach-O: 790.688 bytes; x86_64 e arm64.

O Defender bloqueou o Mach-O gravado durante a aquisição inicial. Sua proteção
foi mantida. As análises históricas 0.2 usaram o membro em memória, sem Ghidra.
O fluxo atual depende de uma cópia local admitida pelo REA: se a proteção impedir
essa importação, a análise deve registrar a falha, sem desativar proteção ou
declarar descompilação realizada. Nenhum componente da amostra deve ser executado.
A idade não determina se o C2 está ativo.

`benign/` contém controles locais extraídos das wheels macOS do Capstone 5.0.9
baixadas do PyPI. Os hashes de cada controle constam dos relatórios. Esse corpus
pequeno não representa o universo de software legítimo.
