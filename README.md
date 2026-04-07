# HTTP Message Signatures (RFC 9421) — Demo .NET 10

Implementação de referência da [RFC 9421](https://datatracker.ietf.org/doc/rfc9421/) em .NET 10, demonstrando como assinar e verificar requisições HTTP de forma que qualquer alteração no payload, método ou URI invalide a assinatura — independente de TLS.

## Por que RFC 9421?

HTTPS protege o **canal** (transporte). HTTP Message Signatures protegem a **mensagem** em si:

| Ameaça | HTTPS | RFC 9421 |
|---|---|---|
| Interceptação no transporte | Protege | Protege |
| Intermediário que altera o body | Não protege | Detecta |
| Replay de uma requisição legítima | Não protege | Detecta (via timestamp/nonce) |
| Spoofing de identidade do caller | Não protege | Detecta (via keyid) |

Casos de uso reais: APIs B2B, webhooks com garantia de origem, comunicação entre microsserviços em ambiente zero-trust.

---

## Estrutura do projeto

```
HttpMessageSignatures.sln
└── src/
    ├── HttpMessageSignatures.Core/       ← Biblioteca compartilhada (RFC 9421 puro)
    │   ├── Models/                       ← DTOs: SignatureParams, HttpMessageContext, etc.
    │   ├── Signing/                      ← Assinatura: Signer, Providers, SignatureBaseBuilder
    │   ├── Verification/                 ← Verificação: Verifier, InputParser
    │   ├── Digest/                       ← Content-Digest (RFC 9530)
    │   └── Extensions/                   ← AddHttpMessageSigning() para DI
    ├── HttpMessageSignatures.Api/        ← Minimal API ASP.NET Core (servidor)
    └── HttpMessageSignatures.Client/     ← Console app (cliente)
```

---

## Fluxo completo

### Visão geral

```
CLIENT                                          API
  │                                              │
  │  1. Gera par de chaves ECDSA P-256           │
  │  2. Exporta chave pública → client-public-key.pem
  │                                              │
  │  3. Monta payload JSON                       │
  │  4. Calcula Content-Digest (SHA-256 do body) │
  │  5. Monta Signature Base (string canônica)   │
  │  6. Assina com chave privada                 │
  │  7. Adiciona headers à requisição            │
  │                                              │
  │──── POST /api/orders ──────────────────────▶│
  │     Headers:                                 │
  │       Content-Digest: sha-256=:abc123:       │
  │       Signature-Input: sig1=(...)            │
  │       Signature: sig1=:xyz789:               │
  │                                              │
  │                        8. Verifica Content-Digest vs body
  │                        9. Reconstrói Signature Base
  │                        10. Verifica assinatura com chave pública
  │                        11. Valida timestamp (máx 5 min)
  │                                              │
  │◀─── 201 Created ──────────────────────────── │
```

---

### Passo a passo detalhado

#### 1. Gerenciamento de chaves

O client gera um par de chaves ECDSA P-256 no primeiro run:

```
client-private-key.pem  →  fica no Client (nunca sai daqui)
client-public-key.pem   →  copiado para o diretório da API
```

A API carrega a chave pública no startup via DI e a mantém em memória para todas as verificações.

#### 2. Cálculo do Content-Digest (RFC 9530)

Antes de assinar, o client calcula o hash do body:

```
body = '{"item":"quantum-widget","quantity":3,"price":49.99}'
digest = Base64(SHA-256(body))
header = "sha-256=:" + digest + ":"
```

Esse header garante a **integridade do corpo** da requisição. Qualquer byte diferente invalida o digest — detectado ainda antes de verificar a assinatura criptográfica.

#### 3. Montagem da Signature Base (RFC 9421 §2.5)

A Signature Base é a string canônica que será efetivamente assinada. Ela é construída pelo `SignatureBaseBuilder` concatenando os valores dos componentes cobertos, um por linha, seguidos pelos parâmetros da assinatura:

```
"@method": POST
"@target-uri": http://localhost:5050/api/orders
"@authority": localhost:5050
"content-type": application/json
"content-digest": sha-256=:abc123...:
"@signature-params": ("@method" "@target-uri" "@authority" "content-type" "content-digest");created=1712345678;expires=1712345978;nonce="a1b2c3";keyid="client-demo-key-2026";alg="ecdsa-p256-sha256";tag="client-demo"
```

Componentes cobertos neste demo:

| Componente | O que protege |
|---|---|
| `@method` | Impede trocar POST por GET, etc. |
| `@target-uri` | Impede redirecionar para outro endpoint |
| `@authority` | Impede replay em outro servidor |
| `content-type` | Impede trocar o tipo do body |
| `content-digest` | Protege integridade do body |

#### 4. Assinatura

```
signatureBytes = ECDSA-P256-SHA256.Sign(UTF8(signatureBase), privateKey)
signatureBase64 = Base64(signatureBytes)
```

Os headers adicionados à requisição:

```http
Signature-Input: sig1=("@method" "@target-uri" "@authority" "content-type" "content-digest");created=1712345678;expires=1712345978;nonce="a1b2c3...";keyid="client-demo-key-2026";alg="ecdsa-p256-sha256";tag="client-demo"
Signature: sig1=:MEUCIQDx...:
Content-Digest: sha-256=:abc123...:
```

O `SigningDelegatingHandler` faz isso de forma transparente — o código da aplicação só chama `http.PostAsync(...)` normalmente.

#### 5. Verificação na API (SignatureVerificationMiddleware)

O middleware intercepta todas as rotas `/api/*` (exceto `/api/orders/health`) e executa:

```
1. Verifica presença dos headers Signature-Input e Signature
        ↓ ausentes → 401
2. Lê o body (com EnableBuffering para não consumir o stream)
3. Verifica Content-Digest
        ↓ mismatch → 401 "body was tampered with"
4. Monta HttpMessageContext (abstração neutra da mensagem)
5. Chama HttpMessageVerifier.Verify(...)
   ├── Extrai e parseia Signature-Input pelo label "sig1"
   ├── Valida idade: now - created <= 5 min
   ├── Valida clock skew: created não pode ser > 30s no futuro
   ├── Valida expiração (se presente)
   ├── Valida que o alg bate com o provider configurado
   ├── Reconstrói a Signature Base com os mesmos componentes
   └── ECDSA.Verify(signatureBase, signatureBytes, publicKey)
        ↓ inválido → 401 "Cryptographic verification failed"
6. Anexa SignatureParams ao HttpContext.Items["rfc9421.signature-params"]
7. next(context) → endpoint
```

#### 6. Resposta

O endpoint `POST /api/orders` acessa os `SignatureParams` do `HttpContext.Items` e inclui o `keyid` na resposta:

```json
{
  "orderId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "status": "created",
  "verifiedBy": "client-demo-key-2026"
}
```

---

## Como rodar

### 1. Restaurar e compilar

```bash
dotnet restore
dotnet build
```

### 2. Gerar as chaves (primeiro run do client)

```bash
cd src/HttpMessageSignatures.Client
dotnet run
```

Vai gerar `client-private-key.pem` e copiar `client-public-key.pem` para o projeto da API. A conexão vai falhar (API ainda não está rodando) — isso é esperado.

### 3. Rodar a API

Em outro terminal:

```bash
cd src/HttpMessageSignatures.Api
dotnet run
```

A API sobe em `http://localhost:5050`.

### 4. Rodar o client

```bash
cd src/HttpMessageSignatures.Client
dotnet run
```

Saída esperada:

```
→ Loading existing key pair from client-private-key.pem
→ Sending signed POST /api/orders
  (o SigningDelegatingHandler adiciona os headers automaticamente)

← Status: 201 Created
← Body:   {"orderId":"...","status":"created","verifiedBy":"client-demo-key-2026"}

✓ Request signed and verified successfully!
```

### Testando cenários de falha

**Body adulterado** — altere `ContentDigestCalculator.ComputeSha256` para retornar um hash errado. A API vai rejeitar com `Content-Digest mismatch`.

**Assinatura expirada** — mude `maxSignatureAge` no `Program.cs` da API para `TimeSpan.FromSeconds(5)` e adicione um `await Task.Delay(6000)` no client antes do `PostAsync`.

**Chave errada** — substitua `client-public-key.pem` na API por outra chave pública qualquer. A verificação criptográfica vai falhar.

**Componente não coberto** — remova `SignatureComponent.ContentDigest` da lista no client. A assinatura ainda passa, mas o Content-Digest não será coberto — demonstrando que a proteção de integridade do body é opt-in.

---

## Melhorias para produção

### Segurança

| Limitação do demo | Solução para produção |
|---|---|
| Chave privada em arquivo `.pem` | AWS Secrets Manager, Azure Key Vault, ou HSM |
| Chave pública hardcoded na API | Keystore dinâmico com lookup por `keyid` |
| Nonces gerados mas não validados | Armazenar nonces recentes em Redis e rejeitar duplicatas |
| Parser simplificado de RFC 8941 | Usar biblioteca [NSign](https://github.com/Unisys/NSign) ou implementar parser completo de Structured Fields |

### Funcionalidades

- **Lookup dinâmico de chave**: o `keyid` do `Signature-Input` deve ser usado para buscar a chave pública correta no keystore, suportando múltiplos clientes
- **Rotação de chaves**: chaves devem ter validade e o `keyid` deve incluir versão (ex: `client-key-2026-v2`)
- **Suporte a RSA-PSS**: o `RsaPssSignatureProvider` já existe no Core — basta plugar no lugar do ECDSA
- **Cobertura de response**: RFC 9421 também permite assinar respostas HTTP — útil para webhooks onde o servidor prova autoria
- **Componentes de query**: cobrir `@query-param` individualmente para proteger parâmetros específicos da URL
- **Observabilidade**: logar `keyid`, `tag`, `created` e latência de verificação para auditoria

### Estrutura de código

- Extrair `IKeyStore` com `GetPublicKey(keyId)` para desacoplar o verifier da chave estática
- Adicionar testes unitários para `SignatureBaseBuilder` com os vetores de teste do Apêndice B da RFC 9421
- Configurar `maxSignatureAge`, `coveredComponents` e `keyId` via `appsettings.json`

---

## Referências

- [RFC 9421 — HTTP Message Signatures](https://datatracker.ietf.org/doc/rfc9421/)
- [RFC 9530 — Digest Fields](https://datatracker.ietf.org/doc/rfc9530/)
- [RFC 8941 — Structured Field Values for HTTP](https://datatracker.ietf.org/doc/rfc8941/)
- [NSign — implementação completa em .NET](https://github.com/Unisys/NSign)
