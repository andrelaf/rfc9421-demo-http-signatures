namespace HttpMessageSignatures.Core.Models;

/// <summary>
/// Parâmetros que acompanham uma assinatura HTTP.
/// Conforme RFC 9421 Section 2.3 — "Signature Parameters".
///
/// Esses parâmetros são serializados no header Signature-Input e fazem parte
/// da signature base (a string que é efetivamente assinada).
/// </summary>
public sealed class SignatureParams
{
    /// <summary>
    /// Identificador da chave usada para assinar.
    /// O servidor usa esse valor para selecionar a chave pública correta na verificação.
    /// </summary>
    public required string KeyId { get; init; }

    /// <summary>
    /// Identificador do algoritmo de assinatura.
    /// Valores definidos na RFC 9421: rsa-pss-sha512, ecdsa-p256-sha256, hmac-sha256, ed25519.
    /// </summary>
    public required string Algorithm { get; init; }

    /// <summary>
    /// Timestamp de criação da assinatura (Unix time).
    /// Usado pelo verificador para checar se a assinatura não é muito antiga.
    /// </summary>
    public DateTimeOffset Created { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Timestamp de expiração da assinatura (opcional).
    /// Após esse momento, a assinatura deve ser rejeitada.
    /// </summary>
    public DateTimeOffset? Expires { get; init; }

    /// <summary>
    /// Nonce para proteção contra replay attacks (opcional mas recomendado).
    /// </summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// Tag da aplicação — permite ao verificador filtrar assinaturas por contexto.
    /// Ex: "client-request", "webhook-delivery", etc.
    /// </summary>
    public string? Tag { get; init; }

    /// <summary>
    /// Lista de componentes da mensagem HTTP cobertos pela assinatura.
    /// Esses componentes compõem a signature base.
    /// </summary>
    public required List<string> CoveredComponents { get; init; }
}
