using System.Text;
using HttpMessageSignatures.Core.Models;
using HttpMessageSignatures.Core.Signing;

namespace HttpMessageSignatures.Core.Verification;

/// <summary>
/// Verifica assinaturas de mensagens HTTP conforme RFC 9421 Section 3.2.
///
/// Etapas da verificação:
/// 1. Extrair Signature-Input e Signature pelo label
/// 2. Parsear os parâmetros do Signature-Input
/// 3. Validar timestamp (created) e expiração (expires)
/// 4. Reconstruir a signature base com os mesmos covered components
/// 5. Verificar a assinatura criptograficamente
/// </summary>
public sealed class HttpMessageVerifier
{
    private readonly ISignatureProvider _provider;
    private readonly TimeSpan _maxSignatureAge;

    /// <param name="provider">Provider com a chave pública para verificação.</param>
    /// <param name="maxSignatureAge">Idade máxima aceita para uma assinatura. Default: 5 minutos.</param>
    public HttpMessageVerifier(ISignatureProvider provider, TimeSpan? maxSignatureAge = null)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _maxSignatureAge = maxSignatureAge ?? TimeSpan.FromMinutes(5);
    }

    /// <summary>
    /// Verifica a assinatura de uma mensagem HTTP.
    /// </summary>
    /// <param name="context">Contexto da mensagem recebida (method, URI, headers, body).</param>
    /// <param name="signatureInputHeader">Valor do header Signature-Input.</param>
    /// <param name="signatureHeader">Valor do header Signature.</param>
    /// <param name="signatureName">Label da assinatura a verificar (default: "sig1").</param>
    public VerificationResult Verify(
        HttpMessageContext context,
        string signatureInputHeader,
        string signatureHeader,
        string signatureName = "sig1")
    {
        try
        {
            // 1. Extrair Signature-Input para o label
            var signatureInput = SignatureInputParser.ExtractByLabel(signatureInputHeader, signatureName);
            if (signatureInput is null)
                return VerificationResult.Failure(
                    $"Signature-Input not found for label '{signatureName}'.");

            // 2. Parsear parâmetros
            var signatureParams = SignatureInputParser.Parse(signatureInput, _provider.AlgorithmIdentifier);

            // 3. Validar timestamp
            var age = DateTimeOffset.UtcNow - signatureParams.Created;
            if (age > _maxSignatureAge)
                return VerificationResult.Failure(
                    $"Signature too old. Age: {age.TotalSeconds:F0}s, max: {_maxSignatureAge.TotalSeconds:F0}s.");

            if (age < TimeSpan.FromSeconds(-30)) // Clock skew tolerance
                return VerificationResult.Failure(
                    "Signature created in the future (clock skew > 30s).");

            // 4. Validar expiração
            if (signatureParams.Expires.HasValue && DateTimeOffset.UtcNow > signatureParams.Expires.Value)
                return VerificationResult.Failure(
                    "Signature has expired.");

            // 5. Validar algoritmo
            if (!string.Equals(signatureParams.Algorithm, _provider.AlgorithmIdentifier, StringComparison.Ordinal))
                return VerificationResult.Failure(
                    $"Algorithm mismatch. Expected: {_provider.AlgorithmIdentifier}, got: {signatureParams.Algorithm}.");

            // 6. Reconstruir signature base
            var signatureBase = SignatureBaseBuilder.Build(context, signatureParams);

            // 7. Extrair e decodificar a assinatura
            var signatureValue = SignatureInputParser.ExtractByLabel(signatureHeader, signatureName);
            if (signatureValue is null)
                return VerificationResult.Failure(
                    $"Signature not found for label '{signatureName}'.");

            var base64 = signatureValue.Trim(':');
            var signatureBytes = Convert.FromBase64String(base64);

            // 8. Verificação criptográfica
            var isValid = _provider.Verify(Encoding.UTF8.GetBytes(signatureBase), signatureBytes);

            return isValid
                ? VerificationResult.Success(signatureParams)
                : VerificationResult.Failure("Cryptographic verification failed.");
        }
        catch (FormatException ex)
        {
            return VerificationResult.Failure($"Invalid signature format: {ex.Message}");
        }
        catch (Exception ex)
        {
            return VerificationResult.Failure($"Verification error: {ex.Message}");
        }
    }
}
