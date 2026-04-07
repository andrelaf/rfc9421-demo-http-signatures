using System.Text;
using HttpMessageSignatures.Core.Digest;
using HttpMessageSignatures.Core.Models;

namespace HttpMessageSignatures.Core.Signing;

/// <summary>
/// Assina mensagens HTTP conforme RFC 9421.
///
/// Responsabilidades:
/// 1. Calcular Content-Digest do body (RFC 9530) quando aplicável
/// 2. Montar o HttpMessageContext a partir do HttpRequestMessage
/// 3. Construir a signature base canônica
/// 4. Assinar com o provider configurado
/// 5. Adicionar headers Signature-Input e Signature à requisição
/// </summary>
public sealed class HttpMessageSigner
{
    private readonly ISignatureProvider _provider;
    private readonly string _keyId;
    private readonly List<string> _coveredComponents;
    private readonly string _signatureName;
    private readonly string? _tag;
    private readonly TimeSpan? _expiresAfter;

    public HttpMessageSigner(
        ISignatureProvider provider,
        string keyId,
        List<string> coveredComponents,
        string signatureName = "sig1",
        string? tag = null,
        TimeSpan? expiresAfter = null)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _keyId = keyId;
        _coveredComponents = coveredComponents;
        _signatureName = signatureName;
        _tag = tag;
        _expiresAfter = expiresAfter;
    }

    /// <summary>
    /// Assina o HttpRequestMessage, adicionando os headers necessários.
    /// </summary>
    public async Task SignAsync(HttpRequestMessage request)
    {
        ArgumentNullException.ThrowIfNull(request.RequestUri);

        // 1. Content-Digest (se body presente e componente coberto)
        string? body = null;
        if (request.Content is not null)
        {
            body = await request.Content.ReadAsStringAsync();

            if (_coveredComponents.Contains(SignatureComponent.ContentDigest))
            {
                var digest = ContentDigestCalculator.ComputeSha256(body);
                request.Headers.TryAddWithoutValidation("content-digest", digest);
            }
        }

        // 2. Montar contexto
        var context = await HttpMessageContext.FromRequestAsync(request);

        // 3. Criar parâmetros
        var now = DateTimeOffset.UtcNow;
        var signatureParams = new SignatureParams
        {
            KeyId = _keyId,
            Algorithm = _provider.AlgorithmIdentifier,
            Created = now,
            Expires = _expiresAfter.HasValue ? now.Add(_expiresAfter.Value) : null,
            Nonce = Guid.NewGuid().ToString("N"),
            Tag = _tag,
            CoveredComponents = _coveredComponents,
        };

        // 4. Construir signature base
        var signatureBase = SignatureBaseBuilder.Build(context, signatureParams);

        // 5. Assinar
        var signatureBytes = _provider.Sign(Encoding.UTF8.GetBytes(signatureBase));
        var signatureBase64 = Convert.ToBase64String(signatureBytes);

        // 6. Adicionar headers (RFC 9421 §4.1)
        var signatureInput = SignatureBaseBuilder.SerializeSignatureInput(signatureParams);
        request.Headers.TryAddWithoutValidation("signature-input", $"{_signatureName}={signatureInput}");
        request.Headers.TryAddWithoutValidation("signature", $"{_signatureName}=:{signatureBase64}:");
    }
}
