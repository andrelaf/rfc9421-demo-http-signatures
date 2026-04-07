using System.Security.Cryptography;
using System.Text;

namespace HttpMessageSignatures.Core.Digest;

/// <summary>
/// Calcula e verifica o header Content-Digest conforme RFC 9530.
///
/// O Content-Digest é um hash do body da mensagem HTTP. Quando incluído
/// nos covered components da assinatura (RFC 9421), garante que o body
/// não foi alterado após a assinatura.
///
/// Formato: sha-256=:base64-encoded-hash:
/// </summary>
public static class ContentDigestCalculator
{
    /// <summary>
    /// Calcula o Content-Digest usando SHA-256.
    /// </summary>
    public static string ComputeSha256(string content)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(content));
        return $"sha-256=:{Convert.ToBase64String(hash)}:";
    }

    /// <summary>
    /// Calcula o Content-Digest usando SHA-512.
    /// </summary>
    public static string ComputeSha512(string content)
    {
        var hash = SHA512.HashData(Encoding.UTF8.GetBytes(content));
        return $"sha-512=:{Convert.ToBase64String(hash)}:";
    }

    /// <summary>
    /// Verifica se o Content-Digest informado corresponde ao conteúdo.
    /// </summary>
    public static bool Verify(string contentDigestHeader, string content)
    {
        // Detectar o algoritmo pelo prefixo
        if (contentDigestHeader.StartsWith("sha-512=", StringComparison.OrdinalIgnoreCase))
        {
            var expected = ComputeSha512(content);
            return string.Equals(expected, contentDigestHeader, StringComparison.Ordinal);
        }

        // Default: SHA-256
        var expectedSha256 = ComputeSha256(content);
        return string.Equals(expectedSha256, contentDigestHeader, StringComparison.Ordinal);
    }
}
