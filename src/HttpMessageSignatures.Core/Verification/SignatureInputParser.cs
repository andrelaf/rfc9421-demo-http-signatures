using HttpMessageSignatures.Core.Models;

namespace HttpMessageSignatures.Core.Verification;

/// <summary>
/// Parser do header Signature-Input conforme RFC 9421 Section 4.1.
///
/// O Signature-Input é um Structured Field do tipo Dictionary (RFC 8941).
/// Cada entry tem um label e um Inner List com os covered components + parâmetros.
///
/// Exemplo:
///   sig1=("@method" "@target-uri" "content-digest");created=1712345678;keyid="my-key";alg="ecdsa-p256-sha256"
///
/// NOTA: Esta é uma implementação simplificada. Em produção, use um parser
/// completo de Structured Fields (RFC 8941).
/// </summary>
public static class SignatureInputParser
{
    /// <summary>
    /// Extrai o valor associado a um label no header.
    /// Ex: Para "sig1=(...)" com label "sig1", retorna "(...)".
    /// </summary>
    public static string? ExtractByLabel(string headerValue, string label)
    {
        var prefix = $"{label}=";
        var idx = headerValue.IndexOf(prefix, StringComparison.Ordinal);
        if (idx < 0) return null;

        return headerValue[(idx + prefix.Length)..].Trim();
    }

    /// <summary>
    /// Parseia o Signature-Input em um SignatureParams.
    /// </summary>
    public static SignatureParams Parse(string input, string? defaultAlgorithm = null)
    {
        // 1. Extrair covered components entre ( )
        var componentsStart = input.IndexOf('(');
        var componentsEnd = input.IndexOf(')');

        if (componentsStart < 0 || componentsEnd < 0 || componentsEnd <= componentsStart)
            throw new FormatException("Invalid Signature-Input: missing component list.");

        var componentsStr = input[(componentsStart + 1)..componentsEnd];
        var components = componentsStr
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Select(c => c.Trim('"'))
            .ToList();

        // 2. Extrair parâmetros após o )
        var paramsSection = input[(componentsEnd + 1)..];

        return new SignatureParams
        {
            CoveredComponents = components,
            KeyId = ExtractStringParam(paramsSection, "keyid") ?? "unknown",
            Algorithm = ExtractStringParam(paramsSection, "alg") ?? defaultAlgorithm ?? "unknown",
            Created = DateTimeOffset.FromUnixTimeSeconds(
                long.Parse(ExtractRawParam(paramsSection, "created") ?? "0")),
            Expires = ExtractRawParam(paramsSection, "expires") is { } exp
                ? DateTimeOffset.FromUnixTimeSeconds(long.Parse(exp))
                : null,
            Nonce = ExtractStringParam(paramsSection, "nonce"),
            Tag = ExtractStringParam(paramsSection, "tag"),
        };
    }

    /// <summary>
    /// Extrai um parâmetro string (entre aspas): ;keyid="value"
    /// </summary>
    private static string? ExtractStringParam(string input, string name)
    {
        var key = $";{name}=\"";
        var idx = input.IndexOf(key, StringComparison.Ordinal);
        if (idx < 0) return null;

        var start = idx + key.Length;
        var end = input.IndexOf('"', start);
        return end > start ? input[start..end] : null;
    }

    /// <summary>
    /// Extrai um parâmetro raw (sem aspas): ;created=1712345678
    /// </summary>
    private static string? ExtractRawParam(string input, string name)
    {
        var key = $";{name}=";
        var idx = input.IndexOf(key, StringComparison.Ordinal);
        if (idx < 0) return null;

        var start = idx + key.Length;
        if (start >= input.Length) return null;

        // Se começa com aspas, delegar para ExtractStringParam
        if (input[start] == '"')
            return ExtractStringParam(input, name);

        // Senão, ler até o próximo ; ou fim
        var end = input.IndexOf(';', start);
        return end > 0 ? input[start..end] : input[start..];
    }
}
