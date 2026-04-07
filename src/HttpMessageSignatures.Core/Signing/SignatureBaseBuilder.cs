using System.Text;
using HttpMessageSignatures.Core.Models;

namespace HttpMessageSignatures.Core.Signing;

/// <summary>
/// Constrói a Signature Base conforme RFC 9421 Section 2.5.
///
/// A signature base é a representação canônica dos componentes cobertos
/// pela assinatura. É essa string que será efetivamente assinada/verificada.
///
/// Formato de cada linha:
///   "component-id": value
///
/// Última linha sempre:
///   "@signature-params": (serialized params)
/// </summary>
public static class SignatureBaseBuilder
{
    /// <summary>
    /// Monta a signature base a partir do contexto HTTP e dos parâmetros.
    /// </summary>
    public static string Build(HttpMessageContext context, SignatureParams signatureParams)
    {
        var lines = new List<string>(signatureParams.CoveredComponents.Count + 1);

        foreach (var component in signatureParams.CoveredComponents)
        {
            var value = ResolveComponentValue(context, component);
            lines.Add($"\"{component}\": {value}");
        }

        var serializedInput = SerializeSignatureInput(signatureParams);
        lines.Add($"\"@signature-params\": {serializedInput}");

        return string.Join('\n', lines);
    }

    /// <summary>
    /// Serializa os parâmetros para o header Signature-Input.
    /// Formato: ("comp1" "comp2");created=ts;keyid="id";alg="algo"
    /// </summary>
    public static string SerializeSignatureInput(SignatureParams p)
    {
        var components = string.Join(' ', p.CoveredComponents.Select(c => $"\"{c}\""));
        var sb = new StringBuilder($"({components})");

        sb.Append($";created={p.Created.ToUnixTimeSeconds()}");

        if (p.Expires.HasValue)
            sb.Append($";expires={p.Expires.Value.ToUnixTimeSeconds()}");

        if (p.Nonce is not null)
            sb.Append($";nonce=\"{p.Nonce}\"");

        sb.Append($";keyid=\"{p.KeyId}\"");
        sb.Append($";alg=\"{p.Algorithm}\"");

        if (p.Tag is not null)
            sb.Append($";tag=\"{p.Tag}\"");

        return sb.ToString();
    }

    /// <summary>
    /// Resolve o valor de um componente da mensagem HTTP.
    /// </summary>
    private static string ResolveComponentValue(HttpMessageContext context, string component)
    {
        return component switch
        {
            SignatureComponent.Method    => context.Method.ToUpperInvariant(),
            SignatureComponent.TargetUri => context.RequestUri.AbsoluteUri,
            SignatureComponent.Authority => context.RequestUri.Authority.ToLowerInvariant(),
            SignatureComponent.Scheme    => context.RequestUri.Scheme.ToLowerInvariant(),
            SignatureComponent.Path      => context.RequestUri.AbsolutePath,
            SignatureComponent.Query     => context.RequestUri.Query.Length > 0
                                             ? context.RequestUri.Query
                                             : "?",

            // Regular components → headers
            _ => context.Headers.TryGetValue(component, out var value)
                ? value
                : throw new InvalidOperationException(
                    $"Component '{component}' not found in message headers.")
        };
    }
}
