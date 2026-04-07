namespace HttpMessageSignatures.Core.Models;

/// <summary>
/// Representação agnóstica de uma mensagem HTTP para fins de assinatura/verificação.
/// Abstrai tanto HttpRequestMessage (client) quanto HttpRequest (ASP.NET Core).
/// </summary>
public sealed class HttpMessageContext
{
    /// <summary>Método HTTP: GET, POST, PUT, DELETE, etc.</summary>
    public required string Method { get; init; }

    /// <summary>URI completa da requisição.</summary>
    public required Uri RequestUri { get; init; }

    /// <summary>Headers da mensagem (chave lowercase → valor).</summary>
    public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Body da mensagem (se aplicável).</summary>
    public string? Body { get; init; }

    /// <summary>
    /// Factory method para criar contexto a partir de um HttpRequestMessage.
    /// Usado no lado do client (DelegatingHandler).
    /// </summary>
    public static async Task<HttpMessageContext> FromRequestAsync(HttpRequestMessage request)
    {
        string? body = null;
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Headers da requisição
        foreach (var header in request.Headers)
            headers[header.Key.ToLowerInvariant()] = string.Join(", ", header.Value);

        // Headers do content
        if (request.Content is not null)
        {
            body = await request.Content.ReadAsStringAsync();
            foreach (var header in request.Content.Headers)
                headers[header.Key.ToLowerInvariant()] = string.Join(", ", header.Value);
        }

        return new HttpMessageContext
        {
            Method = request.Method.Method,
            RequestUri = request.RequestUri!,
            Headers = headers,
            Body = body,
        };
    }
}
