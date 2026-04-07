using HttpMessageSignatures.Core.Digest;
using HttpMessageSignatures.Core.Models;
using HttpMessageSignatures.Core.Verification;

namespace HttpMessageSignatures.Api.Middleware;

/// <summary>
/// Middleware ASP.NET Core que verifica a assinatura HTTP das requisições
/// recebidas antes de encaminhar para os endpoints.
///
/// Em caso de falha, retorna 401 Unauthorized com um corpo JSON descrevendo o erro.
/// Em caso de sucesso, anexa os SignatureParams ao HttpContext.Items para que
/// os endpoints possam inspecionar (keyid, tag, etc).
/// </summary>
public sealed class SignatureVerificationMiddleware
{
    public const string SignatureParamsKey = "rfc9421.signature-params";

    private readonly RequestDelegate _next;
    private readonly HttpMessageVerifier _verifier;
    private readonly ILogger<SignatureVerificationMiddleware> _logger;

    public SignatureVerificationMiddleware(
        RequestDelegate next,
        HttpMessageVerifier verifier,
        ILogger<SignatureVerificationMiddleware> logger)
    {
        _next = next;
        _verifier = verifier;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // 1. Verificar presença dos headers obrigatórios
        if (!context.Request.Headers.TryGetValue("Signature-Input", out var signatureInput) ||
            !context.Request.Headers.TryGetValue("Signature", out var signature))
        {
            await WriteUnauthorizedAsync(context, "Missing Signature or Signature-Input header.");
            return;
        }

        // 2. Habilitar buffering para podermos ler o body e ainda passar adiante
        context.Request.EnableBuffering();

        string body = string.Empty;
        if (context.Request.ContentLength > 0)
        {
            using var reader = new StreamReader(
                context.Request.Body,
                leaveOpen: true);
            body = await reader.ReadToEndAsync();
            context.Request.Body.Position = 0;
        }

        // 3. Verificar Content-Digest se presente
        if (context.Request.Headers.TryGetValue("Content-Digest", out var contentDigest))
        {
            if (!ContentDigestCalculator.Verify(contentDigest.ToString(), body))
            {
                await WriteUnauthorizedAsync(context, "Content-Digest mismatch: body was tampered with.");
                return;
            }
        }

        // 4. Montar contexto da mensagem
        var messageContext = BuildContext(context, body);

        // 5. Verificar a assinatura
        var result = _verifier.Verify(
            messageContext,
            signatureInput.ToString(),
            signature.ToString());

        if (!result.IsValid)
        {
            _logger.LogWarning("Signature verification failed: {Error}", result.Error);
            await WriteUnauthorizedAsync(context, result.Error ?? "Signature verification failed.");
            return;
        }

        // 6. Armazenar os parâmetros para uso nos endpoints
        context.Items[SignatureParamsKey] = result.Params;

        _logger.LogInformation(
            "Signature verified successfully. KeyId: {KeyId}, Tag: {Tag}",
            result.Params?.KeyId,
            result.Params?.Tag);

        await _next(context);
    }

    private static HttpMessageContext BuildContext(HttpContext httpContext, string body)
    {
        var request = httpContext.Request;

        var uri = new Uri($"{request.Scheme}://{request.Host}{request.PathBase}{request.Path}{request.QueryString}");

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in request.Headers)
            headers[header.Key.ToLowerInvariant()] = header.Value.ToString();

        return new HttpMessageContext
        {
            Method = request.Method,
            RequestUri = uri,
            Headers = headers,
            Body = body,
        };
    }

    private static async Task WriteUnauthorizedAsync(HttpContext context, string error)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new { error });
    }
}

/// <summary>
/// Extension method para registrar o middleware no pipeline.
/// </summary>
public static class SignatureVerificationMiddlewareExtensions
{
    public static IApplicationBuilder UseSignatureVerification(this IApplicationBuilder app) =>
        app.UseMiddleware<SignatureVerificationMiddleware>();
}
