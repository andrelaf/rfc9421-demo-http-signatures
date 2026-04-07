using HttpMessageSignatures.Core.Signing;
using Microsoft.Extensions.DependencyInjection;

namespace HttpMessageSignatures.Core.Extensions;

/// <summary>
/// Extensões para registrar assinatura HTTP no container de DI.
/// </summary>
public static class HttpMessageSigningExtensions
{
    /// <summary>
    /// Adiciona um DelegatingHandler de assinatura ao HttpClient named/typed.
    /// Usa o HttpMessageSigner registrado no DI.
    ///
    /// Exemplo:
    ///   services.AddSingleton(signer);
    ///   services.AddHttpClient("api").AddHttpMessageSigning();
    /// </summary>
    public static IHttpClientBuilder AddHttpMessageSigning(this IHttpClientBuilder builder)
    {
        builder.Services.AddTransient<SigningDelegatingHandler>();
        return builder.AddHttpMessageHandler<SigningDelegatingHandler>();
    }
}
