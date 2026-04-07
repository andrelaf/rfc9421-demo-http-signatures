namespace HttpMessageSignatures.Core.Signing;

/// <summary>
/// DelegatingHandler que assina automaticamente todas as requisições
/// feitas pelo HttpClient configurado.
///
/// Integra-se ao pipeline do HttpClient via DI:
///   builder.Services
///     .AddHttpClient("MyApi")
///     .AddHttpMessageHandler(sp => new SigningDelegatingHandler(signer));
/// </summary>
public sealed class SigningDelegatingHandler : DelegatingHandler
{
    private readonly HttpMessageSigner _signer;

    public SigningDelegatingHandler(HttpMessageSigner signer)
    {
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        await _signer.SignAsync(request);
        return await base.SendAsync(request, cancellationToken);
    }
}
