using System.Text;
using System.Text.Json;
using HttpMessageSignatures.Core.Extensions;
using HttpMessageSignatures.Core.Models;
using HttpMessageSignatures.Core.Signing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

// ─────────────────────────────────────────────────────────────────────
//  RFC 9421 — Console Client Demo
// ─────────────────────────────────────────────────────────────────────
//  Este client:
//   1. Gera (ou carrega) um par de chaves ECDSA P-256
//   2. Exporta a chave pública para a API consumir
//   3. Configura um HttpClient com o DelegatingHandler de assinatura
//   4. Envia uma requisição assinada para a API
// ─────────────────────────────────────────────────────────────────────

const string PrivateKeyPath = "client-private-key.pem";
const string PublicKeyPath  = "client-public-key.pem";
const string ApiUrl         = "http://localhost:5050";

// 1. Gerar ou carregar o par de chaves
EcdsaP256SignatureProvider signer;

if (File.Exists(PrivateKeyPath))
{
    Console.WriteLine($"→ Loading existing key pair from {PrivateKeyPath}");
    signer = EcdsaP256SignatureProvider.FromPrivateKeyPem(File.ReadAllText(PrivateKeyPath));
}
else
{
    Console.WriteLine("→ Generating new ECDSA P-256 key pair");
    var (newSigner, _) = EcdsaP256SignatureProvider.GenerateKeyPair();
    signer = newSigner;

    File.WriteAllText(PrivateKeyPath, signer.ExportPrivateKeyPem());
    File.WriteAllText(PublicKeyPath,  signer.ExportPublicKeyPem());

    // Também copiar a public key para o diretório da API
    var apiPubKeyPath = Path.Combine(
        "..", "HttpMessageSignatures.Api", "client-public-key.pem");
    if (Directory.Exists(Path.GetDirectoryName(apiPubKeyPath)!))
        File.WriteAllText(apiPubKeyPath, signer.ExportPublicKeyPem());

    Console.WriteLine($"  Private key saved to: {PrivateKeyPath}");
    Console.WriteLine($"  Public key saved to:  {PublicKeyPath}");
    Console.WriteLine($"  Public key copied to API project as well.");
}

// 2. Configurar DI com HttpClient + SigningHandler
var host = Host.CreateDefaultBuilder()
    .ConfigureServices(services =>
    {
        // Registrar o signer com os covered components desejados
        services.AddSingleton(new HttpMessageSigner(
            provider: signer,
            keyId: "client-demo-key-2026",
            coveredComponents: new List<string>
            {
                SignatureComponent.Method,
                SignatureComponent.TargetUri,
                SignatureComponent.Authority,
                SignatureComponent.ContentType,
                SignatureComponent.ContentDigest,
            },
            signatureName: "sig1",
            tag: "client-demo",
            expiresAfter: TimeSpan.FromMinutes(5)));

        // HttpClient named com assinatura automática
        services
            .AddHttpClient("SignedApi", client =>
            {
                client.BaseAddress = new Uri(ApiUrl);
                client.DefaultRequestHeaders.Add("User-Agent", "RFC9421-Demo-Client/1.0");
            })
            .AddHttpMessageSigning();
    })
    .Build();

var httpClientFactory = host.Services.GetRequiredService<IHttpClientFactory>();
var http = httpClientFactory.CreateClient("SignedApi");

// 3. Enviar requisição assinada
Console.WriteLine("\n→ Sending signed POST /api/orders");
Console.WriteLine("  (o SigningDelegatingHandler adiciona os headers automaticamente)\n");

var payload = new
{
    item = "quantum-widget",
    quantity = 3,
    price = 49.99m,
};

var requestBody = JsonSerializer.Serialize(payload);
var content = new StringContent(requestBody, Encoding.UTF8, "application/json");

try
{
    var response = await http.PostAsync("/api/orders", content);
    var responseBody = await response.Content.ReadAsStringAsync();

    Console.WriteLine($"← Status: {(int)response.StatusCode} {response.StatusCode}");
    Console.WriteLine($"← Body:   {responseBody}");

    if (response.IsSuccessStatusCode)
        Console.WriteLine("\n✓ Request signed and verified successfully!");
    else
        Console.WriteLine("\n✗ Server rejected the request.");
}
catch (HttpRequestException ex)
{
    Console.WriteLine($"✗ Connection error: {ex.Message}");
    Console.WriteLine($"  Make sure the API is running at {ApiUrl}");
}

signer.Dispose();
