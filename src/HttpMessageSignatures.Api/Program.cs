using System.Security.Cryptography;
using HttpMessageSignatures.Api.Endpoints;
using HttpMessageSignatures.Api.Middleware;
using HttpMessageSignatures.Core.Signing;
using HttpMessageSignatures.Core.Verification;

var builder = WebApplication.CreateBuilder(args);

// ─────────────────────────────────────────────────────────────────────
// DI: carregar a chave pública do client e registrar o verifier
// ─────────────────────────────────────────────────────────────────────
// Em produção:
//   - A chave pública fica num keystore (AWS Secrets Manager, Azure Key Vault, etc.)
//   - Você pode ter múltiplas chaves identificadas por keyid
//   - A seleção da chave correta acontece DENTRO do verifier baseado no keyid do header
//
// Para esta demo: lemos a chave de um arquivo PEM gerado pelo client no primeiro run.

builder.Services.AddSingleton<ISignatureProvider>(_ =>
{
    const string pubKeyPath = "client-public-key.pem";

    if (!File.Exists(pubKeyPath))
    {
        // Fallback: gera chaves temporárias e avisa
        // (em produção isso NÃO deve acontecer — a chave pública deve estar pré-provisionada)
        Console.WriteLine($"⚠ {pubKeyPath} not found. Generating temporary key pair for demo.");
        Console.WriteLine("  Run the Client project first to generate a persistent key pair.");

        var (signer, _) = EcdsaP256SignatureProvider.GenerateKeyPair();
        return signer;
    }

    var pem = File.ReadAllText(pubKeyPath);
    return EcdsaP256SignatureProvider.FromPublicKeyPem(pem);
});

builder.Services.AddSingleton<HttpMessageVerifier>(sp =>
{
    var provider = sp.GetRequiredService<ISignatureProvider>();
    return new HttpMessageVerifier(provider, maxSignatureAge: TimeSpan.FromMinutes(5));
});

var app = builder.Build();

// ─────────────────────────────────────────────────────────────────────
// Pipeline: verifica assinaturas apenas em rotas /api/*
// ─────────────────────────────────────────────────────────────────────
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/api") &&
           !ctx.Request.Path.StartsWithSegments("/api/orders/health"),
    branch => branch.UseSignatureVerification());

// Endpoints
app.MapGet("/", () => "HTTP Message Signatures (RFC 9421) Demo API");
app.MapOrdersEndpoints();

app.Run();
