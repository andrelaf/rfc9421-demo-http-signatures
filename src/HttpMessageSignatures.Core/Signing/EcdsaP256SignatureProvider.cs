using System.Security.Cryptography;

namespace HttpMessageSignatures.Core.Signing;

/// <summary>
/// Provider de assinatura usando ECDSA com curva P-256 e SHA-256.
/// Algoritmo RFC 9421: ecdsa-p256-sha256 (Section 3.3.3)
///
/// Produz assinaturas compactas (~64 bytes) e é significativamente mais
/// rápido que RSA para operações de assinatura.
/// </summary>
public sealed class EcdsaP256SignatureProvider : ISignatureProvider
{
    private readonly ECDsa _key;

    public string AlgorithmIdentifier => "ecdsa-p256-sha256";

    public EcdsaP256SignatureProvider(ECDsa key)
    {
        _key = key ?? throw new ArgumentNullException(nameof(key));
    }

    /// <summary>
    /// Gera um novo par de chaves ECDSA P-256.
    /// Retorna o signer (com chave privada) e a chave pública separada para o verificador.
    /// </summary>
    public static (EcdsaP256SignatureProvider Signer, ECDsa PublicKey) GenerateKeyPair()
    {
        var privateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKeyOnly = ECDsa.Create(privateKey.ExportParameters(includePrivateParameters: false));
        return (new EcdsaP256SignatureProvider(privateKey), publicKeyOnly);
    }

    /// <summary>
    /// Cria um provider somente para verificação a partir de uma chave pública PEM.
    /// </summary>
    public static EcdsaP256SignatureProvider FromPublicKeyPem(string pem)
    {
        var key = ECDsa.Create();
        key.ImportFromPem(pem);
        return new EcdsaP256SignatureProvider(key);
    }

    /// <summary>
    /// Cria um provider para assinatura a partir de uma chave privada PEM.
    /// </summary>
    public static EcdsaP256SignatureProvider FromPrivateKeyPem(string pem)
    {
        var key = ECDsa.Create();
        key.ImportFromPem(pem);
        return new EcdsaP256SignatureProvider(key);
    }

    /// <summary>Exporta a chave pública em formato PEM.</summary>
    public string ExportPublicKeyPem() => _key.ExportSubjectPublicKeyInfoPem();

    /// <summary>Exporta a chave privada em formato PEM (proteger adequadamente!).</summary>
    public string ExportPrivateKeyPem() => _key.ExportECPrivateKeyPem();

    public byte[] Sign(byte[] data) =>
        _key.SignData(data, HashAlgorithmName.SHA256);

    public bool Verify(byte[] data, byte[] signature) =>
        _key.VerifyData(data, signature, HashAlgorithmName.SHA256);

    public void Dispose() => _key.Dispose();
}
