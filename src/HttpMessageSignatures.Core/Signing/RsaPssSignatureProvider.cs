using System.Security.Cryptography;

namespace HttpMessageSignatures.Core.Signing;

/// <summary>
/// Provider de assinatura usando RSA-PSS com SHA-512.
/// Algoritmo RFC 9421: rsa-pss-sha512 (Section 3.3.1)
///
/// O PSS (Probabilistic Signature Scheme) é a variante recomendada do RSA
/// para assinaturas. Diferente do PKCS#1 v1.5, é probabilístico (usa salt
/// aleatório), gerando assinaturas diferentes para a mesma mensagem.
/// </summary>
public sealed class RsaPssSignatureProvider : ISignatureProvider
{
    private readonly RSA _key;
    private static readonly RSASignaturePadding Padding = RSASignaturePadding.Pss;

    public string AlgorithmIdentifier => "rsa-pss-sha512";

    public RsaPssSignatureProvider(RSA key)
    {
        _key = key ?? throw new ArgumentNullException(nameof(key));
    }

    /// <summary>
    /// Gera um novo par de chaves RSA.
    /// </summary>
    /// <param name="keySizeInBits">
    /// Tamanho da chave: 2048 (mínimo), 3072 (recomendado NIST pós-2030), 4096 (conservador).
    /// </param>
    public static (RsaPssSignatureProvider Signer, RSA PublicKey) GenerateKeyPair(int keySizeInBits = 2048)
    {
        var privateKey = RSA.Create(keySizeInBits);
        var publicKeyOnly = RSA.Create();
        publicKeyOnly.ImportParameters(privateKey.ExportParameters(includePrivateParameters: false));
        return (new RsaPssSignatureProvider(privateKey), publicKeyOnly);
    }

    public static RsaPssSignatureProvider FromPublicKeyPem(string pem)
    {
        var key = RSA.Create();
        key.ImportFromPem(pem);
        return new RsaPssSignatureProvider(key);
    }

    public static RsaPssSignatureProvider FromPrivateKeyPem(string pem)
    {
        var key = RSA.Create();
        key.ImportFromPem(pem);
        return new RsaPssSignatureProvider(key);
    }

    public string ExportPublicKeyPem() => _key.ExportSubjectPublicKeyInfoPem();

    public byte[] Sign(byte[] data) =>
        _key.SignData(data, HashAlgorithmName.SHA512, Padding);

    public bool Verify(byte[] data, byte[] signature) =>
        _key.VerifyData(data, signature, HashAlgorithmName.SHA512, Padding);

    public void Dispose() => _key.Dispose();
}
