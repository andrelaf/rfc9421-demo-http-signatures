namespace HttpMessageSignatures.Core.Signing;

/// <summary>
/// Contrato para providers de assinatura e verificação.
/// Cada implementação encapsula um algoritmo específico (ECDSA, RSA-PSS, HMAC, Ed25519).
/// </summary>
public interface ISignatureProvider : IDisposable
{
    /// <summary>
    /// Identificador do algoritmo conforme RFC 9421 Section 3.3.
    /// Ex: "ecdsa-p256-sha256", "rsa-pss-sha512", "hmac-sha256", "ed25519"
    /// </summary>
    string AlgorithmIdentifier { get; }

    /// <summary>Assina os dados com a chave privada.</summary>
    byte[] Sign(byte[] data);

    /// <summary>Verifica a assinatura com a chave pública.</summary>
    bool Verify(byte[] data, byte[] signature);
}
