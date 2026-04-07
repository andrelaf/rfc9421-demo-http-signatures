namespace HttpMessageSignatures.Core.Models;

/// <summary>
/// Resultado da verificação de uma assinatura HTTP.
/// Carrega o status, mensagem de erro (se houver) e os parâmetros verificados.
/// </summary>
public sealed record VerificationResult
{
    public bool IsValid { get; init; }
    public string? Error { get; init; }
    public SignatureParams? Params { get; init; }

    public static VerificationResult Success(SignatureParams parameters) =>
        new() { IsValid = true, Params = parameters };

    public static VerificationResult Failure(string error) =>
        new() { IsValid = false, Error = error };
}
