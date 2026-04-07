namespace HttpMessageSignatures.Core.Models;

/// <summary>
/// Identificadores dos componentes de mensagem HTTP cobertos pela assinatura.
/// Conforme RFC 9421 Section 2 — "HTTP Message Components".
///
/// Derived Components (@-prefixed) são extraídos da estrutura da requisição.
/// Regular Components são headers HTTP padrão.
/// </summary>
public static class SignatureComponent
{
    // ── Derived Components (RFC 9421 §2.2) ──────────────────────────────
    public const string Method       = "@method";
    public const string TargetUri    = "@target-uri";
    public const string Authority    = "@authority";
    public const string Scheme       = "@scheme";
    public const string Path         = "@path";
    public const string Query        = "@query";
    public const string QueryParam   = "@query-param";
    public const string Status       = "@status";
    public const string RequestTarget = "@request-target";

    // ── Regular Components (Headers) ────────────────────────────────────
    public const string ContentType    = "content-type";
    public const string ContentLength  = "content-length";
    public const string ContentDigest  = "content-digest";
    public const string Host           = "host";
    public const string Date           = "date";
    public const string Authorization  = "authorization";
}
