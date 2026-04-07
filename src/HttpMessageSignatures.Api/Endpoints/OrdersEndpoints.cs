using HttpMessageSignatures.Api.Middleware;
using HttpMessageSignatures.Core.Models;

namespace HttpMessageSignatures.Api.Endpoints;

/// <summary>
/// Endpoints de exemplo que demonstram como acessar os SignatureParams
/// depois que o middleware verificou com sucesso.
/// </summary>
public static class OrdersEndpoints
{
    public record CreateOrderRequest(string Item, int Quantity, decimal Price);
    public record CreateOrderResponse(Guid OrderId, string Status, string VerifiedBy);

    public static IEndpointRouteBuilder MapOrdersEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/orders").WithTags("Orders");

        // POST /api/orders — cria um pedido. Requisição deve estar assinada.
        group.MapPost("/", (CreateOrderRequest request, HttpContext http) =>
        {
            // Os parâmetros da assinatura foram anexados pelo middleware
            var signatureParams = http.Items[SignatureVerificationMiddleware.SignatureParamsKey] as SignatureParams;

            var response = new CreateOrderResponse(
                OrderId: Guid.NewGuid(),
                Status: "created",
                VerifiedBy: signatureParams?.KeyId ?? "unknown");

            return Results.Created($"/api/orders/{response.OrderId}", response);
        })
        .WithName("CreateOrder")
        .WithSummary("Creates a new order. Requires a valid RFC 9421 signature.");

        // GET /api/orders/health — sem necessidade de assinatura (exemplo)
        group.MapGet("/health", () => Results.Ok(new { status = "ok" }))
             .WithName("OrdersHealth");

        return app;
    }
}
