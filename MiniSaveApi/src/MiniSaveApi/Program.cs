using System.Threading.RateLimiting;
using MiniSaveApi;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<MiniSaveOptions>(builder.Configuration.GetSection(MiniSaveOptions.SectionName));
builder.Services.Configure<JsonOptions>(options =>
{
    options.SerializerOptions.WriteIndented = false;
});
builder.Services.AddSingleton<RequestSignatureValidator>();
builder.Services.AddSingleton<AccessTokenService>();
builder.Services.AddSingleton<VersionPolicy>();
builder.Services.AddSingleton<WechatIdentityResolver>();
builder.Services.AddSingleton<SqliteSaveStore>();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("auth", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "local",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 20,
            Window = TimeSpan.FromMinutes(1),
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 0,
            AutoReplenishment = true
        }));
    options.AddPolicy("save", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Request.Headers.Authorization.ToString() ?? context.Connection.RemoteIpAddress?.ToString() ?? "local",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 60,
            Window = TimeSpan.FromMinutes(1),
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 0,
            AutoReplenishment = true
        }));
});

var app = builder.Build();

app.UseRateLimiter();

app.MapGet("/healthz", (SqliteSaveStore store) => Results.Ok(new
{
    status = "ok",
    databasePath = store.DatabasePath
}));

app.MapPost("/v1/auth/external-login", async (
    HttpRequest httpRequest,
    RequestSignatureValidator requestSignatureValidator,
    VersionPolicy versionPolicy,
    SqliteSaveStore store,
    AccessTokenService accessTokenService,
    CancellationToken cancellationToken) =>
{
    SignedRequest<LoginRequest> signedRequest = await requestSignatureValidator.ReadAsync<LoginRequest>(httpRequest, cancellationToken);
    if (!signedRequest.IsValid || signedRequest.Value is null)
    {
        return signedRequest.ToResult();
    }

    LoginRequest request = signedRequest.Value;

    if (string.IsNullOrWhiteSpace(request.Provider) || string.IsNullOrWhiteSpace(request.ExternalUserId))
    {
        return Results.BadRequest(new ErrorResponse("invalid_login", "Provider and externalUserId are required."));
    }

    if (!versionPolicy.IsSupported(request.ClientVersion, out string versionError))
    {
        return Results.BadRequest(new ErrorResponse("unsupported_client_version", versionError));
    }

    PlayerRecord player = await store.GetOrCreatePlayerAsync(request.Provider, request.ExternalUserId, request.DisplayName, cancellationToken);
    SaveEnvelope save = await store.GetOrCreateSaveAsync(player.PlayerId, request.ClientVersion, cancellationToken);
    string accessToken = accessTokenService.Create(player.PlayerId);

    return Results.Ok(new LoginResponse(player.PlayerId, accessToken, save));
})
.RequireRateLimiting("auth");

app.MapPost("/v1/auth/wechat-login", async (
    HttpRequest httpRequest,
    RequestSignatureValidator requestSignatureValidator,
    VersionPolicy versionPolicy,
    WechatIdentityResolver wechatIdentityResolver,
    SqliteSaveStore store,
    AccessTokenService accessTokenService,
    CancellationToken cancellationToken) =>
{
    SignedRequest<WechatLoginRequest> signedRequest = await requestSignatureValidator.ReadAsync<WechatLoginRequest>(httpRequest, cancellationToken);
    if (!signedRequest.IsValid || signedRequest.Value is null)
    {
        return signedRequest.ToResult();
    }

    WechatLoginRequest request = signedRequest.Value;

    if (!versionPolicy.IsSupported(request.ClientVersion, out string versionError))
    {
        return Results.BadRequest(new ErrorResponse("unsupported_client_version", versionError));
    }

    if (!wechatIdentityResolver.TryResolve(request, out ResolvedExternalIdentity? identity, out ErrorResponse? validationError))
    {
        return Results.BadRequest(validationError!);
    }

    PlayerRecord player = await store.GetOrCreatePlayerAsync(identity!.Provider, identity.ExternalUserId, identity.DisplayName, cancellationToken);
    SaveEnvelope save = await store.GetOrCreateSaveAsync(player.PlayerId, request.ClientVersion, cancellationToken);
    string accessToken = accessTokenService.Create(player.PlayerId);

    return Results.Ok(new LoginResponse(player.PlayerId, accessToken, save));
})
.RequireRateLimiting("auth");

app.MapGet("/v1/save", async (
    HttpRequest httpRequest,
    AccessTokenService accessTokenService,
    SqliteSaveStore store,
    CancellationToken cancellationToken) =>
{
    if (!accessTokenService.TryReadPlayerId(httpRequest, out string playerId, out string? tokenError))
    {
        return Results.Unauthorized();
    }

    SaveEnvelope save = await store.GetSaveAsync(playerId, cancellationToken);
    return Results.Ok(save);
})
.RequireRateLimiting("save");

app.MapPut("/v1/save", async (
    HttpRequest httpRequest,
    SaveWriteRequest request,
    AccessTokenService accessTokenService,
    VersionPolicy versionPolicy,
    SqliteSaveStore store,
    CancellationToken cancellationToken) =>
{
    if (!accessTokenService.TryReadPlayerId(httpRequest, out string playerId, out string? tokenError))
    {
        return Results.Unauthorized();
    }

    if (!versionPolicy.IsSupported(request.ClientVersion, out string versionError))
    {
        return Results.BadRequest(new ErrorResponse("unsupported_client_version", versionError));
    }

    if (request.SaveVersion <= 0)
    {
        return Results.BadRequest(new ErrorResponse("invalid_save_version", "saveVersion must be greater than zero."));
    }

    SaveWriteResult result = await store.WriteSaveAsync(playerId, request, cancellationToken);

    return result.Status switch
    {
        SaveWriteStatus.Updated => Results.Ok(result.Save),
        SaveWriteStatus.Conflict => Results.Conflict(new ErrorResponse("stale_revision", "The save was updated elsewhere. Reload and retry.")),
        _ => Results.BadRequest(new ErrorResponse("save_error", "Unable to update save."))
    };
})
.RequireRateLimiting("save");

app.Run();

public partial class Program;
