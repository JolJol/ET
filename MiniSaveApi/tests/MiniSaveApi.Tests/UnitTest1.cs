using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace MiniSaveApi.Tests;

public sealed class SaveApiTests : IClassFixture<MiniSaveApiFactory>
{
    private readonly MiniSaveApiFactory factory;

    public SaveApiTests(MiniSaveApiFactory factory)
    {
        this.factory = factory;
    }

    [Fact]
    public async Task Login_creates_default_save_for_new_player()
    {
        using HttpClient client = this.factory.CreateClient();
        LoginRequest request = new("wechat", "wx-open-id-1", "1.0.0", "Player One");

        using HttpRequestMessage message = SignedJsonRequest(HttpMethod.Post, "/v1/auth/external-login", request);

        using HttpResponseMessage response = await client.SendAsync(message);

        response.EnsureSuccessStatusCode();

        LoginResponse? payload = await response.Content.ReadFromJsonAsync<LoginResponse>();

        Assert.NotNull(payload);
        Assert.False(string.IsNullOrWhiteSpace(payload.PlayerId));
        Assert.False(string.IsNullOrWhiteSpace(payload.AccessToken));
        Assert.Equal(0, payload.Save.Revision);
        Assert.Equal(1, payload.Save.SaveVersion);
        Assert.Equal("{}", payload.Save.GameData.GetRawText());
    }

    [Fact]
    public async Task Save_write_persists_and_reloads_latest_revision()
    {
        using HttpClient client = this.factory.CreateClient();
        LoginResponse login = await LoginAsync(client, "wx-open-id-2");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.AccessToken);

        SaveWriteRequest update = new(0, 1, "1.0.0", JsonDocument.Parse("{\"coins\":123,\"level\":4}").RootElement);

        using HttpResponseMessage writeResponse = await client.PutAsJsonAsync("/v1/save", update);

        writeResponse.EnsureSuccessStatusCode();

        SaveEnvelope? updated = await writeResponse.Content.ReadFromJsonAsync<SaveEnvelope>();

        Assert.NotNull(updated);
        Assert.Equal(1, updated.Revision);

        using HttpResponseMessage readResponse = await client.GetAsync("/v1/save");

        readResponse.EnsureSuccessStatusCode();

        SaveEnvelope? reloaded = await readResponse.Content.ReadFromJsonAsync<SaveEnvelope>();

        Assert.NotNull(reloaded);
        Assert.Equal(1, reloaded.Revision);
        Assert.Equal(123, reloaded.GameData.GetProperty("coins").GetInt32());
        Assert.Equal(4, reloaded.GameData.GetProperty("level").GetInt32());
    }

    [Fact]
    public async Task Save_write_rejects_stale_revision()
    {
        using HttpClient client = this.factory.CreateClient();
        LoginResponse login = await LoginAsync(client, "wx-open-id-3");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.AccessToken);

        SaveWriteRequest firstUpdate = new(0, 1, "1.0.0", JsonDocument.Parse("{\"coins\":5}").RootElement);
        SaveWriteRequest staleUpdate = new(0, 1, "1.0.0", JsonDocument.Parse("{\"coins\":999}").RootElement);

        using HttpResponseMessage firstResponse = await client.PutAsJsonAsync("/v1/save", firstUpdate);
        firstResponse.EnsureSuccessStatusCode();

        using HttpResponseMessage staleResponse = await client.PutAsJsonAsync("/v1/save", staleUpdate);

        Assert.Equal(HttpStatusCode.Conflict, staleResponse.StatusCode);
    }

    [Fact]
    public async Task Login_rejects_unsupported_client_version()
    {
        using HttpClient client = this.factory.CreateClient();
        LoginRequest request = new("wechat", "wx-open-id-4", "0.9.0", "Player Four");

        using HttpRequestMessage message = SignedJsonRequest(HttpMethod.Post, "/v1/auth/external-login", request);
        using HttpResponseMessage response = await client.SendAsync(message);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Login_rejects_invalid_signature()
    {
        using HttpClient client = this.factory.CreateClient();
        LoginRequest request = new("wechat", "wx-open-id-invalid-signature", "1.0.0", "Bad Actor");

        using HttpRequestMessage message = SignedJsonRequest(HttpMethod.Post, "/v1/auth/external-login", request);
        message.Headers.Remove("X-Request-Signature");
        message.Headers.Add("X-Request-Signature", "BAD");

        using HttpResponseMessage response = await client.SendAsync(message);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Login_reuses_player_mapping_for_same_external_account()
    {
        using HttpClient client = this.factory.CreateClient();

        LoginResponse firstLogin = await LoginAsync(client, "wx-open-id-repeat");
        LoginResponse secondLogin = await LoginAsync(client, "wx-open-id-repeat");

        Assert.Equal(firstLogin.PlayerId, secondLogin.PlayerId);
    }

    [Fact]
    public async Task Save_write_rejects_unsupported_client_version()
    {
        using HttpClient client = this.factory.CreateClient();
        LoginResponse login = await LoginAsync(client, "wx-open-id-unsupported-save");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.AccessToken);

        using HttpResponseMessage response = await client.PutAsJsonAsync(
            "/v1/save",
            new SaveWriteRequest(0, 1, "0.9.0", JsonDocument.Parse("{\"coins\":1}").RootElement));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Health_endpoint_reports_service_status()
    {
        using HttpClient client = this.factory.CreateClient();

        using HttpResponseMessage response = await client.GetAsync("/healthz");

        response.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task Save_reads_are_rate_limited_per_access_token()
    {
        using HttpClient client = this.factory.CreateClient();
        LoginResponse login = await LoginAsync(client, "wx-open-id-rate-limit");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.AccessToken);

        HttpStatusCode lastStatus = HttpStatusCode.OK;

        for (int attempt = 0; attempt < 61; attempt++)
        {
            using HttpResponseMessage response = await client.GetAsync("/v1/save");
            lastStatus = response.StatusCode;
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, lastStatus);
    }

    [Fact]
    public async Task Read_save_recovers_latest_valid_backup_when_current_save_is_corrupted()
    {
        using HttpClient client = this.factory.CreateClient();
        LoginResponse login = await LoginAsync(client, "wx-open-id-5");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.AccessToken);

        await client.PutAsJsonAsync("/v1/save", new SaveWriteRequest(0, 1, "1.0.0", JsonDocument.Parse("{\"coins\":10}").RootElement));
        await client.PutAsJsonAsync("/v1/save", new SaveWriteRequest(1, 1, "1.0.0", JsonDocument.Parse("{\"coins\":20}").RootElement));

        string databasePath = Path.Combine(this.factory.DataDirectory, "testsaves.db");
        using (SqliteConnection connection = new($"Data Source={databasePath}"))
        {
            connection.Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = """
                UPDATE CurrentSaves
                SET GameData = '{broken-json', Checksum = 'BROKEN'
                WHERE PlayerId = $playerId;
                """;
            command.Parameters.AddWithValue("$playerId", login.PlayerId);
            command.ExecuteNonQuery();
        }

        using HttpResponseMessage response = await client.GetAsync("/v1/save");

        response.EnsureSuccessStatusCode();

        SaveEnvelope? repaired = await response.Content.ReadFromJsonAsync<SaveEnvelope>();

        Assert.NotNull(repaired);
        Assert.Equal(1, repaired.Revision);
        Assert.Equal(10, repaired.GameData.GetProperty("coins").GetInt32());
    }

    private static async Task<LoginResponse> LoginAsync(HttpClient client, string externalUserId)
    {
        LoginRequest request = new("wechat", externalUserId, "1.0.0", "Player");
        using HttpRequestMessage message = SignedJsonRequest(HttpMethod.Post, "/v1/auth/external-login", request);
        using HttpResponseMessage response = await client.SendAsync(message);

        response.EnsureSuccessStatusCode();

        return (await response.Content.ReadFromJsonAsync<LoginResponse>())!;
    }

    private static HttpRequestMessage SignedJsonRequest(HttpMethod method, string uri, LoginRequest request)
    {
        string body = JsonSerializer.Serialize(request);
        string timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        string signature = ComputeSignature(timestamp, body);

        HttpRequestMessage message = new(method, uri)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };
        message.Headers.Add("X-Request-Timestamp", timestamp);
        message.Headers.Add("X-Request-Signature", signature);
        return message;
    }

    private static string ComputeSignature(string timestamp, string body)
    {
        using HMACSHA256 hmac = new(Encoding.UTF8.GetBytes(TestSecrets.ApiSecret));
        byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes($"{timestamp}.{body}"));
        return Convert.ToHexString(hash);
    }

    public sealed record LoginRequest(string Provider, string ExternalUserId, string ClientVersion, string? DisplayName);

    public sealed record SaveWriteRequest(int ExpectedRevision, int SaveVersion, string ClientVersion, JsonElement GameData);

    public sealed record LoginResponse(string PlayerId, string AccessToken, SaveEnvelope Save);

    public sealed record SaveEnvelope(int Revision, int SaveVersion, string ClientVersion, JsonElement GameData);

    public static class TestSecrets
    {
        public const string ApiSecret = "test-api-secret-123";
        public const string TokenSecret = "test-token-secret-456";
    }
}