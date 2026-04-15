using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace MiniSaveApi;

public sealed class MiniSaveOptions
{
    public const string SectionName = "MiniSave";

    public string DataDirectory { get; init; } = "data";

    public string DatabaseFileName { get; init; } = "minisave.db";

    public string ApiSecret { get; init; } = string.Empty;

    public string TokenSecret { get; init; } = string.Empty;

    public string MinimumSupportedClientVersion { get; init; } = "1.0.0";

    public int RequestLifetimeMinutes { get; init; } = 5;

    public int TokenLifetimeHours { get; init; } = 24;
}

public sealed record LoginRequest(string Provider, string ExternalUserId, string ClientVersion, string? DisplayName);

public sealed record SaveWriteRequest(int ExpectedRevision, int SaveVersion, string ClientVersion, JsonElement GameData);

public sealed record LoginResponse(string PlayerId, string AccessToken, SaveEnvelope Save);

public sealed record SaveEnvelope(int Revision, int SaveVersion, string ClientVersion, JsonElement GameData, DateTimeOffset UpdatedAtUtc);

public sealed record ErrorResponse(string Code, string Message);

public sealed record PlayerRecord(string PlayerId, string Provider, string ExternalUserId, string? DisplayName);

internal sealed record StoredSaveRecord(
    int Revision,
    int SaveVersion,
    string ClientVersion,
    string GameData,
    string Checksum,
    DateTimeOffset UpdatedAtUtc);

public enum SaveWriteStatus
{
    Updated,
    Conflict,
    Failed
}

public sealed record SaveWriteResult(SaveWriteStatus Status, SaveEnvelope? Save);

public sealed class SignedRequest<T>
{
    public bool IsValid { get; init; }

    public T? Value { get; init; }

    public int StatusCode { get; init; }

    public ErrorResponse Error { get; init; } = new("invalid_request", "The request is invalid.");

    public IResult ToResult()
    {
        return Results.Json(Error, statusCode: StatusCode);
    }
}

public sealed class RequestSignatureValidator
{
    private readonly MiniSaveOptions options;

    public RequestSignatureValidator(IOptions<MiniSaveOptions> options)
    {
        this.options = options.Value;
        if (string.IsNullOrWhiteSpace(this.options.ApiSecret))
        {
            throw new InvalidOperationException("MiniSave:ApiSecret must be configured before the API can start.");
        }
    }

    public async Task<SignedRequest<T>> ReadAsync<T>(HttpRequest request, CancellationToken cancellationToken)
    {
        request.EnableBuffering();

        using StreamReader reader = new(request.Body, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        string body = await reader.ReadToEndAsync(cancellationToken);
        request.Body.Position = 0;

        if (!request.Headers.TryGetValue("X-Request-Timestamp", out var timestampHeader) ||
            !request.Headers.TryGetValue("X-Request-Signature", out var signatureHeader))
        {
            return Invalid<T>(StatusCodes.Status401Unauthorized, "invalid_signature", "Missing request signature headers.");
        }

        if (!long.TryParse(timestampHeader.ToString(), out long unixTime))
        {
            return Invalid<T>(StatusCodes.Status401Unauthorized, "invalid_signature", "Timestamp header is invalid.");
        }

        DateTimeOffset timestamp = DateTimeOffset.FromUnixTimeSeconds(unixTime);
        TimeSpan drift = DateTimeOffset.UtcNow - timestamp;
        if (drift.Duration() > TimeSpan.FromMinutes(this.options.RequestLifetimeMinutes))
        {
            return Invalid<T>(StatusCodes.Status401Unauthorized, "request_expired", "The signed request has expired.");
        }

        string expectedSignature = ComputeHmac(this.options.ApiSecret, $"{timestampHeader}.{body}");
        string providedSignature = signatureHeader.ToString();
        if (!FixedEquals(expectedSignature, providedSignature))
        {
            return Invalid<T>(StatusCodes.Status401Unauthorized, "invalid_signature", "Request signature validation failed.");
        }

        T? payload = JsonSerializer.Deserialize<T>(body);
        if (payload is null)
        {
            return Invalid<T>(StatusCodes.Status400BadRequest, "invalid_body", "Request body cannot be parsed.");
        }

        return new SignedRequest<T>
        {
            IsValid = true,
            Value = payload,
            StatusCode = StatusCodes.Status200OK
        };
    }

    private static SignedRequest<T> Invalid<T>(int statusCode, string code, string message)
    {
        return new SignedRequest<T>
        {
            IsValid = false,
            StatusCode = statusCode,
            Error = new ErrorResponse(code, message)
        };
    }

    private static string ComputeHmac(string secret, string value)
    {
        using HMACSHA256 hmac = new(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(value)));
    }

    private static bool FixedEquals(string left, string right)
    {
        try
        {
            byte[] leftBytes = Convert.FromHexString(left);
            byte[] rightBytes = Convert.FromHexString(right);
            return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

public sealed class AccessTokenService
{
    private readonly MiniSaveOptions options;

    public AccessTokenService(IOptions<MiniSaveOptions> options)
    {
        this.options = options.Value;
        if (string.IsNullOrWhiteSpace(this.options.TokenSecret))
        {
            throw new InvalidOperationException("MiniSave:TokenSecret must be configured before the API can start.");
        }
    }

    public string Create(string playerId)
    {
        long expiresAt = DateTimeOffset.UtcNow.AddHours(this.options.TokenLifetimeHours).ToUnixTimeSeconds();
        string payload = $"{playerId}|{expiresAt}";
        string payloadToken = Base64UrlEncode(payload);
        string signature = ComputeHmac(this.options.TokenSecret, payloadToken);
        return $"{payloadToken}.{signature}";
    }

    public bool TryReadPlayerId(HttpRequest request, out string playerId, out string? error)
    {
        playerId = string.Empty;
        error = null;

        string authorization = request.Headers.Authorization.ToString();
        if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            error = "Missing bearer token.";
            return false;
        }

        string token = authorization["Bearer ".Length..].Trim();
        string[] segments = token.Split('.', 2, StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length != 2)
        {
            error = "Token format is invalid.";
            return false;
        }

        string expectedSignature = ComputeHmac(this.options.TokenSecret, segments[0]);
        if (!RequestSignatureValidatorFixedEquals(expectedSignature, segments[1]))
        {
            error = "Token signature is invalid.";
            return false;
        }

        string payload = Base64UrlDecode(segments[0]);
        string[] payloadSegments = payload.Split('|', 2, StringSplitOptions.RemoveEmptyEntries);
        if (payloadSegments.Length != 2 || !long.TryParse(payloadSegments[1], out long expiresAt))
        {
            error = "Token payload is invalid.";
            return false;
        }

        if (DateTimeOffset.UtcNow > DateTimeOffset.FromUnixTimeSeconds(expiresAt))
        {
            error = "Token has expired.";
            return false;
        }

        playerId = payloadSegments[0];
        return true;
    }

    private static string ComputeHmac(string secret, string value)
    {
        using HMACSHA256 hmac = new(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(value)));
    }

    private static string Base64UrlEncode(string value)
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(value)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string Base64UrlDecode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
        return Encoding.UTF8.GetString(Convert.FromBase64String(padded));
    }

    private static bool RequestSignatureValidatorFixedEquals(string left, string right)
    {
        try
        {
            byte[] leftBytes = Convert.FromHexString(left);
            byte[] rightBytes = Convert.FromHexString(right);
            return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

public sealed class VersionPolicy
{
    private readonly Version minimumVersion;

    public VersionPolicy(IOptions<MiniSaveOptions> options)
    {
        MiniSaveOptions value = options.Value;
        if (string.IsNullOrWhiteSpace(value.MinimumSupportedClientVersion))
        {
            throw new InvalidOperationException("MiniSave:MinimumSupportedClientVersion must be configured.");
        }

        this.minimumVersion = ParseVersion(value.MinimumSupportedClientVersion);
    }

    public bool IsSupported(string? clientVersion, out string message)
    {
        if (string.IsNullOrWhiteSpace(clientVersion))
        {
            message = "clientVersion is required.";
            return false;
        }

        try
        {
            Version requestedVersion = ParseVersion(clientVersion);
            if (requestedVersion < this.minimumVersion)
            {
                message = $"clientVersion {clientVersion} is lower than the minimum supported version {this.minimumVersion}.";
                return false;
            }

            message = string.Empty;
            return true;
        }
        catch (FormatException)
        {
            message = "clientVersion must use semantic version format, for example 1.0.0.";
            return false;
        }
    }

    private static Version ParseVersion(string value)
    {
        if (!Version.TryParse(value, out Version? version))
        {
            throw new FormatException("Invalid version string.");
        }

        return version;
    }
}

public sealed class SqliteSaveStore
{
    private readonly string connectionString;
    private readonly SemaphoreSlim gate = new(1, 1);

    public SqliteSaveStore(IOptions<MiniSaveOptions> options)
    {
        MiniSaveOptions value = options.Value;
        if (string.IsNullOrWhiteSpace(value.DataDirectory))
        {
            throw new InvalidOperationException("MiniSave:DataDirectory must be configured.");
        }

        if (string.IsNullOrWhiteSpace(value.DatabaseFileName))
        {
            throw new InvalidOperationException("MiniSave:DatabaseFileName must be configured.");
        }

        string dataDirectory = Path.GetFullPath(value.DataDirectory);
        Directory.CreateDirectory(dataDirectory);

        this.DatabasePath = Path.Combine(dataDirectory, value.DatabaseFileName);
        this.connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = this.DatabasePath
        }.ToString();

        this.Initialize();
    }

    public string DatabasePath { get; }

    public async Task<PlayerRecord> GetOrCreatePlayerAsync(string provider, string externalUserId, string? displayName, CancellationToken cancellationToken)
    {
        await this.gate.WaitAsync(cancellationToken);
        try
        {
            await using SqliteConnection connection = this.CreateConnection();

            const string selectSql = """
                SELECT PlayerId, Provider, ExternalUserId, DisplayName
                FROM Players
                WHERE Provider = $provider AND ExternalUserId = $externalUserId;
                """;

            await using SqliteCommand selectCommand = connection.CreateCommand();
            selectCommand.CommandText = selectSql;
            selectCommand.Parameters.AddWithValue("$provider", provider);
            selectCommand.Parameters.AddWithValue("$externalUserId", externalUserId);

            await using SqliteDataReader reader = await selectCommand.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                string playerId = reader.GetString(0);
                string existingProvider = reader.GetString(1);
                string existingExternalId = reader.GetString(2);
                string? existingDisplayName = reader.IsDBNull(3) ? null : reader.GetString(3);

                if (!string.Equals(existingDisplayName, displayName, StringComparison.Ordinal))
                {
                    await reader.DisposeAsync();
                    await using SqliteCommand updateCommand = connection.CreateCommand();
                    updateCommand.CommandText = "UPDATE Players SET DisplayName = $displayName WHERE PlayerId = $playerId;";
                    updateCommand.Parameters.AddWithValue("$displayName", (object?)displayName ?? DBNull.Value);
                    updateCommand.Parameters.AddWithValue("$playerId", playerId);
                    await updateCommand.ExecuteNonQueryAsync(cancellationToken);
                }

                return new PlayerRecord(playerId, existingProvider, existingExternalId, displayName ?? existingDisplayName);
            }

            string newPlayerId = Guid.NewGuid().ToString("N");
            await using SqliteCommand insertCommand = connection.CreateCommand();
            insertCommand.CommandText = """
                INSERT INTO Players(PlayerId, Provider, ExternalUserId, DisplayName, CreatedAtUtc)
                VALUES($playerId, $provider, $externalUserId, $displayName, $createdAtUtc);
                """;
            insertCommand.Parameters.AddWithValue("$playerId", newPlayerId);
            insertCommand.Parameters.AddWithValue("$provider", provider);
            insertCommand.Parameters.AddWithValue("$externalUserId", externalUserId);
            insertCommand.Parameters.AddWithValue("$displayName", (object?)displayName ?? DBNull.Value);
            insertCommand.Parameters.AddWithValue("$createdAtUtc", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            await insertCommand.ExecuteNonQueryAsync(cancellationToken);

            return new PlayerRecord(newPlayerId, provider, externalUserId, displayName);
        }
        finally
        {
            this.gate.Release();
        }
    }

    public async Task<SaveEnvelope> GetOrCreateSaveAsync(string playerId, string clientVersion, CancellationToken cancellationToken)
    {
        await this.gate.WaitAsync(cancellationToken);
        try
        {
            await using SqliteConnection connection = this.CreateConnection();
            return await this.GetOrCreateSaveInternalAsync(connection, playerId, clientVersion, cancellationToken);
        }
        finally
        {
            this.gate.Release();
        }
    }

    public async Task<SaveEnvelope> GetSaveAsync(string playerId, CancellationToken cancellationToken)
    {
        await this.gate.WaitAsync(cancellationToken);
        try
        {
            await using SqliteConnection connection = this.CreateConnection();
            return await this.LoadAndRepairSaveAsync(connection, playerId, defaultClientVersion: "1.0.0", cancellationToken);
        }
        finally
        {
            this.gate.Release();
        }
    }

    public async Task<SaveWriteResult> WriteSaveAsync(string playerId, SaveWriteRequest request, CancellationToken cancellationToken)
    {
        await this.gate.WaitAsync(cancellationToken);
        try
        {
            await using SqliteConnection connection = this.CreateConnection();
            SaveEnvelope current = await this.LoadAndRepairSaveAsync(connection, playerId, request.ClientVersion, cancellationToken);
            if (current.Revision != request.ExpectedRevision)
            {
                return new SaveWriteResult(SaveWriteStatus.Conflict, current);
            }

            string gameDataJson = NormalizeJson(request.GameData);
            string checksum = ComputeChecksum(request.SaveVersion, request.ClientVersion, gameDataJson);
            DateTimeOffset now = DateTimeOffset.UtcNow;

            await using SqliteTransaction transaction = connection.BeginTransaction();

            await using (SqliteCommand updateCommand = connection.CreateCommand())
            {
                updateCommand.Transaction = transaction;
                updateCommand.CommandText = """
                    UPDATE CurrentSaves
                    SET Revision = $revision,
                        SaveVersion = $saveVersion,
                        ClientVersion = $clientVersion,
                        GameData = $gameData,
                        Checksum = $checksum,
                        UpdatedAtUtc = $updatedAtUtc
                    WHERE PlayerId = $playerId AND Revision = $expectedRevision;
                    """;
                updateCommand.Parameters.AddWithValue("$revision", current.Revision + 1);
                updateCommand.Parameters.AddWithValue("$saveVersion", request.SaveVersion);
                updateCommand.Parameters.AddWithValue("$clientVersion", request.ClientVersion);
                updateCommand.Parameters.AddWithValue("$gameData", gameDataJson);
                updateCommand.Parameters.AddWithValue("$checksum", checksum);
                updateCommand.Parameters.AddWithValue("$updatedAtUtc", now.ToString("O", CultureInfo.InvariantCulture));
                updateCommand.Parameters.AddWithValue("$playerId", playerId);
                updateCommand.Parameters.AddWithValue("$expectedRevision", request.ExpectedRevision);

                int rowsAffected = await updateCommand.ExecuteNonQueryAsync(cancellationToken);
                if (rowsAffected == 0)
                {
                    await transaction.RollbackAsync(cancellationToken);
                    SaveEnvelope latest = await this.LoadAndRepairSaveAsync(connection, playerId, request.ClientVersion, cancellationToken);
                    return new SaveWriteResult(SaveWriteStatus.Conflict, latest);
                }
            }

            await using (SqliteCommand backupCommand = connection.CreateCommand())
            {
                backupCommand.Transaction = transaction;
                backupCommand.CommandText = """
                    INSERT INTO SaveBackups(PlayerId, Revision, SaveVersion, ClientVersion, GameData, Checksum, UpdatedAtUtc, BackupReason, CreatedAtUtc)
                    VALUES($playerId, $revision, $saveVersion, $clientVersion, $gameData, $checksum, $updatedAtUtc, $backupReason, $createdAtUtc);
                    """;
                backupCommand.Parameters.AddWithValue("$playerId", playerId);
                backupCommand.Parameters.AddWithValue("$revision", current.Revision);
                backupCommand.Parameters.AddWithValue("$saveVersion", current.SaveVersion);
                backupCommand.Parameters.AddWithValue("$clientVersion", current.ClientVersion);
                backupCommand.Parameters.AddWithValue("$gameData", NormalizeJson(current.GameData));
                backupCommand.Parameters.AddWithValue("$checksum", ComputeChecksum(current.SaveVersion, current.ClientVersion, NormalizeJson(current.GameData)));
                backupCommand.Parameters.AddWithValue("$updatedAtUtc", current.UpdatedAtUtc.ToString("O", CultureInfo.InvariantCulture));
                backupCommand.Parameters.AddWithValue("$backupReason", "before_update");
                backupCommand.Parameters.AddWithValue("$createdAtUtc", now.ToString("O", CultureInfo.InvariantCulture));
                await backupCommand.ExecuteNonQueryAsync(cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);

            return new SaveWriteResult(
                SaveWriteStatus.Updated,
                new SaveEnvelope(current.Revision + 1, request.SaveVersion, request.ClientVersion, ParseJson(gameDataJson), now));
        }
        finally
        {
            this.gate.Release();
        }
    }

    private SqliteConnection CreateConnection()
    {
        SqliteConnection connection = new(this.connectionString);
        connection.Open();
        return connection;
    }

    private void Initialize()
    {
        using SqliteConnection connection = this.CreateConnection();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS Players (
                PlayerId TEXT PRIMARY KEY,
                Provider TEXT NOT NULL,
                ExternalUserId TEXT NOT NULL,
                DisplayName TEXT NULL,
                CreatedAtUtc TEXT NOT NULL,
                UNIQUE (Provider, ExternalUserId)
            );

            CREATE TABLE IF NOT EXISTS CurrentSaves (
                PlayerId TEXT PRIMARY KEY,
                Revision INTEGER NOT NULL,
                SaveVersion INTEGER NOT NULL,
                ClientVersion TEXT NOT NULL,
                GameData TEXT NOT NULL,
                Checksum TEXT NOT NULL,
                UpdatedAtUtc TEXT NOT NULL,
                FOREIGN KEY (PlayerId) REFERENCES Players(PlayerId)
            );

            CREATE TABLE IF NOT EXISTS SaveBackups (
                BackupId INTEGER PRIMARY KEY AUTOINCREMENT,
                PlayerId TEXT NOT NULL,
                Revision INTEGER NOT NULL,
                SaveVersion INTEGER NOT NULL,
                ClientVersion TEXT NOT NULL,
                GameData TEXT NOT NULL,
                Checksum TEXT NOT NULL,
                UpdatedAtUtc TEXT NOT NULL,
                BackupReason TEXT NOT NULL,
                CreatedAtUtc TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS IX_SaveBackups_PlayerId_CreatedAtUtc
                ON SaveBackups(PlayerId, CreatedAtUtc DESC);
            """;
        command.ExecuteNonQuery();
    }

    private async Task<SaveEnvelope> GetOrCreateSaveInternalAsync(SqliteConnection connection, string playerId, string clientVersion, CancellationToken cancellationToken)
    {
        return await this.LoadAndRepairSaveAsync(connection, playerId, clientVersion, cancellationToken);
    }

    private async Task<SaveEnvelope> LoadAndRepairSaveAsync(SqliteConnection connection, string playerId, string defaultClientVersion, CancellationToken cancellationToken)
    {
        StoredSaveRecord? current = await this.TryLoadCurrentSaveAsync(connection, playerId, cancellationToken);
        if (current is null)
        {
            SaveEnvelope defaultSave = CreateDefaultSave(defaultClientVersion);
            await this.UpsertCurrentSaveAsync(connection, playerId, defaultSave, cancellationToken);
            return defaultSave;
        }

        try
        {
            JsonElement currentJson = ParseJson(current.GameData);
            string normalizedCurrentJson = NormalizeJson(currentJson);
            string currentChecksum = ComputeChecksum(current.SaveVersion, current.ClientVersion, normalizedCurrentJson);
            if (string.Equals(currentChecksum, current.Checksum, StringComparison.Ordinal))
            {
                return new SaveEnvelope(current.Revision, current.SaveVersion, current.ClientVersion, currentJson, current.UpdatedAtUtc);
            }
        }
        catch (JsonException)
        {
            // Invalid JSON is treated as corruption and repaired from backup below.
        }

        SaveEnvelope? backup = await this.TryLoadLatestBackupAsync(connection, playerId, cancellationToken);
        SaveEnvelope repaired = backup ?? CreateDefaultSave(current.ClientVersion);
        await this.UpsertCurrentSaveAsync(connection, playerId, repaired, cancellationToken);
        return repaired;
    }

    private async Task<StoredSaveRecord?> TryLoadCurrentSaveAsync(SqliteConnection connection, string playerId, CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT Revision, SaveVersion, ClientVersion, GameData, Checksum, UpdatedAtUtc
            FROM CurrentSaves
            WHERE PlayerId = $playerId;
            """;
        command.Parameters.AddWithValue("$playerId", playerId);

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new StoredSaveRecord(
            reader.GetInt32(0),
            reader.GetInt32(1),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetString(4),
            DateTimeOffset.Parse(reader.GetString(5), CultureInfo.InvariantCulture));
    }

    private async Task<SaveEnvelope?> TryLoadLatestBackupAsync(SqliteConnection connection, string playerId, CancellationToken cancellationToken)
    {
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT Revision, SaveVersion, ClientVersion, GameData, UpdatedAtUtc, Checksum
            FROM SaveBackups
            WHERE PlayerId = $playerId
            ORDER BY CreatedAtUtc DESC;
            """;
        command.Parameters.AddWithValue("$playerId", playerId);

        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            int revision = reader.GetInt32(0);
            int saveVersion = reader.GetInt32(1);
            string clientVersion = reader.GetString(2);
            string gameData = reader.GetString(3);
            DateTimeOffset updatedAtUtc = DateTimeOffset.Parse(reader.GetString(4), CultureInfo.InvariantCulture);
            string checksum = reader.GetString(5);

            if (string.Equals(checksum, ComputeChecksum(saveVersion, clientVersion, gameData), StringComparison.Ordinal))
            {
                return new SaveEnvelope(revision, saveVersion, clientVersion, ParseJson(gameData), updatedAtUtc);
            }
        }

        return null;
    }

    private async Task UpsertCurrentSaveAsync(SqliteConnection connection, string playerId, SaveEnvelope save, CancellationToken cancellationToken)
    {
        string gameDataJson = NormalizeJson(save.GameData);
        string checksum = ComputeChecksum(save.SaveVersion, save.ClientVersion, gameDataJson);

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO CurrentSaves(PlayerId, Revision, SaveVersion, ClientVersion, GameData, Checksum, UpdatedAtUtc)
            VALUES($playerId, $revision, $saveVersion, $clientVersion, $gameData, $checksum, $updatedAtUtc)
            ON CONFLICT(PlayerId) DO UPDATE SET
                Revision = excluded.Revision,
                SaveVersion = excluded.SaveVersion,
                ClientVersion = excluded.ClientVersion,
                GameData = excluded.GameData,
                Checksum = excluded.Checksum,
                UpdatedAtUtc = excluded.UpdatedAtUtc;
            """;
        command.Parameters.AddWithValue("$playerId", playerId);
        command.Parameters.AddWithValue("$revision", save.Revision);
        command.Parameters.AddWithValue("$saveVersion", save.SaveVersion);
        command.Parameters.AddWithValue("$clientVersion", save.ClientVersion);
        command.Parameters.AddWithValue("$gameData", gameDataJson);
        command.Parameters.AddWithValue("$checksum", checksum);
        command.Parameters.AddWithValue("$updatedAtUtc", save.UpdatedAtUtc.ToString("O", CultureInfo.InvariantCulture));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static SaveEnvelope CreateDefaultSave(string clientVersion)
    {
        return new SaveEnvelope(
            Revision: 0,
            SaveVersion: 1,
            ClientVersion: clientVersion,
            GameData: ParseJson("{}"),
            UpdatedAtUtc: DateTimeOffset.UtcNow);
    }

    private static string NormalizeJson(JsonElement gameData)
    {
        return JsonSerializer.Serialize(gameData);
    }

    private static JsonElement ParseJson(string json)
    {
        using JsonDocument document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }

    private static string ComputeChecksum(int saveVersion, string clientVersion, string gameData)
    {
        byte[] payload = Encoding.UTF8.GetBytes($"{saveVersion}:{clientVersion}:{gameData}");
        return Convert.ToHexString(SHA256.HashData(payload));
    }
}
