using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;

namespace MiniSaveApi.Tests;

public sealed class MiniSaveApiFactory : WebApplicationFactory<Program>, IDisposable
{
    private readonly string dataDirectory = Path.Combine(Path.GetTempPath(), "MiniSaveApiTests", Guid.NewGuid().ToString("N"));

    public string DataDirectory => this.dataDirectory;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        Directory.CreateDirectory(this.dataDirectory);

        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["MiniSave:DataDirectory"] = this.dataDirectory,
                ["MiniSave:DatabaseFileName"] = "testsaves.db",
                ["MiniSave:ApiSecret"] = SaveApiTests.TestSecrets.ApiSecret,
                ["MiniSave:TokenSecret"] = SaveApiTests.TestSecrets.TokenSecret,
                ["MiniSave:MinimumSupportedClientVersion"] = "1.0.0"
            });
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        if (!disposing)
        {
            return;
        }

        if (Directory.Exists(this.dataDirectory))
        {
            SqliteConnection.ClearAllPools();

            for (int attempt = 0; attempt < 5; attempt++)
            {
                try
                {
                    Directory.Delete(this.dataDirectory, recursive: true);
                    break;
                }
                catch (IOException) when (attempt < 4)
                {
                    Thread.Sleep(50);
                }
            }
        }
    }
}
