using PCMigrationTool.Core.Infrastructure;
using PCMigrationTool.Core.Models;

namespace PCMigrationTool.Core.Tests;

public sealed class AtomicJsonFileTests
{
    [Fact]
    public async Task ExistingStateIsReplacedAtomically()
    {
        string directory = Path.Combine(Path.GetTempPath(), "pcmigration-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "state.json");
        try
        {
            AtomicJsonFile store = new();
            await store.WriteAsync(path, new RestoreState { NextPhase = RestorePhases.PostJoin });
            await store.WriteAsync(path, new RestoreState { NextPhase = RestorePhases.Complete });

            RestoreState? restored = await store.ReadAsync<RestoreState>(path);

            Assert.Equal(RestorePhases.Complete, restored?.NextPhase);
            Assert.Empty(Directory.EnumerateFiles(directory, "*.tmp-*"));
        }
        finally
        {
            Directory.Delete(directory, true);
        }
    }

    [Fact]
    public async Task LegacySchemaOneManifestLoadsWithDefensiveDefaults()
    {
        string directory = Path.Combine(Path.GetTempPath(), "pcmigration-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "manifest.json");
        await File.WriteAllTextAsync(path, """
            {
              "SchemaVersion": "1.0",
              "Mode": "Gather",
              "General": { "ComputerName": "OLD-PC", "ProgramVersion": "0.5.34" },
              "Computer": { "Hostname": "OLD-PC" },
              "User": { "Username": "legacy" },
              "IncludeOneDrive": false,
              "FutureProperty": { "kept": true }
            }
            """);

        try
        {
            AtomicJsonFile store = new();
            MigrationManifest? manifest = await store.ReadAsync<MigrationManifest>(path);

            Assert.NotNull(manifest);
            Assert.Equal("1.0", manifest.SchemaVersion);
            Assert.Equal("OLD-PC", manifest.Computer.Hostname);
            Assert.NotNull(manifest.Computer.NetworkAdapters);
            Assert.True(manifest.ExtensionData?.ContainsKey("FutureProperty"));
        }
        finally
        {
            Directory.Delete(directory, true);
        }
    }
}
