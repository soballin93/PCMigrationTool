using PCMigrationTool.Core.Infrastructure;
using PCMigrationTool.Core.Models;
using PCMigrationTool.Core.Services;

namespace PCMigrationTool.Core.Tests;

public sealed class MappedDriveServiceTests
{
    [Fact]
    public void Restore_SkipsMalformedMappingsWithoutCallingWindowsNetworking()
    {
        TestLogger logger = new();
        MappedDriveService service = new(logger);

        IReadOnlyList<MappedDriveRestoreResult> results = service.Restore(
        [
            new MappedDriveInfo { DeviceID = "Documents", ProviderName = @"\\server\share" },
            new MappedDriveInfo { DeviceID = "Z:", ProviderName = @"C:\NotANetworkShare" }
        ]);

        Assert.Equal(2, results.Count);
        Assert.All(results, static result => Assert.False(result.Succeeded));
        Assert.Equal(2, logger.Warnings.Count);
    }

    private sealed class TestLogger : IAppLogger
    {
        public List<string> Warnings { get; } = [];
        public event EventHandler<LogEntry>? EntryWritten { add { } remove { } }
        public string? LogPath => null;
        public void SetLogPath(string path) { }
        public void Info(string message) { }
        public void Warning(string message) => Warnings.Add(message);
        public void Error(string message, Exception? exception = null) { }
    }
}
