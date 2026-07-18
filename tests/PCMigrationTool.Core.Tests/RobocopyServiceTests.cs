using PCMigrationTool.Core.Infrastructure;
using PCMigrationTool.Core.Models;
using PCMigrationTool.Core.Services;

namespace PCMigrationTool.Core.Tests;

public sealed class RobocopyServiceTests
{
    [Fact]
    public async Task CopyProfile_ExcludesLiveRegistryHivesAndWritesTranscript()
    {
        string root = Path.Combine(Path.GetTempPath(), "pcmigration-tests", Guid.NewGuid().ToString("N"));
        string source = Path.Combine(root, "source");
        string destination = Path.Combine(root, "output", "UserProfile");
        Directory.CreateDirectory(source);
        CapturingRunner runner = new();
        TestLogger logger = new();
        string applicationLog = Path.Combine(root, "repository", "app.log");
        logger.SetLogPath(applicationLog);
        try
        {
            RobocopyService service = new(runner, logger);

            CopyResult result = await service.CopyProfileAsync(source, destination, includeOneDrive: false);

            Assert.True(result.Succeeded);
            Assert.Contains("/XF", runner.Arguments);
            Assert.Contains("NTUSER.DAT", runner.Arguments);
            Assert.Contains("UsrClass.dat", runner.Arguments);
            Assert.Contains(
                Path.Combine(source, @"AppData\Local\Microsoft\Windows\Explorer"),
                runner.Arguments);
            Assert.DoesNotContain("/SEC", runner.Arguments);
            Assert.Contains(
                $"/LOG+:{Path.Combine(Path.GetDirectoryName(applicationLog)!, "profile-copy.log")}",
                runner.Arguments);
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }

    private sealed class CapturingRunner : IProcessRunner
    {
        public IReadOnlyList<string> Arguments { get; private set; } = [];

        public Task<ProcessResult> RunAsync(
            string executable,
            IEnumerable<string> arguments,
            TimeSpan timeout,
            CancellationToken cancellationToken = default,
            Action<string>? output = null)
        {
            Arguments = arguments.ToList();
            return Task.FromResult(new ProcessResult(1, string.Empty, string.Empty, TimeSpan.Zero));
        }
    }

    private sealed class TestLogger : IAppLogger
    {
        public event EventHandler<LogEntry>? EntryWritten { add { } remove { } }
        public string? LogPath { get; private set; }
        public void SetLogPath(string path) => LogPath = path;
        public void Info(string message) { }
        public void Warning(string message) { }
        public void Error(string message, Exception? exception = null) { }
    }
}
