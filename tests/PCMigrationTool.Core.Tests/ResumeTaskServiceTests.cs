using System.Text;
using PCMigrationTool.Core.Infrastructure;
using PCMigrationTool.Core.Services;

namespace PCMigrationTool.Core.Tests;

public sealed class ResumeTaskServiceTests
{
    [Fact]
    public async Task RemoveAll_UsesOneIdempotentCleanupInvocation()
    {
        CapturingRunner runner = new(new ProcessResult(0, string.Empty, string.Empty, TimeSpan.Zero));
        ResumeTaskService service = new(new PowerShellRunner(runner), new TestLogger());

        await service.RemoveAllAsync();

        Assert.Equal(1, runner.InvocationCount);
        string script = runner.DecodedScript;
        Assert.Contains(ResumeTaskService.SystemTaskName, script);
        Assert.Contains(ResumeTaskService.UserTaskName, script);
        Assert.Contains("Get-ScheduledTask", script);
        Assert.Contains("$failures", script);
    }

    [Fact]
    public async Task RemoveAll_ThrowsWhenCleanupProcessFails()
    {
        CapturingRunner runner = new(new ProcessResult(1, string.Empty, "cleanup failed", TimeSpan.Zero));
        ResumeTaskService service = new(new PowerShellRunner(runner), new TestLogger());

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.RemoveAllAsync());

        Assert.Contains("cleanup failed", exception.Message);
    }

    private sealed class CapturingRunner(ProcessResult result) : IProcessRunner
    {
        public int InvocationCount { get; private set; }
        public string DecodedScript { get; private set; } = string.Empty;

        public Task<ProcessResult> RunAsync(
            string executable,
            IEnumerable<string> arguments,
            TimeSpan timeout,
            CancellationToken cancellationToken = default,
            Action<string>? output = null)
        {
            InvocationCount++;
            List<string> values = arguments.ToList();
            int encodedIndex = values.IndexOf("-EncodedCommand");
            DecodedScript = Encoding.Unicode.GetString(Convert.FromBase64String(values[encodedIndex + 1]));
            return Task.FromResult(result);
        }
    }

    private sealed class TestLogger : IAppLogger
    {
        public event EventHandler<LogEntry>? EntryWritten { add { } remove { } }
        public string? LogPath => null;
        public void SetLogPath(string path) { }
        public void Info(string message) { }
        public void Warning(string message) { }
        public void Error(string message, Exception? exception = null) { }
    }
}
