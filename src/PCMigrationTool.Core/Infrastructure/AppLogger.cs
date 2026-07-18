using System.Globalization;
using System.Text;

namespace PCMigrationTool.Core.Infrastructure;

public enum LogLevel
{
    Info,
    Warning,
    Error
}

public sealed record LogEntry(DateTimeOffset Timestamp, LogLevel Level, string Message)
{
    public override string ToString() =>
        $"[{Timestamp.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)}][{Level.ToString().ToUpperInvariant()}] {Message}";
}

public interface IAppLogger
{
    event EventHandler<LogEntry>? EntryWritten;
    string? LogPath { get; }
    void SetLogPath(string path);
    void Info(string message);
    void Warning(string message);
    void Error(string message, Exception? exception = null);
}

public sealed class AppLogger : IAppLogger
{
    private readonly object gate = new();
    private string? logPath;

    public event EventHandler<LogEntry>? EntryWritten;
    public string? LogPath
    {
        get
        {
            lock (gate)
            {
                return logPath;
            }
        }
    }

    public void SetLogPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        lock (gate)
        {
            logPath = fullPath;
        }
    }

    public void Info(string message) => Write(LogLevel.Info, message);
    public void Warning(string message) => Write(LogLevel.Warning, message);
    public void Error(string message, Exception? exception = null) =>
        Write(LogLevel.Error, exception is null ? message : $"{message}: {exception.Message}");

    private void Write(LogLevel level, string message)
    {
        LogEntry entry = new(DateTimeOffset.Now, level, message);
        lock (gate)
        {
            string target = logPath ?? Path.Combine(
                Path.GetTempPath(),
                $"pcmigration_{Environment.ProcessId}.log");
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.AppendAllText(target, entry + Environment.NewLine, new UTF8Encoding(false));
        }

        EntryWritten?.Invoke(this, entry);
    }
}
