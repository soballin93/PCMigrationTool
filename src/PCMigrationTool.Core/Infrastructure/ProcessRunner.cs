using System.Diagnostics;
using System.Text;

namespace PCMigrationTool.Core.Infrastructure;

public sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError, TimeSpan Duration)
{
    public bool Succeeded => ExitCode == 0;
}

public interface IProcessRunner
{
    Task<ProcessResult> RunAsync(
        string executable,
        IEnumerable<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken = default,
        Action<string>? output = null);
}

public sealed class ProcessRunner(IAppLogger logger) : IProcessRunner
{
    public async Task<ProcessResult> RunAsync(
        string executable,
        IEnumerable<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken = default,
        Action<string>? output = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executable);
        ArgumentNullException.ThrowIfNull(arguments);

        using Process process = new();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        foreach (string argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        StringBuilder stdout = new();
        StringBuilder stderr = new();
        process.OutputDataReceived += (_, eventArgs) =>
        {
            if (eventArgs.Data is null)
            {
                return;
            }

            lock (stdout)
            {
                stdout.AppendLine(eventArgs.Data);
            }

            output?.Invoke(eventArgs.Data);
        };
        process.ErrorDataReceived += (_, eventArgs) =>
        {
            if (eventArgs.Data is null)
            {
                return;
            }

            lock (stderr)
            {
                stderr.AppendLine(eventArgs.Data);
            }

            output?.Invoke(eventArgs.Data);
        };

        Stopwatch stopwatch = Stopwatch.StartNew();
        logger.Info($"Starting process: {Path.GetFileName(executable)}");
        if (!process.Start())
        {
            throw new InvalidOperationException($"Failed to start '{executable}'.");
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using CancellationTokenSource timeoutSource = new(timeout);
        using CancellationTokenSource linkedSource = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            timeoutSource.Token);
        try
        {
            await process.WaitForExitAsync(linkedSource.Token).ConfigureAwait(false);
            process.WaitForExit();
        }
        catch (OperationCanceledException) when (timeoutSource.IsCancellationRequested)
        {
            TryKill(process);
            throw new TimeoutException($"'{executable}' exceeded the {timeout} timeout.");
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            throw;
        }
        finally
        {
            stopwatch.Stop();
        }

        ProcessResult result = new(process.ExitCode, stdout.ToString(), stderr.ToString(), stopwatch.Elapsed);
        logger.Info($"Process completed: {Path.GetFileName(executable)} exit={result.ExitCode} duration={result.Duration:g}");
        return result;
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(true);
            }
        }
        catch (InvalidOperationException)
        {
        }
    }
}
