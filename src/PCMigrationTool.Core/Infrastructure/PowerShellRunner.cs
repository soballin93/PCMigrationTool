using System.Text;

namespace PCMigrationTool.Core.Infrastructure;

public sealed class PowerShellRunner(IProcessRunner processRunner)
{
    public Task<ProcessResult> RunAsync(
        string script,
        TimeSpan timeout,
        CancellationToken cancellationToken = default,
        Action<string>? output = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(script);
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        return processRunner.RunAsync(
            "powershell.exe",
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
            timeout,
            cancellationToken,
            output);
    }

    public static string QuoteLiteral(string value) => "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";
}
