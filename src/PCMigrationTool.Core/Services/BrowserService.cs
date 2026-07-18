using System.Diagnostics;
using Microsoft.Win32;
using PCMigrationTool.Core.Infrastructure;
using PCMigrationTool.Core.Models;

namespace PCMigrationTool.Core.Services;

public sealed class BrowserService(IAppLogger logger)
{
    private static readonly BrowserDefinition[] Definitions =
    [
        new("Chrome", "Google Chrome", "chrome.exe", "chrome://password-manager/settings", "Chrome Passwords.csv", [@"Google\Chrome\Application\chrome.exe"]),
        new("Edge", "Microsoft Edge", "msedge.exe", "edge://wallet/passwords", "Microsoft Edge Passwords.csv", [@"Microsoft\Edge\Application\msedge.exe"]),
        new("Firefox", "Mozilla Firefox", "firefox.exe", "about:logins", "passwords.csv", [@"Mozilla Firefox\firefox.exe"]),
        new("Brave", "Brave Browser", "brave.exe", "brave://password-manager/settings", "Brave Passwords.csv", [@"BraveSoftware\Brave-Browser\Application\brave.exe"]),
        new("Opera", "Opera Browser", "opera.exe", "opera://password-manager/settings", "Opera Passwords.csv", [@"Opera\opera.exe", @"Programs\Opera\opera.exe"])
    ];

    public IReadOnlyList<BrowserInfo> DetectInstalled()
    {
        List<BrowserInfo> browsers = [];
        foreach (BrowserDefinition definition in Definitions)
        {
            string? executable = FindExecutable(definition);
            if (executable is null)
            {
                continue;
            }

            browsers.Add(new BrowserInfo
            {
                Name = definition.Name,
                DisplayName = definition.DisplayName,
                ExecutablePath = executable,
                PasswordUrl = definition.PasswordUrl,
                ExportFileName = definition.ExportFileName
            });
        }

        logger.Info(browsers.Count == 0
            ? "No supported browsers detected."
            : $"Detected browsers: {string.Join(", ", browsers.Select(static browser => browser.DisplayName))}.");
        return browsers;
    }

    public void OpenPasswordExportPages(IEnumerable<BrowserInfo> browsers)
    {
        foreach (BrowserInfo browser in browsers)
        {
            try
            {
                Process.Start(new ProcessStartInfo(browser.ExecutablePath, browser.PasswordUrl)
                {
                    UseShellExecute = true
                });
                logger.Info($"Opened {browser.DisplayName} password export page.");
            }
            catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                logger.Warning($"Unable to open {browser.DisplayName}: {exception.Message}");
            }
        }
    }

    public List<BrowserExportInfo> ValidateExports(IEnumerable<BrowserInfo> browsers, string exportDirectory)
    {
        return browsers.Select(browser =>
        {
            string path = Path.Combine(exportDirectory, browser.ExportFileName);
            bool valid = File.Exists(path) && new FileInfo(path).Length > 0;
            return new BrowserExportInfo
            {
                Name = browser.Name,
                DisplayName = browser.DisplayName,
                FileName = browser.ExportFileName,
                Exported = valid
            };
        }).ToList();
    }

    private static string? FindExecutable(BrowserDefinition definition)
    {
        IEnumerable<string> roots =
        [
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
        ];
        foreach (string root in roots.Where(static root => !string.IsNullOrWhiteSpace(root)))
        {
            foreach (string relativePath in definition.RelativePaths)
            {
                string candidate = Path.Combine(root, relativePath);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }

        foreach (RegistryView view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using RegistryKey? appPath = baseKey.OpenSubKey(
                $@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{definition.ExecutableName}");
            if (appPath?.GetValue(null) is string registered && File.Exists(registered))
            {
                return registered;
            }
        }

        using RegistryKey? currentUserAppPath = Registry.CurrentUser.OpenSubKey(
            $@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{definition.ExecutableName}");
        return currentUserAppPath?.GetValue(null) is string userRegistered && File.Exists(userRegistered)
            ? userRegistered
            : null;
    }

    private sealed record BrowserDefinition(
        string Name,
        string DisplayName,
        string ExecutableName,
        string PasswordUrl,
        string ExportFileName,
        string[] RelativePaths);
}
