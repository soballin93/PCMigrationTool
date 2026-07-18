using System.ComponentModel;
using System.Runtime.InteropServices;
using PCMigrationTool.Core.Infrastructure;

namespace PCMigrationTool.Core.Services;

public sealed record ArtifactResults(bool WallpaperCopied, bool SignaturesCopied);
public sealed record ArtifactRestoreResults(
    bool WallpaperCopied,
    bool WallpaperApplied,
    bool SignaturesCopied,
    int BrowserExportCount,
    string? BrowserExportDirectory);

public interface IWallpaperApplier
{
    bool Apply(string wallpaperPath);
}

public sealed class WindowsWallpaperApplier : IWallpaperApplier
{
    private const uint SetDesktopWallpaper = 0x0014;
    private const uint UpdateProfile = 0x0001;
    private const uint SendChange = 0x0002;

    public bool Apply(string wallpaperPath) =>
        SystemParametersInfo(SetDesktopWallpaper, 0, wallpaperPath, UpdateProfile | SendChange);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SystemParametersInfo(uint action, uint parameter, string value, uint flags);
}

public sealed class ArtifactService
{
    private readonly IAppLogger logger;
    private readonly IWallpaperApplier wallpaperApplier;

    public ArtifactService(IAppLogger logger, IWallpaperApplier? wallpaperApplier = null)
    {
        this.logger = logger;
        this.wallpaperApplier = wallpaperApplier ?? new WindowsWallpaperApplier();
    }

    public ArtifactResults Gather(RepositoryPaths paths)
    {
        bool wallpaper = CopyWallpaper(paths.InfoRoot);
        bool signatures = CopySignatures(paths.InfoRoot);
        return new ArtifactResults(wallpaper, signatures);
    }

    public ArtifactRestoreResults Restore(RepositoryPaths paths, string targetProfile)
    {
        bool wallpaperCopied = false;
        bool wallpaperApplied = false;
        string wallpaperSource = Path.Combine(paths.InfoRoot, "TranscodedWallpaper");
        if (File.Exists(wallpaperSource))
        {
            string themeDirectory = Path.Combine(targetProfile, @"AppData\Roaming\Microsoft\Windows\Themes");
            Directory.CreateDirectory(themeDirectory);
            string wallpaperTarget = Path.Combine(themeDirectory, "TranscodedWallpaper");
            File.Copy(wallpaperSource, wallpaperTarget, true);
            wallpaperCopied = true;
            wallpaperApplied = wallpaperApplier.Apply(wallpaperTarget);
            if (wallpaperApplied)
            {
                logger.Info("Restored and applied the captured wallpaper.");
            }
            else
            {
                int error = Marshal.GetLastWin32Error();
                logger.Warning($"Restored the wallpaper file but Windows did not apply it: {new Win32Exception(error).Message}");
            }
        }

        bool signaturesCopied = false;
        string signaturesSource = Path.Combine(paths.InfoRoot, "Signatures");
        if (Directory.Exists(signaturesSource))
        {
            string signaturesTarget = Path.Combine(targetProfile, @"AppData\Roaming\Microsoft\Signatures");
            CopyDirectory(signaturesSource, signaturesTarget);
            signaturesCopied = true;
            logger.Info("Restored Outlook signatures.");
        }

        int browserExportCount = 0;
        string? browserExportDirectory = null;
        if (Directory.Exists(paths.BrowserExportsPath))
        {
            string[] browserExports = Directory.GetFiles(paths.BrowserExportsPath, "*.csv", SearchOption.TopDirectoryOnly);
            if (browserExports.Length > 0)
            {
                browserExportDirectory = Path.Combine(targetProfile, "Documents", "PC Migration Browser Exports");
                Directory.CreateDirectory(browserExportDirectory);
                foreach (string export in browserExports)
                {
                    File.Copy(export, Path.Combine(browserExportDirectory, Path.GetFileName(export)), true);
                }
                browserExportCount = browserExports.Length;
                logger.Info($"Restored {browserExportCount} browser export file(s) to '{browserExportDirectory}'.");
            }
        }

        return new ArtifactRestoreResults(
            wallpaperCopied,
            wallpaperApplied,
            signaturesCopied,
            browserExportCount,
            browserExportDirectory);
    }

    private bool CopyWallpaper(string infoRoot)
    {
        string source = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Windows\Themes\TranscodedWallpaper");
        if (!File.Exists(source))
        {
            return false;
        }

        File.Copy(source, Path.Combine(infoRoot, "TranscodedWallpaper"), true);
        logger.Info("Captured current wallpaper.");
        return true;
    }

    private bool CopySignatures(string infoRoot)
    {
        string source = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Signatures");
        if (!Directory.Exists(source))
        {
            return false;
        }

        CopyDirectory(source, Path.Combine(infoRoot, "Signatures"));
        logger.Info("Captured Outlook signatures.");
        return true;
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (string directory in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(Path.Combine(destination, Path.GetRelativePath(source, directory)));
        }

        foreach (string file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            string target = Path.Combine(destination, Path.GetRelativePath(source, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, true);
        }
    }
}
