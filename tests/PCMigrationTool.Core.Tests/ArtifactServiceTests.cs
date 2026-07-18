using PCMigrationTool.Core.Infrastructure;
using PCMigrationTool.Core.Services;

namespace PCMigrationTool.Core.Tests;

public sealed class ArtifactServiceTests
{
    [Fact]
    public void Restore_CopiesAndAppliesCapturedArtifacts()
    {
        string root = CreateTemporaryDirectory();
        try
        {
            RepositoryPaths paths = RepositoryLayout.Create(root, "SOURCE-PC", DateTimeOffset.Now);
            RepositoryLayout.EnsureDirectories(paths);
            File.WriteAllBytes(Path.Combine(paths.InfoRoot, "TranscodedWallpaper"), [1, 2, 3, 4]);
            File.WriteAllText(Path.Combine(paths.BrowserExportsPath, "Chrome Passwords.csv"), "name,url");
            File.WriteAllText(Path.Combine(paths.BrowserExportsPath, "Edge Passwords.csv"), "name,url");
            string signature = Path.Combine(paths.InfoRoot, "Signatures", "default.htm");
            Directory.CreateDirectory(Path.GetDirectoryName(signature)!);
            File.WriteAllText(signature, "signature");

            string targetProfile = Path.Combine(root, "target");
            Directory.CreateDirectory(targetProfile);
            FakeWallpaperApplier wallpaper = new(true);
            ArtifactService service = new(CreateLogger(root), wallpaper);

            ArtifactRestoreResults result = service.Restore(paths, targetProfile);

            string wallpaperTarget = Path.Combine(
                targetProfile,
                @"AppData\Roaming\Microsoft\Windows\Themes\TranscodedWallpaper");
            Assert.True(result.WallpaperCopied);
            Assert.True(result.WallpaperApplied);
            Assert.Equal(wallpaperTarget, wallpaper.AppliedPath);
            Assert.Equal(new byte[] { 1, 2, 3, 4 }, File.ReadAllBytes(wallpaperTarget));
            Assert.True(result.SignaturesCopied);
            Assert.Equal("signature", File.ReadAllText(Path.Combine(
                targetProfile,
                @"AppData\Roaming\Microsoft\Signatures\default.htm")));
            Assert.Equal(2, result.BrowserExportCount);
            Assert.Equal(
                "name,url",
                File.ReadAllText(Path.Combine(
                    targetProfile,
                    "Documents",
                    "PC Migration Browser Exports",
                    "Chrome Passwords.csv")));
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Restore_ReportsWallpaperActivationFailure()
    {
        string root = CreateTemporaryDirectory();
        try
        {
            RepositoryPaths paths = RepositoryLayout.Create(root, "SOURCE-PC", DateTimeOffset.Now);
            RepositoryLayout.EnsureDirectories(paths);
            File.WriteAllBytes(Path.Combine(paths.InfoRoot, "TranscodedWallpaper"), [1]);
            string targetProfile = Path.Combine(root, "target");
            Directory.CreateDirectory(targetProfile);

            ArtifactRestoreResults result = new ArtifactService(
                CreateLogger(root),
                new FakeWallpaperApplier(false)).Restore(paths, targetProfile);

            Assert.True(result.WallpaperCopied);
            Assert.False(result.WallpaperApplied);
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }

    private static AppLogger CreateLogger(string root)
    {
        AppLogger logger = new();
        logger.SetLogPath(Path.Combine(root, "test.log"));
        return logger;
    }

    private static string CreateTemporaryDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), $"pcmigration-artifact-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    private sealed class FakeWallpaperApplier(bool succeeds) : IWallpaperApplier
    {
        public string? AppliedPath { get; private set; }

        public bool Apply(string wallpaperPath)
        {
            AppliedPath = wallpaperPath;
            return succeeds;
        }
    }
}
