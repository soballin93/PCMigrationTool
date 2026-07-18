using PCMigrationTool.Core.Services;

namespace PCMigrationTool.Core.Tests;

public sealed class RepositoryLayoutTests
{
    [Fact]
    public void Create_PreservesRequiredRepositoryShape()
    {
        DateTimeOffset now = new(2026, 7, 15, 18, 30, 0, TimeSpan.Zero);

        RepositoryPaths paths = RepositoryLayout.Create(@"C:\Migration", "OLD-PC", now);

        Assert.Equal(@"C:\Migration\OLD-PC_15-07-2026", paths.HostRoot);
        Assert.Equal(@"C:\Migration\OLD-PC_15-07-2026\PC_SWAP_INFO", paths.InfoRoot);
        Assert.Equal(Path.Combine(paths.InfoRoot, "manifest.json"), paths.ManifestPath);
        Assert.Equal(Path.Combine(paths.InfoRoot, "state.json"), paths.StatePath);
    }

    [Fact]
    public void FromManifest_RejectsAdHocArtifactFolders()
    {
        InvalidDataException exception = Assert.Throws<InvalidDataException>(() =>
            RepositoryLayout.FromManifest(@"C:\Migration\manifest.json", DateTimeOffset.Now));

        Assert.Contains("PC_SWAP_INFO", exception.Message, StringComparison.Ordinal);
    }
}
