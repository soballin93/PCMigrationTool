using PCMigrationTool.Core.Services;

namespace PCMigrationTool.Core.Tests;

public sealed class RepositoryStagingServiceTests
{
    [Theory]
    [InlineData(@"\\unraid\isos\OLD-PC\PC_SWAP_INFO\manifest.json", @"\\unraid\isos\OLD-PC\PC_SWAP_INFO\UserProfile", true)]
    [InlineData(@"C:\Migration\OLD-PC\PC_SWAP_INFO\manifest.json", @"\\server\profiles\user", true)]
    [InlineData(@"C:\Migration\OLD-PC\PC_SWAP_INFO\manifest.json", @"C:\Migration\OLD-PC\PC_SWAP_INFO\UserProfile", false)]
    public void RequiresStaging_DetectsNetworkDependencies(string manifest, string profile, bool expected)
    {
        Assert.Equal(expected, RepositoryStagingService.RequiresStaging(manifest, profile));
    }
}
