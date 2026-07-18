using PCMigrationTool.Core.Services;

namespace PCMigrationTool.Core.Tests;

public sealed class RobocopyExitCodesTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    public void CodesBelowEightAreSuccessful(int exitCode)
    {
        Assert.True(RobocopyExitCodes.IsSuccess(exitCode));
    }

    [Theory]
    [InlineData(8)]
    [InlineData(16)]
    public void CodesEightAndAboveAreFailures(int exitCode)
    {
        Assert.False(RobocopyExitCodes.IsSuccess(exitCode));
        Assert.Equal(RobocopyOutcome.CopyFailure, RobocopyExitCodes.Classify(exitCode));
    }
}
