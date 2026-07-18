using PCMigrationTool.Core.Models;
using PCMigrationTool.Core.Services;

namespace PCMigrationTool.Core.Tests;

public sealed class PrinterRestoreServiceTests
{
    [Theory]
    [InlineData(@"\\print01\Accounting", "WSD-123", @"\\print01\Accounting")]
    [InlineData("Accounting", @"\\print01\Accounting", @"\\print01\Accounting")]
    [InlineData("Local PDF", "PORTPROMPT:", "")]
    public void SharedConnectionName_ReturnsOnlyVerifiableUncConnections(
        string name,
        string port,
        string expected)
    {
        PrinterInfo printer = new() { Name = name, PortName = port };

        Assert.Equal(expected, PrinterRestoreService.SharedConnectionName(printer));
    }
}
