using System.Text.Json;
using System.Text.Json.Serialization;

namespace PCMigrationTool.Core.Infrastructure;

public static class AppJson
{
    public static JsonSerializerOptions Options { get; } = new()
    {
        AllowTrailingCommas = true,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };
}
