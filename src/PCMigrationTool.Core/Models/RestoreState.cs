using System.Text.Json;
using System.Text.Json.Serialization;

namespace PCMigrationTool.Core.Models;

public sealed class RestoreState
{
    public string StateVersion { get; set; } = "1.1";
    public string NextPhase { get; set; } = RestorePhases.PostJoin;
    public string ManifestPath { get; set; } = string.Empty;
    public string? ProfileSource { get; set; }
    public string? SourceStatePath { get; set; }
    public bool IncludeOneDrive { get; set; }
    public string? TargetLocalUser { get; set; }
    public string? TargetDomainUser { get; set; }
    public string? RequestedHostname { get; set; }
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.Now;

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? ExtensionData { get; set; }
}

public static class RestorePhases
{
    public const string PostJoin = "PostJoin";
    public const string UserProfile = "UserProfile";
    public const string Complete = "Complete";
}
