// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;

namespace Cratis.AuthProxy.Vectors;

public static class PublishedAuthorizationVectors
{
    public const string Version = "1.0.0";
    public const string Tag = "vectors/arc-mcp-authorization/v1.0.0";

    public static string PathFor(string file) => Path.Combine(AppContext.BaseDirectory, "Vectors", "arc-mcp-authorization", Version, file);

    public static JsonElement Manifest => Read("manifest.json");

    public static IEnumerable<TheoryDataRow<string>> Cases => Manifest.GetProperty("cases").EnumerateArray()
        .Select(entry => new TheoryDataRow<string>(entry.GetProperty("id").GetString()));

    public static JsonElement Case(string id)
    {
        var entry = Manifest.GetProperty("cases").EnumerateArray().Single(_ => _.GetProperty("id").GetString() == id);
        return Read(entry.GetProperty("file").GetString()).GetProperty("given").GetProperty("vectors")[entry.GetProperty("index").GetInt32()];
    }

    public static JsonElement Read(string file)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(PathFor(file)));
        return document.RootElement.Clone();
    }
}
