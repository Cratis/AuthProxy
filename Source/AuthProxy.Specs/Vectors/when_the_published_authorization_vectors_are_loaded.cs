// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace Cratis.AuthProxy.Vectors;

public class when_the_published_authorization_vectors_are_loaded : Specification
{
    static readonly JsonSerializerOptions _compactJson = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    [Fact]
    void should_match_the_pinned_manifest()
    {
        var manifest = PublishedAuthorizationVectors.Manifest;
        manifest.GetProperty("version").GetString().ShouldEqual(PublishedAuthorizationVectors.Version);
        manifest.GetProperty("caseCount").GetInt32().ShouldEqual(48);
        var cases = manifest.GetProperty("cases").EnumerateArray().ToArray();
        cases.Length.ShouldEqual(manifest.GetProperty("caseCount").GetInt32());
        cases.Select(_ => _.GetProperty("id").GetString()).Distinct(StringComparer.Ordinal).Count().ShouldEqual(cases.Length);
        foreach (var file in manifest.GetProperty("files").EnumerateArray())
        {
            var name = file.GetProperty("path").GetString();
            Hash(File.ReadAllBytes(PublishedAuthorizationVectors.PathFor(name))).ShouldEqual(file.GetProperty("sha256").GetString());
            var entries = cases.Where(_ => _.GetProperty("file").GetString() == name).ToArray();
            var vectors = PublishedAuthorizationVectors.Read(name).GetProperty("given").GetProperty("vectors");
            entries.Length.ShouldEqual(vectors.GetArrayLength());
            entries.Select(_ => _.GetProperty("index").GetInt32()).Distinct().Count().ShouldEqual(entries.Length);
        }
    }

    [Theory]
    [MemberData(nameof(PublishedAuthorizationVectors.Cases), MemberType = typeof(PublishedAuthorizationVectors))]
    public void should_match_each_case_hash(string id)
    {
        var entry = PublishedAuthorizationVectors.Manifest.GetProperty("cases").EnumerateArray().Single(_ => _.GetProperty("id").GetString() == id);

        // Preserve insertion order and literal Unicode, matching JSON.stringify in the upstream packager.
        var bytes = JsonSerializer.SerializeToUtf8Bytes(PublishedAuthorizationVectors.Case(id), _compactJson);
        Assert.True(Hash(bytes) == entry.GetProperty("sha256").GetString(), $"Published vector hash mismatch: {id}.");
    }

    static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
}
