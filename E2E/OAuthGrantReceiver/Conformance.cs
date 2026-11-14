// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;

namespace E2E.OAuthGrantReceiver;

static class Conformance
{
    static readonly JsonSerializerOptions Options = new() { PropertyNameCaseInsensitive = true };

    public static void Run()
    {
        var json = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Contract/vectors.json"));
        var fixture = JsonSerializer.Deserialize<Fixture>(json, Options)!;
        var groups = new Dictionary<string, NonceStore>(StringComparer.Ordinal);
        foreach (var vector in fixture.Cases)
        {
            var store = new NonceStore();
            if (vector.ReplayGroup is { } group)
            {
                if (!groups.TryGetValue(group, out store!)) groups[group] = store = new();
            }
            var actual = Reference.Verify(vector, fixture.TestKeys, store);
            if (actual != vector.Expected) throw new InvalidOperationException($"Vector failed: {vector.Name}: {actual} != {vector.Expected}");
        }
        ExpectRejected([new("X-Cratis-Unrecognised", "value")]);
        ExpectRejected([new("Authorization", "Bearer a"), new("authorization", "Bearer b")]);
        ExpectRejected([new("x-cratis-subject", "bad\nvalue")]);
        Console.WriteLine($"PASS: {fixture.Cases.Count} pinned Arc v2 vectors; unknown, duplicate and control-header rejection");
    }

    static void ExpectRejected(Header[] headers)
    {
        try { GrantAdmission.ValidateHeaders(headers); }
        catch (Rejected) { return; }
        throw new InvalidOperationException("Receiver accepted invalid headers");
    }
}
