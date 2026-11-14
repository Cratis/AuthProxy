// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace E2E.OAuthGrantReceiver;

/// <summary>In-process test shim: signed material and bearer tokens never leave this process in responses or logs.</summary>
sealed class HostileChecks(GrantAdmission admission)
{
    Header[]? _last;
    string _method = "GET";
    string _path = "/grants/rest";
    int _accepted;

    public int Accepted => Volatile.Read(ref _accepted);

    public void Remember(string method, string path, Header[] headers)
    {
        _method = method;
        _path = path;
        _last = headers;
        Interlocked.Increment(ref _accepted);
    }

    public async Task<string[]> Run(string replacementToken)
    {
        var captured = _last ?? throw new InvalidOperationException("No accepted request captured");
        // An accepted, fresh-state control rules out expired or otherwise unusable captures.
        await admission.FreshReplayState().Admit(_method, _path, captured);
        var scenarios = Scenarios(captured, replacementToken);
        foreach (var scenario in scenarios)
        {
            await RequireRejection(scenario, captured, DisabledCheck.None);
            await KillMutant(scenario, captured);
        }
        Console.WriteLine("PASS: 9 exact-reason hostile checks; 9 disabled-check mutants killed");
        return scenarios.Select(scenario => scenario.Name).ToArray();
    }

    Scenario[] Scenarios(Header[] captured, string replacementToken)
    {
        var signature = captured.Single(header => header.Name.Equals("x-cratis-forwarded-identity-signature", StringComparison.OrdinalIgnoreCase));
        var forged = signature.Value[..(signature.Value.LastIndexOf('.') + 1)] + new string('A', 86);
        return
        [
            new("tampered", "signature", DisabledCheck.Signature, Replace(captured, "x-cratis-subject", "00000000-0000-0000-0000-000000000999")),
            new("forged", "signature", DisabledCheck.Signature, Replace(captured, signature.Name, forged)),
            new("stripped", "missing-envelope", DisabledCheck.Envelope, captured.Where(header => !header.Name.Equals(signature.Name, StringComparison.OrdinalIgnoreCase)).ToArray()),
            new("replayed", "replay", DisabledCheck.Replay, captured) { Replay = true },
            new("swapped-bearer", "credential", DisabledCheck.BearerBinding, Replace(captured, "Authorization", $"Bearer {replacementToken}")),
            new("duplicate-envelope", "duplicate-header", DisabledCheck.DuplicateHeader, [.. captured, signature]),
            new("unknown-context", "unknown-header", DisabledCheck.UnknownHeader, [.. captured, new("x-cratis-unknown", "untrusted")]),
            new("altered-method", "signature", DisabledCheck.Signature, captured) { Method = "DELETE" },
            new("altered-target", "signature", DisabledCheck.Signature, captured) { Path = _path.Split('?')[0] + "/tampered" }
        ];
    }

    async Task RequireRejection(Scenario scenario, Header[] captured, DisabledCheck disabled)
    {
        var isolated = admission.FreshReplayState(disabled);
        if (scenario.Replay) await isolated.Admit(_method, _path, captured);
        try { await isolated.Admit(scenario.Method ?? _method, scenario.Path ?? _path, scenario.Headers); }
        catch (Rejected error) when (error.Message == scenario.Reason) { return; }
        catch (Rejected) { throw new HostileCheckFailure(scenario.Name); }
        throw new HostileCheckFailure(scenario.Name);
    }

    async Task KillMutant(Scenario scenario, Header[] captured)
    {
        // Run the same oracle with the actual check omitted, not a synthetic expected result.
        try { await RequireRejection(scenario, captured, scenario.Disabled); }
        catch (HostileCheckFailure) { return; }
        throw new InvalidOperationException($"Hostile oracle survived disabled check: {scenario.Name}");
    }

    static Header[] Replace(Header[] headers, string name, string value) => headers.Select(header => header.Name.Equals(name, StringComparison.OrdinalIgnoreCase) ? new Header(header.Name, value) : header).ToArray();

    sealed record Scenario(string Name, string Reason, DisabledCheck Disabled, Header[] Headers)
    {
        public string? Method { get; init; }
        public string? Path { get; init; }
        public bool Replay { get; init; }
    }
    sealed class HostileCheckFailure(string name) : Exception($"Hostile request did not produce its required rejection: {name}");
}
