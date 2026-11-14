// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Text.Json;

namespace E2E.OAuthGrantReceiver;

/// <summary>Single-replica, fail-closed test receiver. No AuthProxy implementation is referenced.</summary>
sealed class GrantAdmission(string publicKey, string issuer, AccessTokenVerifier bearer)
{
    readonly NonceStore _nonces = new();
    readonly object _gate = new();
    DisabledCheck _disabled;

    // Each hostile case owns its nonce store; normal HTTP admission never selects a fault.
    public GrantAdmission FreshReplayState(DisabledCheck disabled = DisabledCheck.None) => new(publicKey, issuer, bearer) { _disabled = disabled };

    public async Task Admit(string method, string path, Header[] headers)
    {
        ValidateHeaders(headers, _disabled);
        string Read(string name) => headers.First(header => header.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
        var envelope = headers.FirstOrDefault(header => header.Name.Equals("x-cratis-forwarded-identity-signature", StringComparison.OrdinalIgnoreCase))?.Value;
        if (envelope is null && _disabled != DisabledCheck.Envelope) throw new Rejected("missing-envelope");
        var authorization = Read("authorization");
        var verified = await bearer.Verify(authorization);
        if (Read("x-cratis-credential-kind") != "oauth-grant") throw new Rejected("kind");
        if (Read("x-cratis-credential-id") != "00000000-0000-4000-8000-000000000348") throw new Rejected("credential");
        var inputs = new Inputs(method, path, "grant-receiver", DateTimeOffset.UtcNow.ToUnixTimeSeconds(), headers,
            TenantHeader: "x-cratis-tenant-id", AuthenticatedTls: true, RealmIssuer: issuer, VerifiedBearer: verified.Bearer);
        if (envelope is not null) VerifyEnvelope(inputs, envelope);
        ValidateEvidence(Read, verified.AuthTime);
        if (headers.Any(header => header.Name is "x-cratis-act" or "x-cratis-grant-id")) throw new Rejected("unexpected-actor");
    }

    void VerifyEnvelope(Inputs inputs, string envelope)
    {
        var vector = new Vector("live", inputs, envelope, "", new("", ""));
        TestKey[] keys = [new("runtime", ["runtime-key"], "", publicKey)];
        Outcome outcome;
        lock (_gate)
        {
            outcome = _disabled is DisabledCheck.Signature or DisabledCheck.BearerBinding or DisabledCheck.Replay
                ? Reference.VerifyWithDisabledCheck(vector, keys, _nonces, _disabled)
                : Reference.Verify(vector, keys, _nonces);
        }
        if (outcome.Result != "accept") throw new Rejected(outcome.Reason);
    }

    void ValidateEvidence(Func<string, string> read, long authTime)
    {
        var expected = new Dictionary<string, string>
        {
            ["x-cratis-sender-binding"] = "none",
            ["x-cratis-policy-epoch"] = "7",
            ["x-cratis-subject"] = "00000000-0000-4000-8000-000000000347",
            ["x-cratis-issuer"] = issuer,
            ["x-cratis-tenant-id"] = "4f1d2c1e-6f1b-4d3b-9a46-5e2f2a7a2b10",
            ["x-cratis-idp"] = "local-issuer",
            ["x-cratis-acr"] = "basic",
            ["x-ms-client-principal-name"] = "grant-person",
            ["x-cratis-token-client-id"] = "local-client",
            ["x-cratis-token-scope"] = "grants.read"
        };
        foreach (var pair in expected)
            if (read(pair.Key) != pair.Value) throw new Rejected($"evidence:{pair.Key}");
        if (read("x-cratis-auth-time") != authTime.ToString(CultureInfo.InvariantCulture)) throw new Rejected("auth-time");
        using var amr = JsonDocument.Parse(Convert.FromBase64String(read("x-cratis-amr")));
        if (amr.RootElement.GetArrayLength() != 1 || amr.RootElement[0].GetString() != "pwd") throw new Rejected("amr");
    }

    public static void ValidateHeaders(Header[] headers) => ValidateHeaders(headers, DisabledCheck.None);

    static void ValidateHeaders(Header[] headers, DisabledCheck disabled)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "x-cratis-credential-kind", "x-cratis-credential-id", "x-cratis-issuer", "x-cratis-subject", "x-cratis-idp",
            "x-cratis-auth-time", "x-cratis-acr", "x-cratis-amr", "x-cratis-act", "x-cratis-grant-id", "x-cratis-policy-epoch",
            "x-cratis-sender-binding", "x-cratis-tenant-id", "x-cratis-forwarded-identity-signature", "x-cratis-forwarded-token-sha256",
            "x-cratis-token-client-id", "x-cratis-token-scope", "x-cratis-microservice"
        };
        foreach (var header in headers)
        {
            if (!names.Add(header.Name) && disabled != DisabledCheck.DuplicateHeader) throw new Rejected("duplicate-header");
            if (header.Value.Any(InvalidCharacter)) throw new Rejected("control-header");
            if (UnknownContext(header.Name, allowed) && disabled != DisabledCheck.UnknownHeader) throw new Rejected("unknown-header");
        }
    }

    static bool InvalidCharacter(char character) => character < 32 || character > 126;
    static bool UnknownContext(string name, HashSet<string> allowed) => name.StartsWith("x-cratis-", StringComparison.OrdinalIgnoreCase) && !allowed.Contains(name);
}
