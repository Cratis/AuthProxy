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
        var passed = new List<string>();
        await Reject("tampered", Replace(captured, "x-cratis-subject", "00000000-0000-0000-0000-000000000999"));
        var envelope = captured.Single(header => header.Name.Equals("x-cratis-forwarded-identity-signature", StringComparison.OrdinalIgnoreCase)).Value;
        await Reject("forged", Replace(captured, "x-cratis-forwarded-identity-signature", envelope[..(envelope.LastIndexOf('.') + 1)] + new string('A', 86)));
        await Reject("stripped", captured.Where(header => !header.Name.Equals("x-cratis-forwarded-identity-signature", StringComparison.OrdinalIgnoreCase)).ToArray());
        await Reject("replayed", captured);
        await Reject("swapped-bearer", Replace(captured, "Authorization", $"Bearer {replacementToken}"));
        await Reject("duplicate-envelope", [.. captured, captured.Single(header => header.Name.Equals("x-cratis-forwarded-identity-signature", StringComparison.OrdinalIgnoreCase))]);
        await Reject("unknown-context", [.. captured, new("x-cratis-unknown", "untrusted")]);
        await Reject("altered-method", captured, method: "DELETE");
        await Reject("altered-target", captured, path: _path + "?untrusted=1");
        return passed.ToArray();

        async Task Reject(string name, Header[] headers, string? method = null, string? path = null)
        {
            try { await admission.Admit(method ?? _method, path ?? _path, headers); }
            catch (Exception error) when (ReceiverErrors.IsRejection(error)) { passed.Add(name); return; }
            throw new InvalidOperationException($"Hostile request admitted: {name}");
        }
    }

    static Header[] Replace(Header[] headers, string name, string value) => headers.Select(header => header.Name.Equals(name, StringComparison.OrdinalIgnoreCase) ? new Header(header.Name, value) : header).ToArray();
}
