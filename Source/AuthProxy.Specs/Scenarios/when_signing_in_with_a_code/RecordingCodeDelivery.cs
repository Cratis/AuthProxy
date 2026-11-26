// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Code;

namespace Cratis.AuthProxy.Scenarios.when_signing_in_with_a_code;

/// <summary>
/// Stands in for the application: records the codes it was asked to send and knows one address.
/// </summary>
/// <param name="knownDomain">The domain of the addresses the application accepts.</param>
/// <param name="subject">The subject it names for those addresses.</param>
public sealed class RecordingCodeDelivery(string knownDomain, string subject) : ICodeDelivery
{
    readonly List<CodeRequest> _requests = [];

    public int CountFor(string address)
    {
        lock (_requests)
        {
            return _requests.Count(_ => _.Email == address);
        }
    }

    public CodeRequest For(string address)
    {
        lock (_requests)
        {
            return _requests.Single(_ => _.Email == address);
        }
    }

    public Task<string?> Deliver(C.CodeSignIn settings, CodeRequest request)
    {
        lock (_requests)
        {
            _requests.Add(request);
        }

        return Task.FromResult<string?>(request.Email.EndsWith(knownDomain, StringComparison.Ordinal) ? subject : null);
    }
}
