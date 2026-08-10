// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// A successful status with nothing in it is the most misleading of the failure shapes: it looks like the
/// happy path to every layer that only checks the status code. <c>204 No Content</c>, an empty body and a
/// body of whitespace all state a verdict nowhere, so none of them may be read as one.
/// </summary>
public class and_the_service_answers_nothing_to_read : given.a_required_verification_resolver
{
    static readonly (string Label, HttpStatusCode Status, string Body)[] _answers =
    [
        ("no-content", HttpStatusCode.NoContent, ""),
        ("empty-body", HttpStatusCode.OK, ""),
        ("blank-body", HttpStatusCode.OK, "   \r\n  ")
    ];

    readonly List<string> _authorizedFor = [];

    async Task Because()
    {
        foreach (var (label, status, body) in _answers)
        {
            _handler.Respond = (_, _, _) => Task.FromResult(Response(status, body));

            var result = await _resolver.Resolve(new DefaultHttpContext(), Principal($"user-{label}"), TenantId);
            if (result.IsAuthorized)
            {
                _authorizedFor.Add(label);
            }
        }
    }

    [Fact] void should_authorize_for_none_of_them() => _authorizedFor.ShouldBeEmpty();
    [Fact] void should_have_asked_the_service_for_each_of_them() => _handler.Calls.ShouldEqual(_answers.Length);
}
