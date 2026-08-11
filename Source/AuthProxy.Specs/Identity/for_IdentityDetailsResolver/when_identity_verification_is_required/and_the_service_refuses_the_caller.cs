// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// An outright refusal still denies, and now in both of the ways a service can express it: the <c>403</c>
/// that used to be the only path to a denial at all, and a well-formed body whose verdict is no. The second
/// is what a service reaching for the documented response shape actually writes.
/// </summary>
public class and_the_service_refuses_the_caller : given.a_required_verification_resolver
{
    static readonly (string Label, HttpStatusCode Status, string Body)[] _answers =
    [
        ("forbidden-status", HttpStatusCode.Forbidden, ""),
        ("negative-verdict", HttpStatusCode.OK, NegativeBody)
    ];

    readonly List<string> _authorizedFor = [];
    readonly List<int> _responseStatuses = [];

    async Task Because()
    {
        foreach (var (label, status, body) in _answers)
        {
            _handler.Respond = (_, _, _) => Task.FromResult(Response(status, body));

            var context = new DefaultHttpContext();
            var result = await _resolver.Resolve(context, Principal($"user-{label}"), TenantId);

            _responseStatuses.Add(context.Response.StatusCode);
            if (result.IsAuthorized)
            {
                _authorizedFor.Add(label);
            }
        }
    }

    [Fact] void should_authorize_for_neither_of_them() => _authorizedFor.ShouldBeEmpty();
    [Fact] void should_serve_the_forbidden_status_for_both() => _responseStatuses.Distinct().ShouldContainOnly([StatusCodes.Status403Forbidden]);
    [Fact] void should_clear_the_recorded_authorization_for_both() => _authorizationCache.Received(2).Clear(Arg.Any<HttpContext>());
}
