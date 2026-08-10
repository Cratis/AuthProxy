// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// A well-formed answer that states no verdict is the case a fail-closed mode must not be tempted by,
/// because it is indistinguishable from a healthy service until you look for the verdict. An empty object,
/// a bare details object, a verdict spelled as a string, and a verdict that contradicts itself all state
/// nothing this proxy is entitled to act on.
/// <para>
/// A service that is only being asked for enrichment answers exactly like this, which is the point: the
/// same body is complete for one question and silent on the other.
/// </para>
/// </summary>
public class and_the_service_answers_no_verdict : given.a_required_verification_resolver
{
    static readonly (string Label, string Body)[] _answers =
    [
        ("empty-object", /*lang=json,strict*/ "{}"),
        ("details-only", /*lang=json,strict*/ "{\"displayName\":\"John Doe\"}"),
        ("quoted-verdict", /*lang=json,strict*/ "{\"isAuthorized\":\"true\"}"),
        ("conflicting-verdict", /*lang=json,strict*/ "{\"isAuthenticated\":false,\"isAuthorized\":true}")
    ];

    readonly List<string> _authorizedFor = [];

    async Task Because()
    {
        foreach (var (label, body) in _answers)
        {
            _handler.Respond = (_, _, _) => Task.FromResult(Response(HttpStatusCode.OK, body));

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
