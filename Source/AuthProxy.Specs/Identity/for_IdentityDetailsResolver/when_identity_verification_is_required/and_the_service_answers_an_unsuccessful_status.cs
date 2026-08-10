// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// Every non-success status other than <c>403</c> used to be logged and then ignored, so a bad request, an
/// expired back-channel credential, a routing mistake and a whole backend being down were all as good as a
/// yes. Only <c>403</c> denied, which made the safe answer depend on a misconfigured service choosing
/// exactly the right code to refuse with.
/// <para>
/// Written across the range rather than one code per file because the behavior under specification is a
/// single rule — "carries no verdict, therefore no" — and the interesting thing is that no member of the
/// range escapes it. A fresh caller per status keeps the in-memory result of one from standing in for the
/// next.
/// </para>
/// </summary>
public class and_the_service_answers_an_unsuccessful_status : given.a_required_verification_resolver
{
    static readonly HttpStatusCode[] _statuses =
    [
        HttpStatusCode.BadRequest,
        HttpStatusCode.Unauthorized,
        HttpStatusCode.NotFound,
        HttpStatusCode.InternalServerError,
        HttpStatusCode.BadGateway,
        HttpStatusCode.ServiceUnavailable
    ];

    readonly List<HttpStatusCode> _authorizedFor = [];
    readonly List<int> _responseStatuses = [];

    async Task Because()
    {
        foreach (var status in _statuses)
        {
            _handler.Respond = (_, _, _) => Task.FromResult(Response(status, "an unbounded downstream error body"));

            var context = new DefaultHttpContext();
            var result = await _resolver.Resolve(context, Principal($"user-{(int)status}"), TenantId);

            _responseStatuses.Add(context.Response.StatusCode);
            if (result.IsAuthorized)
            {
                _authorizedFor.Add(status);
            }
        }
    }

    [Fact] void should_authorize_for_none_of_them() => _authorizedFor.ShouldBeEmpty();
    [Fact] void should_serve_the_forbidden_status_for_all_of_them() => _responseStatuses.Distinct().ShouldContainOnly([StatusCodes.Status403Forbidden]);
    [Fact] void should_have_asked_the_service_for_each_of_them() => _handler.Calls.ShouldEqual(_statuses.Length);
}
