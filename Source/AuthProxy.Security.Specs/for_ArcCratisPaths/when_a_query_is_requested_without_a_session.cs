// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Specifications;

namespace Cratis.AuthProxy.Security.for_ArcCratisPaths;

[Collection(ArcCratisSpecCollection.Name)]
public class when_a_query_is_requested_without_a_session(ArcCratisHarness harness) : Specification
{
    HttpStatusCode _status;

    async Task Because()
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        using var client = harness.CreateArcClient();
        harness.Arc.Received.Clear();
        using var request = SessionCookieHarness.Request(SessionCookieHarness.ConsoleHost, "/.cratis/queries/sse");
        request.Headers.Accept.ParseAdd("text/event-stream");
        using var response = await client.SendAsync(request, deadline.Token);
        _status = response.StatusCode;
    }

    [Fact] void should_require_a_session() => _status.ShouldEqual(HttpStatusCode.Unauthorized);
    [Fact] void should_not_contact_the_origin() => harness.Arc.Received.ShouldBeEmpty();
}
