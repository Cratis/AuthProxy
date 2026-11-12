// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Specifications;

namespace Cratis.AuthProxy.Security.for_ArcCratisPaths;

[Collection(ArcCratisSpecCollection.Name)]
public class when_the_provider_list_is_requested(ArcCratisHarness harness) : given.an_arc_proxy(harness)
{
    HttpStatusCode _status;

    async Task Because()
    {
        using var request = Request("/.cratis/providers");
        using var response = await Client.SendAsync(request, Deadline.Token);
        _status = response.StatusCode;
    }

    [Fact] void should_answer_from_authproxy() => _status.ShouldEqual(HttpStatusCode.OK);
    [Fact] void should_not_contact_the_arc_origin() => Harness.Arc.Received.ShouldBeEmpty();
}
