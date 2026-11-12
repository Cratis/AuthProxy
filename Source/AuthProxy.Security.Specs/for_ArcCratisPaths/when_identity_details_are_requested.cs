// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Specifications;

namespace Cratis.AuthProxy.Security.for_ArcCratisPaths;

/// <summary>
/// Arc also maps <c language="text">/.cratis/me</c>, but AuthProxy owns it: it answers the browser itself and only calls the
/// origin's own endpoint as a back-channel identity call. Anything below it never reaches the origin.
/// </summary>
/// <param name="harness">The shared Arc harness.</param>
[Collection(ArcCratisSpecCollection.Name)]
public class when_identity_details_are_requested(ArcCratisHarness harness) : given.an_arc_proxy(harness)
{
    HttpStatusCode _childStatus;
    bool _owned;
    int _forwardedChildren;

    async Task Because()
    {
        _owned = WellKnownPaths.AuthProxyOwned.Contains("/.cratis/me");
        using var request = Request("/.cratis/me/details");
        using var response = await Client.SendAsync(request, Deadline.Token);
        _childStatus = response.StatusCode;
        _forwardedChildren = Harness.Arc.Received.Count;
    }

    [Fact] void should_declare_the_path_as_owned_by_authproxy() => _owned.ShouldBeTrue();
    [Fact] void should_not_serve_children_of_the_path() => _childStatus.ShouldEqual(HttpStatusCode.NotFound);
    [Fact] void should_not_forward_children_of_the_path_to_the_origin() => _forwardedChildren.ShouldEqual(0);
}
