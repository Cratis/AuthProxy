// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ArcCratisPaths;

[Collection(ArcCratisSpecCollection.Name)]
public class when_proxy_owned_paths_are_requested(ArcCratisHarness harness) : given.an_arc_proxy(harness)
{
    [Theory]
    [InlineData("/.cratis/providers/unmatched-child")]
    [InlineData("/.cratis/me/unmatched-child")]
    [InlineData("/.cratis/token/unmatched-child")]
    [InlineData("/.cratis/link/unmatched-child")]
    public async Task should_stay_local_and_never_reach_the_arc_origin(string path)
    {
        using var request = Request(path);
        using var response = await Client.SendAsync(request, Deadline.Token);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Empty(Harness.Arc.Received);
    }
}
