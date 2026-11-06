// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Mvc.Testing;

namespace Cratis.AuthProxy.Security.for_CredentialBinding;

/// <summary>Real session tickets cannot be replayed into another resource or environment.</summary>
public class when_replaying_a_bound_session
{
    [Theory]
    [InlineData("direct-api", "production")]
    [InlineData("another-api", "staging")]
    public async Task should_refuse_replay_but_accept_the_minting_deployment(string resource, string environment)
    {
        var directory = Directory.CreateTempSubdirectory();
        try
        {
            await using var staging = new BoundSessionHarness("direct-api", "staging", directory.FullName);
            await using var target = new BoundSessionHarness(resource, environment, directory.FullName);
            staging.VerifyEveryCaller();
            target.VerifyEveryCaller();
            var options = new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false };
            using var stagingClient = staging.CreateClient(options);
            using var targetClient = target.CreateClient(options);
            const string path = "/private/session-binding";
            using var accepted = staging.AuthenticatedRequest(path).Message;
            using var replay = new HttpRequestMessage(HttpMethod.Get, path);
            replay.Headers.Add("Cookie", accepted.Headers.GetValues("Cookie"));
            using var control = await stagingClient.SendAsync(accepted, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, control.StatusCode);
            Assert.True(staging.Origin.ReceivedAnythingFor(path));
            using var refused = await targetClient.SendAsync(replay, TestContext.Current.CancellationToken);
            Assert.False(refused.IsSuccessStatusCode);
            Assert.Empty(target.Origin.Received);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }
}
