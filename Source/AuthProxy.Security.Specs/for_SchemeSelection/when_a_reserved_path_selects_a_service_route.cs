// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;

namespace Cratis.AuthProxy.Security.for_SchemeSelection;

public class when_a_reserved_path_selects_a_service_route
{
    public static IEnumerable<TheoryDataRow<string, string>> Requests()
    {
        string[] paths =
        [
            "/.cratis/login/provider/extra",
            "/.CRATIS/LOGIN/provider/EXTRA",
            "/.cratis/login/provider/extra/",
            "/.cratis/login",
            "/.cratis/logout/extra",
            "/.CRATIS/LOGOUT/CALLBACK/extra/",
            "/%2ecratis/login/provider/extra",
            "/%252ecratis/login/provider/extra",
            "/.cratis%2flogin/provider/extra",
            "/.cratis/login/provider%2fextra",
            "/.cratis/unknown",
        ];
        foreach (var path in paths)
        {
            foreach (var mode in new[] { "mixed", "duplicate", "single" })
            {
                yield return new TheoryDataRow<string, string>(path, mode);
            }
        }
    }

    [Theory]
    [MemberData(nameof(Requests))]
    public async Task should_refuse_without_forwarding(string path, string mode)
    {
        await using var harness = new ReservedPathHarness();
        using var client = harness.CreateSecurityClient();
        var token = harness.JwtToken();
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (mode == "duplicate")
        {
            request.Headers.TryAddWithoutValidation("Authorization", [$"Bearer {token}", $"Bearer {token}"]);
        }
        else
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
        if (mode == "mixed")
        {
            request.Headers.TryAddWithoutValidation("Cookie", $"{C.Session.DefaultCookieName}=invalid-spec-session");
        }

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.True(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.NotFound);
        Assert.Empty(harness.Origin.Received);
    }

    [Fact]
    public async Task should_preserve_an_ordinary_authenticated_service_request()
    {
        await using var harness = new ReservedPathHarness();
        using var client = harness.CreateSecurityClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, RequiredVerificationHarness.ProtectedPath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", harness.JwtToken());
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(harness.Origin.ReceivedAnythingFor(RequiredVerificationHarness.ProtectedPath));
    }
}
