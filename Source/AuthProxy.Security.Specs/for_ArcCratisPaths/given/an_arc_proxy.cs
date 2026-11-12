// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Specifications;

namespace Cratis.AuthProxy.Security.for_ArcCratisPaths.given;

public class an_arc_proxy(ArcCratisHarness harness) : Specification
{
    protected ArcCratisHarness Harness { get; } = harness;
    protected HttpClient Client;
    protected string[] Cookies = [];
    protected CancellationTokenSource Deadline;

    async Task Establish()
    {
        Deadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        Deadline.CancelAfter(TimeSpan.FromSeconds(5));
        Client = Harness.CreateArcClient();
        using var request = SessionCookieHarness.Request(SessionCookieHarness.ConsoleHost, SessionCookieHarness.SignInPath);
        using var response = await Client.SendAsync(request, Deadline.Token);
        response.StatusCode.ShouldEqual(HttpStatusCode.NoContent);
        Cookies = SessionCookieHarness.SessionFrom(response);
        Cookies.Length.ShouldBeGreaterThan(0);
        Harness.Arc.Reset();
    }

    protected HttpRequestMessage Request(string path) => SessionCookieHarness.Request(SessionCookieHarness.ConsoleHost, path, Cookies);

    void Destroy()
    {
        Client.Dispose();
        Deadline.Dispose();
    }
}
