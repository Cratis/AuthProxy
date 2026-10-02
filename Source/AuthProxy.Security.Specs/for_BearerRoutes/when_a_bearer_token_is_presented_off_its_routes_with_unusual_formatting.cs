// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A bearer-route token stays off browser-only surfaces however the <c language="text">Authorization</c> header is
/// written. The JWT Bearer handler trims what follows the scheme, so a second space or a tab would otherwise carry
/// the token past the refusal and into a handler that trusts its issuer. The same holds when the token is one of
/// several <c language="text">Authorization</c> headers.
/// <para>
/// The headers are set on the server-side request directly: an <see cref="HttpClient"/> would parse and re-write
/// them into the canonical form this spec is about avoiding.
/// </para>
/// </summary>
/// <param name="harness">The running proxy, with the JWT Bearer handler trusting the bearer-route issuer.</param>
[Collection(JwtBearerAlongsideBearerRoutesSpecCollection.Name)]
public class when_a_bearer_token_is_presented_off_its_routes_with_unusual_formatting(JwtBearerAlongsideBearerRoutesHarness harness) : IAsyncLifetime
{
    const string Path = "/api/items";

    HttpResponseMessage? _control;
    HttpContext? _doubleSpace;
    HttpContext? _tab;
    HttpContext? _spaceAndTab;
    HttpContext? _lowerCase;
    HttpContext? _secondHeader;
    bool _forwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        // A token the JWT Bearer handler accepts and no bearer route names: the handler is live on this path.
        _control = await client.SendAsync(BearerRouteHarness.WithToken(
            HttpMethod.Get,
            Path,
            harness.Issuer.Token(issuer: JwtBearerAlongsideBearerRoutesHarness.OtherIssuer)));

        harness.Origin.Clear();
        var token = harness.Issuer.Token();
        _doubleSpace = await SendWithRawAuthorization($"Bearer  {token}");
        _tab = await SendWithRawAuthorization($"Bearer\t{token}");
        _spaceAndTab = await SendWithRawAuthorization($"Bearer \t{token} ");
        _lowerCase = await SendWithRawAuthorization($"bearer {token}");
        _secondHeader = await SendWithRawAuthorization("Basic dXNlcjpwYXNz", $"Bearer {token}");
        _forwarded = harness.Origin.ReceivedAnythingFor(Path);
    }

    public Task DisposeAsync()
    {
        _control?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_let_the_jwt_bearer_handler_accept_a_token_from_another_issuer() => Assert.Equal(HttpStatusCode.OK, _control!.StatusCode);
    [Fact] public void should_refuse_it_after_two_spaces() => Assert.Equal(HttpStatusCode.Unauthorized, (HttpStatusCode)_doubleSpace!.Response.StatusCode);
    [Fact] public void should_refuse_it_after_a_tab() => Assert.Equal(HttpStatusCode.Unauthorized, (HttpStatusCode)_tab!.Response.StatusCode);
    [Fact] public void should_refuse_it_after_a_space_and_a_tab() => Assert.Equal(HttpStatusCode.Unauthorized, (HttpStatusCode)_spaceAndTab!.Response.StatusCode);
    [Fact] public void should_refuse_it_under_a_lower_case_scheme() => Assert.Equal(HttpStatusCode.Unauthorized, (HttpStatusCode)_lowerCase!.Response.StatusCode);
    [Fact] public void should_refuse_it_as_one_of_several_headers() => Assert.Equal(HttpStatusCode.Unauthorized, (HttpStatusCode)_secondHeader!.Response.StatusCode);
    [Fact] public void should_challenge_with_invalid_token() => Assert.Equal("Bearer error=\"invalid_token\"", _doubleSpace!.Response.Headers.WWWAuthenticate.ToString());
    [Fact] public void should_not_forward_any_of_them() => Assert.False(_forwarded);

    Task<HttpContext> SendWithRawAuthorization(params string[] values) =>
        harness.Server.SendAsync(context =>
        {
            context.Request.Method = HttpMethods.Get;
            context.Request.Path = Path;
            context.Request.Headers.Authorization = new StringValues(values);
        });
}
