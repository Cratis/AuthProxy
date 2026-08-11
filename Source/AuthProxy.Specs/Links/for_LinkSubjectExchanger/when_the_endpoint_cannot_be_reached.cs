// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Links.for_LinkSubjectExchanger;

/// <summary>
/// The exchange is the one step that leaves the process, so an unreachable endpoint is an operating
/// condition, not a bug. It has to come back as a bounded failure the callback can answer — an exception
/// escaping here would surface in the browser as a blank error page instead.
/// </summary>
public class when_the_endpoint_cannot_be_reached : Specification
{
    const string ExchangeUrl = "https://studio.example.com/api/internal/identity-providers/link";

    LinkSubjectExchanger _exchanger;
    ClaimsPrincipal _principal;
    AuthenticationProperties _properties;
    LinkExchangeResult _result;
    Exception _error;

    void Establish()
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy { Link = new C.Link { ExchangeUrl = ExchangeUrl } });

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new ThrowingHttpMessageHandler()));

        _exchanger = new LinkSubjectExchanger(config, httpClientFactory, Substitute.For<ILogger<LinkSubjectExchanger>>());

        _principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "linked-subject-123")], "github"));
        _properties = new AuthenticationProperties();
        _properties.Items[LinkMiddleware.LinkTokenPropertyKey] = "the-one-time-link-token";
    }

    async Task Because() => _error = await Catch.Exception(Exchange);

    [Fact] void should_not_throw() => _error.ShouldBeNull();
    [Fact] void should_fail() => _result.ShouldEqual(LinkExchangeResult.Failed);

    async Task Exchange() => _result = await _exchanger.Exchange(_principal, _properties);
}
