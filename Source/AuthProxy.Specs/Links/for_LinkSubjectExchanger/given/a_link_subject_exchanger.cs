// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Links.for_LinkSubjectExchanger.given;

public class a_link_subject_exchanger : Specification
{
    protected const string ExchangeUrl = "https://studio.example.com/api/internal/identity-providers/link";
    protected const string LinkToken = "the-one-time-link-token";

    protected LinkSubjectExchanger _exchanger;
    protected RecordingHttpMessageHandler _handler;
    protected IOptionsMonitor<C.AuthProxy> _config;
    protected ClaimsPrincipal _principal;
    protected AuthenticationProperties _properties;

    protected virtual C.AuthProxy CreateConfig() => new() { Link = new C.Link { ExchangeUrl = ExchangeUrl } };

    protected virtual HttpStatusCode ExchangeStatusCode => HttpStatusCode.OK;

    protected virtual ClaimsPrincipal CreatePrincipal() => new(new ClaimsIdentity(
    [
        new Claim("sub", "linked-subject-123"),
        new Claim("iss", "https://github.com"),
    ],
    "github"));

    protected virtual AuthenticationProperties CreateProperties()
    {
        var properties = new AuthenticationProperties();
        properties.Items[LinkMiddleware.LinkTokenPropertyKey] = LinkToken;
        return properties;
    }

    protected virtual LinkSubjectExchanger CreateExchanger(
        C.AuthProxy configuration,
        IOptionsMonitor<C.AuthProxy> optionsMonitor,
        IHttpClientFactory httpClientFactory) =>
        new(optionsMonitor, httpClientFactory, Substitute.For<ILogger<LinkSubjectExchanger>>());

    void Establish()
    {
        var configuration = CreateConfig();
        _config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        _config.CurrentValue.Returns(configuration);

        _handler = new RecordingHttpMessageHandler(ExchangeStatusCode);
        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(_handler));

        _principal = CreatePrincipal();

        _properties = CreateProperties();

        _exchanger = CreateExchanger(configuration, _config, httpClientFactory);
    }
}
