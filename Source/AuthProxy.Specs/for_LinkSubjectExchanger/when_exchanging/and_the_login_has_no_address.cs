// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text.Json;
using Cratis.AuthProxy.Links;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.for_LinkSubjectExchanger.when_exchanging;

public class and_the_login_has_no_address : Specification
{
    CapturingHandler _handler;
    LinkSubjectExchanger _exchanger;
    ClaimsPrincipal _principal;
    AuthenticationProperties _properties;

    void Establish()
    {
        _handler = new(HttpStatusCode.OK);
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(_handler, disposeHandler: false));
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy { Link = new C.Link { ExchangeUrl = "https://app.example/link" } });
        _exchanger = new(config, factory, Substitute.For<ILogger<LinkSubjectExchanger>>());
        _principal = new(new ClaimsIdentity([new Claim("sub", "subject-1")], "github"));
        _properties = new();
        _properties.Items[LinkMiddleware.LinkTokenPropertyKey] = "one-time-token";
    }

    async Task Because() => await _exchanger.Exchange(_principal, _properties, "github");

    [Fact] void should_leave_the_address_out() => Body().TryGetProperty("email", out _).ShouldBeFalse();

    [Fact] void should_leave_the_verification_out() => Body().TryGetProperty("emailVerified", out _).ShouldBeFalse();

    JsonElement Body() => JsonElement.Parse(_handler.Body);

    sealed class CapturingHandler(HttpStatusCode status) : HttpMessageHandler
    {
        public string Body { get; private set; } = string.Empty;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Body = await request.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(status);
        }
    }
}
