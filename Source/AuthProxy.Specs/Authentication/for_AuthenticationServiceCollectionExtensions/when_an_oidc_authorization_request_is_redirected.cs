// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that configured authorization parameters reach the authorization request of their provider only.
/// </summary>
public class when_an_oidc_authorization_request_is_redirected : given.gated_oidc_providers
{
    OpenIdConnectMessage _strictMessage;
    OpenIdConnectMessage _relaxedMessage;

    async Task Because()
    {
        _strictMessage = await Redirect("strict", _strictOptions);
        _relaxedMessage = await Redirect("relaxed", _relaxedOptions);
    }

    [Fact] void should_add_the_configured_parameter() => _strictMessage.GetParameter("connection").ShouldEqual("email");
    [Fact] void should_add_a_configured_prompt_when_no_fresh_authentication_is_required() => _strictMessage.GetParameter("prompt").ShouldEqual("login");
    [Fact] void should_not_add_parameters_to_another_provider() => _relaxedMessage.GetParameter("connection").ShouldBeNull();

    async Task<OpenIdConnectMessage> Redirect(string schemeName, OpenIdConnectOptions options)
    {
        var scheme = new AuthenticationScheme(schemeName, schemeName, typeof(OpenIdConnectHandler));
        var message = new OpenIdConnectMessage();
        await options.Events.OnRedirectToIdentityProvider(
            new RedirectContext(Context(), scheme, options, new AuthenticationProperties()) { ProtocolMessage = message });
        return message;
    }
}
