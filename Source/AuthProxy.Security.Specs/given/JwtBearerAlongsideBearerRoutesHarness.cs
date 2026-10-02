// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// The bearer-route deployment of <see cref="BearerRouteHarness"/>, with the general JWT Bearer handler also
/// configured to trust the bearer routes' issuer.
/// </summary>
/// <remarks>
/// This is the deployment in which a bearer-route token could reach a browser-only surface at all: the JWT Bearer
/// handler would accept it on any path. The proxy's own authentication scheme selection is kept — no stand-in
/// session handler — so the scheme that would accept the token is the one that actually runs.
/// <para>
/// The JWT Bearer settings are given with <c language="text">UseSetting</c> because the proxy decides whether to
/// register the handler while the application is being built.
/// </para>
/// </remarks>
public class JwtBearerAlongsideBearerRoutesHarness : BearerRouteHarness
{
    /// <summary>
    /// An issuer the JWT Bearer handler also trusts and no bearer route names, so a spec can show the handler
    /// accepts a token at all.
    /// </summary>
    public const string OtherIssuer = "https://machine-to-machine.example.test/";

    /// <inheritdoc/>
    protected override bool UsesHeaderAuthentication => false;

    /// <inheritdoc/>
    protected override void ConfigureHost(IWebHostBuilder builder)
    {
        const string jwtBearer = $"{C.Authentication.SectionKey}:JwtBearer";

        builder
            .UseSetting($"{jwtBearer}:Authority", Issuer.Issuer)
            .UseSetting($"{jwtBearer}:MetadataAddress", $"{Issuer.Issuer}.well-known/oauth-authorization-server")
            .UseSetting($"{jwtBearer}:RequireHttpsMetadata", "false")
            .UseSetting($"{jwtBearer}:Audience", Audience)
            .UseSetting($"{jwtBearer}:TokenValidationParameters:ValidIssuers:0", OtherIssuer);
    }
}
