// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteWarnings;

/// <summary>
/// A bearer route never calls <c language="text">/.cratis/me</c>, so the <c language="text">403</c> veto a best-effort service
/// applies to a browser session never applies to a token. That is reported at startup, naming every service whose
/// veto is not applied, unless the route states it accepts it — and it is not reported when no service would have
/// been asked.
/// </summary>
public class when_a_route_does_not_consult_identity_verification : Specification
{
    BearerRouteWarning[] _notAccepting;
    BearerRouteWarning[] _accepting;
    BearerRouteWarning[] _nothingConsulted;

    void Because()
    {
        _notAccepting = Warnings(accept: false, participates: true);
        _accepting = Warnings(accept: true, participates: true);
        _nothingConsulted = Warnings(accept: false, participates: false);
    }

    [Fact] void should_report_the_route() => _notAccepting.Length.ShouldEqual(1);
    [Fact] void should_name_the_route() => _notAccepting[0].Prefix.ShouldEqual("/mcp");
    [Fact] void should_name_every_service_whose_veto_is_not_applied() => _notAccepting[0].Subjects.ShouldContainOnly(["direct", "lobby"]);
    [Fact] void should_not_report_a_route_accepting_callers_without_it() => _accepting.ShouldBeEmpty();
    [Fact] void should_not_report_a_route_when_no_service_is_consulted() => _nothingConsulted.ShouldBeEmpty();

    static BearerRouteWarning[] Warnings(bool accept, bool participates) =>
        [.. BearerRouteWarnings.For(Configuration(accept, participates))
            .Where(_ => _.Kind == BearerRouteWarningKind.IdentityVerificationNotConsulted)];

    static C.AuthProxy Configuration(bool accept, bool participates) => new()
    {
        Services = new Dictionary<string, C.Service>
        {
            ["direct"] = new()
            {
                Backend = new C.ServiceEndpoint { BaseUrl = "https://direct.example.test" },
                ResolveIdentityDetails = participates,
                BearerRoutes =
                [
                    new()
                    {
                        PathPrefix = "/mcp",
                        Issuers = [new C.BearerIssuer { Issuer = "https://auth.example.test/" }],
                        Audiences = ["direct-api"],
                        AcceptWithoutIdentityVerification = accept,
                    },
                ],
            },
            ["lobby"] = new()
            {
                Backend = new C.ServiceEndpoint { BaseUrl = "https://lobby.example.test" },
                ResolveIdentityDetails = participates,
            },
            ["static"] = new()
            {
                Backend = new C.ServiceEndpoint { BaseUrl = "https://static.example.test" },
                ResolveIdentityDetails = false,
            },
        },
    };
}
