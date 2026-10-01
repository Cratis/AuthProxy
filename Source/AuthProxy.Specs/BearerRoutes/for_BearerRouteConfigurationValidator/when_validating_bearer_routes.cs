// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteConfigurationValidator;

/// <summary>
/// A bearer route AuthProxy cannot enforce as written is left on the browser-session model, which is closed but
/// invisible: the operator believes an API is served and every client is sent to sign in. Each such mistake is
/// refused at startup instead, and a deployment without bearer routes is not affected at all.
/// </summary>
public class when_validating_bearer_routes : Specification
{
    ValidateOptionsResult _valid;
    ValidateOptionsResult _withoutRoutes;
    ValidateOptionsResult _withoutAudience;
    ValidateOptionsResult _withPlainHttpIssuer;
    ValidateOptionsResult _overlappingAnonymousPath;
    ValidateOptionsResult _withoutBackend;
    ValidateOptionsResult _withLargeClockSkew;
    ValidateOptionsResult _mappingIntoReservedClaim;
    ValidateOptionsResult _withQuotedScope;
    ValidateOptionsResult _withoutIssuers;
    ValidateOptionsResult _withRootPrefix;
    ValidateOptionsResult _withProxyOwnedPrefix;
    ValidateOptionsResult _withPlainHttpResourceMetadata;
    ValidateOptionsResult _prefixOfAnotherService;
    ValidateOptionsResult _resourceMetadataOfAnotherService;
    ValidateOptionsResult _withEmptyMapping;
    ValidateOptionsResult _mappingIntoRoles;
    ValidateOptionsResult _verificationRequired;
    ValidateOptionsResult _verificationRequiredByAnotherService;
    ValidateOptionsResult _verificationRequiredAndAcceptedWithout;
    ValidateOptionsResult _verificationRequiredOfANonParticipant;
    ValidateOptionsResult _withRouteRequirement;
    ValidateOptionsResult _withRouteRequirementNamingNoClaim;
    ValidateOptionsResult _withRouteRequirementOnARole;
    ValidateOptionsResult _mappingIntoTenant;
    ValidateOptionsResult _mappingIntoCustomTenant;
    ValidateOptionsResult _mappingIntoDefaultTenant;
    ValidateOptionsResult _conflictingMappingTargets;

    void Because()
    {
        var validator = new BearerRouteConfigurationValidator();

        _valid = validator.Validate(null, Configuration(_ => { }));
        _withoutRoutes = validator.Validate(null, Configuration(_ => _.PathPrefix = string.Empty, declareRoute: false));
        _withoutAudience = validator.Validate(null, Configuration(_ => _.Audiences = []));
        _withPlainHttpIssuer = validator.Validate(null, Configuration(_ => _.Issuers = [new C.BearerIssuer { Issuer = "http://auth.example.test/" }]));
        _overlappingAnonymousPath = validator.Validate(null, Configuration(_ => _.PathPrefix = "/public/mcp"));
        _withoutBackend = validator.Validate(null, Configuration(_ => { }, backend: false));
        _withLargeClockSkew = validator.Validate(null, Configuration(_ => _.ClockSkew = TimeSpan.FromHours(1)));
        _mappingIntoReservedClaim = validator.Validate(null, Configuration(_ => _.ClaimMappings = new Dictionary<string, string> { ["urn:cratis:bearer:scope"] = "scope" }));
        _withQuotedScope = validator.Validate(null, Configuration(_ => _.RequiredScopes = ["direct:\"read"]));
        _withoutIssuers = validator.Validate(null, Configuration(_ => _.Issuers = []));
        _withRootPrefix = validator.Validate(null, Configuration(_ => _.PathPrefix = "/"));
        _withProxyOwnedPrefix = validator.Validate(null, Configuration(_ => _.PathPrefix = "/.cratis/mcp"));
        _withPlainHttpResourceMetadata = validator.Validate(null, Configuration(_ => _.ResourceMetadataUrl = "http://direct.example.test/.well-known/oauth-protected-resource/mcp"));
        _prefixOfAnotherService = validator.Validate(null, Configuration(_ => { }, adjustConfiguration: _ => _.Services["other"] = Service(Route())));
        _resourceMetadataOfAnotherService = validator.Validate(null, Configuration(_ => { }, adjustConfiguration: _ => _.Services["other"] = Service(Route(prefix: "/v1"))));
        _withEmptyMapping = validator.Validate(null, Configuration(_ => _.ClaimMappings = new Dictionary<string, string> { ["sub"] = " " }));
        _mappingIntoRoles = validator.Validate(null, Configuration(_ => _.ClaimMappings = new Dictionary<string, string> { ["roles"] = "groups" }));
        _mappingIntoTenant = validator.Validate(null, Configuration(_ => _.ClaimMappings = new Dictionary<string, string> { ["TID"] = "another_tenant" }));
        _mappingIntoCustomTenant = validator.Validate(null, Configuration(_ =>
        {
            _.TenantClaimType = " tenant ";
            _.ClaimMappings = new Dictionary<string, string> { ["tenant"] = "another_tenant" };
        }));
        _mappingIntoDefaultTenant = validator.Validate(null, Configuration(_ =>
        {
            _.TenantClaimType = " ";
            _.ClaimMappings = new Dictionary<string, string> { ["tid"] = "another_tenant" };
        }));
        _conflictingMappingTargets = validator.Validate(null, Configuration(_ => _.ClaimMappings = new Dictionary<string, string>
        {
            ["sub"] = "github_id",
            ["SUB"] = "another_id",
        }));
        _verificationRequired = validator.Validate(null, Configuration(_ => { }, adjustConfiguration: _ => _.Services["main"].IdentityVerification = C.IdentityVerificationMode.Required));
        _verificationRequiredByAnotherService = validator.Validate(null, Configuration(_ => { }, adjustConfiguration: _ => _.Services["other"] = RequiringVerification(new C.Service { Backend = new C.ServiceEndpoint { BaseUrl = "https://other.example.test" } })));
        _verificationRequiredAndAcceptedWithout = validator.Validate(null, Configuration(_ => _.AcceptWithoutIdentityVerification = true, adjustConfiguration: _ => _.Services["main"].IdentityVerification = C.IdentityVerificationMode.Required));
        _withRouteRequirement = validator.Validate(null, Configuration(_ =>
        {
            _.IgnoreDeploymentRequiredClaims = true;
            _.RequiredClaims = [new C.ClaimRequirement { Claim = "urn:cratis:membership", AnyOf = ["direct"] }];
        }));
        _withRouteRequirementNamingNoClaim = validator.Validate(null, Configuration(_ => _.RequiredClaims = [new C.ClaimRequirement { Claim = " ", AnyOf = ["direct"] }]));
        _withRouteRequirementOnARole = validator.Validate(null, Configuration(_ => _.RequiredClaims = [new C.ClaimRequirement { Claim = "roles", AnyOf = ["admin"] }]));
        _verificationRequiredOfANonParticipant = validator.Validate(null, Configuration(_ => { }, adjustConfiguration: _ => _.Services["other"] = RequiringVerification(new C.Service { Backend = new C.ServiceEndpoint { BaseUrl = "https://other.example.test" }, ResolveIdentityDetails = false })));
    }

    [Fact] void should_accept_a_complete_route() => _valid.Succeeded.ShouldBeTrue();
    [Fact] void should_leave_a_deployment_without_bearer_routes_alone() => _withoutRoutes.Succeeded.ShouldBeTrue();
    [Fact] void should_refuse_a_route_without_an_audience() => _withoutAudience.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_plain_http_issuer_off_loopback() => _withPlainHttpIssuer.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_route_overlapping_an_anonymous_path() => _overlappingAnonymousPath.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_route_on_a_service_without_a_backend() => _withoutBackend.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_clock_skew_beyond_the_maximum() => _withLargeClockSkew.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_mapping_into_a_claim_authproxy_owns() => _mappingIntoReservedClaim.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_scope_that_is_not_a_scope_token() => _withQuotedScope.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_route_without_an_issuer() => _withoutIssuers.Failed.ShouldBeTrue();
    [Fact] void should_refuse_the_root_as_a_prefix() => _withRootPrefix.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_prefix_under_a_path_the_proxy_owns() => _withProxyOwnedPrefix.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_plain_http_resource_metadata_url_off_loopback() => _withPlainHttpResourceMetadata.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_prefix_another_service_already_routes() => _prefixOfAnotherService.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_resource_metadata_path_another_service_already_serves() => _resourceMetadataOfAnotherService.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_mapping_with_an_empty_claim_type() => _withEmptyMapping.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_mapping_into_a_role_claim() => _mappingIntoRoles.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_route_when_its_service_requires_identity_verification() => _verificationRequired.Failed.ShouldBeTrue();
    [Fact] void should_name_the_setting_that_accepts_it() => _verificationRequired.FailureMessage.ShouldContain(nameof(C.BearerRoute.AcceptWithoutIdentityVerification));
    [Fact] void should_refuse_a_route_when_another_service_requires_identity_verification() => _verificationRequiredByAnotherService.Failed.ShouldBeTrue();
    [Fact] void should_accept_a_route_that_accepts_callers_without_identity_verification() => _verificationRequiredAndAcceptedWithout.Succeeded.ShouldBeTrue();
    [Fact] void should_accept_a_route_declaring_its_own_claim_requirements() => _withRouteRequirement.Succeeded.ShouldBeTrue();
    [Fact] void should_refuse_a_route_requirement_naming_no_claim() => _withRouteRequirementNamingNoClaim.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_route_requirement_on_a_role_a_token_never_carries() => _withRouteRequirementOnARole.Failed.ShouldBeTrue();
    [Fact] void should_ignore_a_verification_requirement_of_a_service_that_resolves_no_identity() => _verificationRequiredOfANonParticipant.Succeeded.ShouldBeTrue();

    [Fact] void should_refuse_a_mapping_into_a_case_variant_of_the_tenant_claim() => _mappingIntoTenant.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_mapping_into_the_effective_custom_tenant_claim() => _mappingIntoCustomTenant.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_mapping_into_the_default_tenant_when_unset() => _mappingIntoDefaultTenant.Failed.ShouldBeTrue();
    [Fact] void should_refuse_mapping_targets_differing_only_by_case() => _conflictingMappingTargets.Failed.ShouldBeTrue();

    static C.AuthProxy Configuration(
        Action<C.BearerRoute> adjust,
        bool backend = true,
        bool declareRoute = true,
        Action<C.AuthProxy>? adjustConfiguration = null)
    {
        var route = Route();
        adjust(route);

        var service = Service(declareRoute ? route : null);
        service.AnonymousPaths = ["/public"];
        if (!backend)
        {
            service.Backend = null;
        }

        var configuration = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service> { ["main"] = service },
        };
        adjustConfiguration?.Invoke(configuration);

        return configuration;
    }

    static C.BearerRoute Route(string prefix = "/mcp") => new()
    {
        PathPrefix = prefix,
        Issuers = [new C.BearerIssuer { Issuer = "https://auth.example.test/" }],
        Audiences = ["direct-api"],
        RequiredScopes = ["direct:read"],
        ResourceMetadataUrl = "https://direct.example.test/.well-known/oauth-protected-resource/mcp",
    };

    static C.Service Service(C.BearerRoute? route) => new()
    {
        Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.test" },
        BearerRoutes = route is null ? [] : [route],
    };

    static C.Service RequiringVerification(C.Service service)
    {
        service.IdentityVerification = C.IdentityVerificationMode.Required;
        return service;
    }
}
