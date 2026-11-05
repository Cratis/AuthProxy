// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend;

public class and_the_signing_key_is_not_secret : given.an_auth_proxy_and_a_backend
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task should_refuse_without_resolving_the_parameter_or_configuring_either_resource(bool publish)
    {
        var builder = publish ? DistributedApplication.CreateBuilder(["--operation", "publish"]) : DistributedApplication.CreateBuilder();
        var proxy = builder.AddContainer("proxy", "cratis/authproxy");
        var api = builder.AddContainer("api", "example/api");
        var key = builder.AddParameter("plain-api-key", () => throw new InvalidOperationException("Parameter resolution is forbidden in this spec."));
        var exception = Catch.Exception(() => proxy.WithSignedForwardingTo(api, signingKey: key));

        exception.ShouldBeOfExactType<ArgumentException>();
        var argument = (ArgumentException)exception;
        argument.ParamName.ShouldEqual("signingKey");
        argument.Message.ShouldContain("plain-api-key");
        argument.Message.ShouldContain("secret: true");
        (await RawEnvironmentOf(proxy.Resource)).ShouldBeEmpty();
        (await RawEnvironmentOf(api.Resource)).ShouldBeEmpty();
        builder.Resources.OfType<ParameterResource>().Count().ShouldEqual(1);
    }
}
