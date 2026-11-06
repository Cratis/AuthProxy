// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.given;

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackSender;

/// <summary>
/// A failed callback is logged without the secret, so a log line can never leak the credential.
/// </summary>
public class when_a_failure_is_logged : given.a_sender
{
    sealed class Failing : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("connection refused");
    }

    RecordingLogger<SignInCallbackSender> _logger;

    protected override HttpMessageHandler CreateHandler() => new Failing();

    async Task Because()
    {
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new Failing(), false));
        _logger = new RecordingLogger<SignInCallbackSender>();
        await new SignInCallbackSender(factory, _signer, _configuration, _logger).Send(CreateRequest(), CancellationToken.None);
    }

    [Fact] void should_log_the_failure() => _logger.Messages.Count.ShouldEqual(1);
    [Fact] void should_not_log_the_secret() => _logger.Text.ShouldNotContain("s3cret");
    [Fact] void should_not_log_the_subject() => _logger.Text.ShouldNotContain("user-1");
}
