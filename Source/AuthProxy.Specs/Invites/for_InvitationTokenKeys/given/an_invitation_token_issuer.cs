// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys.given;

public class an_invitation_token_issuer : Specification
{
    protected readonly C.Invite Invite = new() { TokenMetadataUrl = "https://lobby.example.com/metadata", Issuer = "issuer", Audience = "audience" };
    protected readonly IssuerHandler Handler = new();
    protected readonly IssuerClock Clock = new();
    protected InvitationTokenKeys Provider;
    protected IReadOnlyDictionary<string, SecurityKey>? Keys;
    HttpClient _client;

    void Establish()
    {
        _client = new HttpClient(Handler);
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(InvitationTokenKeys.HttpClientName).Returns(_client);
        Provider = new InvitationTokenKeys(factory, NullLogger<InvitationTokenKeys>.Instance, Clock);
    }

    void Destroy()
    {
        Handler.Release.TrySetResult();
        Handler.FinishCancellation.TrySetResult();
        Provider.Dispose();
        _client.Dispose();
    }

    protected Task<IReadOnlyDictionary<string, SecurityKey>?> Get(bool refresh = false) => Provider.GetSigningKeys(Invite, CancellationToken.None, refresh);

    protected static async Task<Exception?> ObserveFailure(Task operation)
    {
        try
        {
            await operation;
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    protected class IssuerClock : TimeProvider
    {
        long _ticks = DateTimeOffset.UtcNow.Ticks;
        public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref _ticks), TimeSpan.Zero);
        internal void Advance(TimeSpan duration) => Interlocked.Add(ref _ticks, duration.Ticks);
    }

    protected class IssuerHandler : HttpMessageHandler
    {
        readonly string _modulus;
        readonly string _exponent;
        int _metadataRequests;
        int _keyRequests;

        internal IssuerHandler()
        {
            using var rsa = RSA.Create(2048);
            var parameters = rsa.ExportParameters(false);
            _modulus = Base64UrlEncoder.Encode(parameters.Modulus);
            _exponent = Base64UrlEncoder.Encode(parameters.Exponent);
        }

        internal string Issuer { get; set; } = "issuer";
        internal string Audience { get; set; } = "audience";
        internal string Kid { get; set; } = "known";
        internal HttpStatusCode Status { get; set; } = HttpStatusCode.OK;
        internal TimeSpan? MaxAge { get; set; } = TimeSpan.FromMinutes(5);
        internal string? OversizedBody { get; set; }
        internal bool UnknownLength { get; set; }
        internal bool Delay { get; set; }
        internal bool HoldCancellation { get; set; }
        internal int MetadataRequests => Volatile.Read(ref _metadataRequests);
        internal int KeyRequests => Volatile.Read(ref _keyRequests);
        internal TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource CancellationObserved { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource FinishCancellation { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var metadata = request.RequestUri!.AbsolutePath == "/metadata";
            if (metadata)
            {
                Interlocked.Increment(ref _metadataRequests);
                await DelayResponse(cancellationToken);
            }
            else
            {
                Interlocked.Increment(ref _keyRequests);
            }

            var body = OversizedBody ?? (metadata
                ? JsonSerializer.Serialize(new { issuer = Issuer, audience = Audience, jwks_uri = "https://lobby.example.com/keys", token_signing_alg_values_supported = new[] { "RS256" } })
                : JsonSerializer.Serialize(new { keys = new[] { new { kty = "RSA", use = "sig", alg = "RS256", kid = Kid, n = _modulus, e = _exponent } } }));
            var response = new HttpResponseMessage(Status) { Content = new StringContent(body) };
            if (UnknownLength)
            {
                response.Content = new StreamingContent(body);
            }
            response.Headers.CacheControl = new() { MaxAge = MaxAge };
            response.Headers.Location = new Uri("https://sink.example.com/");
            return response;
        }

        async Task DelayResponse(CancellationToken cancellationToken)
        {
            if (!Delay)
            {
                return;
            }
            Started.TrySetResult();
            try
            {
                await Release.Task.WaitAsync(cancellationToken);
            }
            catch (OperationCanceledException) when (HoldCancellation)
            {
                CancellationObserved.TrySetResult();
                await FinishCancellation.Task;
                throw;
            }
        }
    }

    sealed class StreamingContent(string body) : HttpContent
    {
        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            stream.WriteAsync(System.Text.Encoding.UTF8.GetBytes(body)).AsTask();
    }
}
