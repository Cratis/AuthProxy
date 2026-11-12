# Builds the Arc sample for the AuthProxy consumer lane. The build context is the E2E folder.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props ./
COPY ArcSample/ArcSample.csproj ArcSample/
RUN dotnet restore ArcSample/ArcSample.csproj
COPY ArcSample/ ArcSample/
RUN dotnet publish ArcSample/ArcSample.csproj -c Release -o /out --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /out/ ./
ENV ASPNETCORE_URLS=http://+:8080
ENTRYPOINT ["dotnet", "ArcSample.dll"]
