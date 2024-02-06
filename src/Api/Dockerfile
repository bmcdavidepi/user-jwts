FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine AS base
WORKDIR /app
# https://stackoverflow.com/a/74939792
RUN apk add --no-cache icu-libs icu-data-full tzdata
ENV TZ=America/New_York
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false
USER app
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release

WORKDIR /code
COPY ["src/Api/*.csproj", "src/Api/"]
RUN dotnet restore src/Api/Api.csproj
COPY . .
WORKDIR /code/src/Api
RUN dotnet build Api.csproj --no-restore -c $BUILD_CONFIGURATION -o /app/build -p:TreatWarningsAsErrors=true

FROM build AS test
WORKDIR /code/tests

COPY ["tests/Tests/*.csproj", "Tests/"]
RUN dotnet restore Tests/Tests.csproj

COPY ["tests/Tests/", "Tests/"]

WORKDIR /code/tests/Tests
RUN dotnet build Tests.csproj -c Debug --no-restore -p:TreatWarningsAsErrors=true

ENTRYPOINT ["dotnet", "test", "-c", "Debug", "--no-restore", "--no-build"]

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish --no-restore /code/src/Api/Api.csproj -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Api.dll"]