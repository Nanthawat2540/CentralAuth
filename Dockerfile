FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY CentralAuth.csproj .
RUN dotnet restore CentralAuth.csproj --locked-mode 2>/dev/null || dotnet restore CentralAuth.csproj

COPY . .
RUN dotnet publish CentralAuth.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .

# Create logs directory
RUN mkdir -p logs

EXPOSE 8080
ENTRYPOINT ["dotnet", "CentralAuth.dll"]
