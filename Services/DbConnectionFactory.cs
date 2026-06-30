using System.Data;
using Microsoft.Data.SqlClient;

namespace CentralAuth.Services;

public interface IDbConnectionFactory
{
    IDbConnection Create();
}

public class SqlConnectionFactory(IConfiguration config) : IDbConnectionFactory
{
    private readonly string _connStr = config.GetConnectionString("CentralAuth")
        ?? throw new InvalidOperationException("ConnectionStrings:CentralAuth missing");

    public IDbConnection Create() => new SqlConnection(_connStr);
}
