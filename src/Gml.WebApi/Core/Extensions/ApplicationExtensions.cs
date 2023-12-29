using Gml.Core.Launcher;
using Gml.WebApi.Core.Handlers;
using GmlCore.Interfaces;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.OpenApi.Models;

namespace Gml.WebApi.Core.Extensions;

public static class ApplicationExtensions
{
    public static WebApplicationBuilder RegisterServices(this WebApplicationBuilder builder)
    {
        var configuration = builder.Configuration.GetSection("ProjectName").Value
                            ?? throw new Exception("AppSettings error, section 'ProjectName' not found");

        var directory = builder.Configuration.GetSection("ProjectPath").Value
                        ?? throw new Exception("AppSettings error, section 'ProjectPath' not found");

        builder.Services.AddSingleton<IGmlManager>(_ => new GmlManager(new GmlSettings(configuration, directory)));

        builder.Services.AddCors(options => options.AddPolicy("CorsPolicy",
            policyBuilder =>
            {
                policyBuilder.WithOrigins("http://localhost:8080");
            }));

        builder.Services.AddSwaggerGen(options =>
        {
            options.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "Gml.Web.Api",
                Description = "Api for administration yours game profiles",
                Version = "v1"
            });

            options.AddSecurityDefinition("Basic", new OpenApiSecurityScheme
            {
                In = ParameterLocation.Header,
                Description = "Please",
            });

        });

        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        return builder;
    }

    public static WebApplication RegisterRoutes(this WebApplication app)
    {
        app.UseSwagger();
        app.UseSwaggerUI();

        app.UseHttpsRedirection();

        #region Profiles

        app.MapGet("/api/profiles", RequestHandler.GetClients);
        app.MapPost("/api/profiles", RequestHandler.CreateProfile);
        app.MapDelete("/api/profiles", RequestHandler.DeleteProfile);


        app.MapPost("/api/profiles/info", RequestHandler.GetProfileInfo);
        app.MapPost("/api/profiles/restore", RequestHandler.RestoreProfileInfo);
        app.MapPost("/api/profiles/pack", RequestHandler.PackProfile);

        app.MapGet("/api/file/{fileHash}", RequestHandler.DownloadFile);

        #endregion

        app.MapGet("/", () => Results.Ok("Hello world!"));


        return app;
    }

    public static WebApplication AddMiddlewares(this WebApplication app)
    {
        app.UseCors("CorsPolicy");

        return app;
    }
}
