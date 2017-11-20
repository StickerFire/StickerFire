using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.Cookies;
using StickerFire.Data;
using Microsoft.EntityFrameworkCore;
using StickerFire.Models;
using Microsoft.AspNetCore.Identity;

namespace StickerFire
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            
            services.Configure<MvcOptions>(options =>
            {
                options.Filters.Add(new RequireHttpsAttribute());
            });

            //Enable Cookies
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie("CookieLogin", options =>
                options.AccessDeniedPath = new PathString("/Account/Forbidden/"));

            //Enable Admin-Only policy
            services.AddAuthorization(options =>
            {
                options.AddPolicy("Admin Only", policy => policy.RequireRole("Admin"));
            });

            // This context is derived from IdentityDbContext. This context is responsible for the ASPNET Identity tables in the database. 
            services.AddDbContext<UserDbContext>(options =>
                    options.UseSqlServer(Configuration.GetConnectionString("StickerFireContext")));
            //This context is for campaign database model
            services.AddDbContext<StickerFireDbContext>(options =>
                    options.UseSqlServer(Configuration.GetConnectionString("StickerFireContext")));
            //Enable Identity Functionality using ApplicationUser model
            services.AddIdentity<ApplicationUser, IdentityRole>()
                   .AddEntityFrameworkStores<UserDbContext>()
                   .AddDefaultTokenProviders();

            //Enabel OAuth for Google +
            services.AddAuthentication().AddGoogle(googleOptions =>
            {
                googleOptions.ClientId = Configuration["Authentication:Google:ClientId"];
                googleOptions.ClientSecret = Configuration["Authentication:Google:ClientSecret"];
            });
            services.AddAuthentication().AddFacebook(facebookOptions =>
            {
                facebookOptions.AppId = Configuration["Authentication:Facebook:AppId"];
                facebookOptions.AppSecret = Configuration["Authentication:Facebook:AppSecret"];
            });

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseAuthentication();
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseStaticFiles();
            app.UseMvcWithDefaultRoute();

            app.Run(async (context) =>
            {
                await context.Response.WriteAsync("You dun messed up");
            });
        }
    }
}
