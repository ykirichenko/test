using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using iknowscore.Services.Exceptions;
using iknowscore.Services.Interfaces;
using iknowscore.Services.ViewModels;
using iknowscore.Services.ViewModels.ExternalAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace iknowscore.API.Controllers
{
    [Produces("application/json")]
    [Route("api/[controller]")]
    public class TokenController : Controller
    {
        private static readonly HttpClient Client = new HttpClient();

        private readonly IConfiguration _config;
        private readonly IPlayerService _playerService;

        public TokenController(IConfiguration config, IPlayerService playerService)
        {
            _config = config;
            _playerService = playerService;
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> CreateToken([FromBody]LoginModel login)
        {
            IActionResult response = Unauthorized();

            var player = await _playerService.LoginPlayerAsync(login.Email, login.Password);
            if (player != null)
            {
                var tokenString = BuildToken();
                response = Ok(new { token = tokenString });
            }

            return response;
        }

        // POST api/token/facebook
        [HttpPost("facebook")]
        public async Task<IActionResult> Facebook([FromBody]FacebookAuthViewModel model)
        {
            if (model == null || string.IsNullOrWhiteSpace(model.AccessToken))
            {
                throw new FacebookException("Invalid facebook token");
            }

            // 1.generate an app access token
            var appId = _config["Facebook:AppID"];
            var appSecret = _config["Facebook:AppSecret"];
            var appAccessTokenResponse = await Client.GetStringAsync($"https://graph.facebook.com/oauth/access_token?client_id={appId}&client_secret={appSecret}&grant_type=client_credentials");
            var appAccessToken = JsonConvert.DeserializeObject<FacebookAppAccessToken>(appAccessTokenResponse);

            // 2. validate the user access token
            var userAccessTokenValidationResponse = await Client.GetStringAsync($"https://graph.facebook.com/debug_token?input_token={model.AccessToken}&access_token={appAccessToken.AccessToken}");
            var userAccessTokenValidation = JsonConvert.DeserializeObject<FacebookApiResponses>(userAccessTokenValidationResponse);

            if (!userAccessTokenValidation.Data.IsValid)
            {
                throw new FacebookException("Invalid facebook token");
            }

            // 3. we've got a valid token so we can request user data from fb
            var userInfoResponse = await Client.GetStringAsync($"https://graph.facebook.com/v2.8/me?fields=id,email,first_name,last_name,name,gender,locale,birthday,picture&access_token={model.AccessToken}");
            var userInfo = JsonConvert.DeserializeObject<FacebookUserData>(userInfoResponse);

            // 4. ready to create the local user account (if necessary) and jwt
            var user = await _playerService.GetPlayerByEmailAsync(userInfo.Email);
            if (user == null)
            {
                var newPlayer = new PlayerViewModel
                {
                    FirstName = userInfo.FirstName,
                    LastName = userInfo.LastName,
                    Email = userInfo.Email
                };

                await _playerService.RegisterPlayerAsync(newPlayer);
                user = await _playerService.GetPlayerByEmailAsync(userInfo.Email);
            }

            // generate the jwt for the local user...
            if (user == null)
            {
                throw new FacebookException("Failed to create local player account");
            }

            var tokenString = BuildToken();
            return Ok(new { token = tokenString });
        }

        public class LoginModel
        {
            public string Email { get; set; }
            public string Password { get; set; }
        }
    }
}