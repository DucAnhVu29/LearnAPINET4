using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Principal;
using Newtonsoft.Json.Linq;
using System.Web.Http.Results;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Ajax.Utilities;
using Microsoft.IdentityModel.Tokens;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Newtonsoft.Json;
using System.Web;
using System.Web.Http.Cors;

namespace LearnAPI.Controllers
{
    [RoutePrefix("api/accounts")]
    public class AccountsController : ApiController
    {
        // GET: api/Accounts
        [HttpGet]
        [Route("")]
        public HttpResponseMessage Get()
        {
            HttpResponseMessage response;
            if (checkSession())
            {
                using (var context = new LearningEntities4())
                {
                    var data = context.Accounts.ToList();
                    response = Request.CreateResponse(HttpStatusCode.OK, data);
                    response.Headers.CacheControl = new CacheControlHeaderValue();
                    return response;
                }
            }
            response = Request.CreateResponse(HttpStatusCode.NotFound, "Please login to countinue");
            response.Headers.CacheControl = new CacheControlHeaderValue();
            return response;
        }

        // GET: api/Accounts/5
        [HttpGet]
        public HttpResponseMessage Get(int id)
        {
            HttpResponseMessage response;
            if (checkSession())
            {
                using (var context = new LearningEntities4())
                {
                    var data = context.Accounts.Where(x => x.ID == id).SingleOrDefault();
                    response = Request.CreateResponse(HttpStatusCode.OK, data);
                    response.Headers.CacheControl = new CacheControlHeaderValue();
                    return response;
                }
            }
            response = Request.CreateResponse(HttpStatusCode.NotFound, "Please login to countinue");
            response.Headers.CacheControl = new CacheControlHeaderValue();
            return response;
        }

        // POST: api/Accounts
        [HttpPost]
        [Route("")]
        public void Post([FromBody] Account account)
        {
            var salt = new byte[128 / 8];

            string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: account.Password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 256 / 8));

            account.Password = hashed;

            using (var context = new LearningEntities4())
            {
                context.Accounts.Add(account);

                context.SaveChanges();
            }
        }

        [HttpGet]
        [Route("checkRole")]
        public HttpResponseMessage CheckRole()
        {
            Account account = DecodeTokenHeader();
            if (account != null)
            {
                HttpResponseMessage responseOK = Request.CreateResponse(HttpStatusCode.OK, account.role);
                responseOK.Headers.CacheControl = new CacheControlHeaderValue();
                return responseOK;
            }

            HttpResponseMessage response = Request.CreateResponse(HttpStatusCode.NotFound);
            response.Headers.CacheControl = new CacheControlHeaderValue();
            return response;
        }

        // PUT: api/Accounts/5
        public HttpResponseMessage Put(int id, [FromBody]Account value)
        {
            HttpResponseMessage response;

            if (checkSession())
            {
                var account = DecodeTokenSession();
                if(account.role == "admin")
                {
                    using (var context = new LearningEntities4())
                    {
                        var data = context.Accounts.Where(x => x.ID == id).SingleOrDefault();

                        if(data != null)
                        {
                            data = value;
                            context.SaveChanges();
                            response = Request.CreateResponse(HttpStatusCode.OK, data);
                            response.Headers.CacheControl = new CacheControlHeaderValue();
                            return response;
                        }

                        response = Request.CreateResponse(HttpStatusCode.NotFound);
                        response.Headers.CacheControl = new CacheControlHeaderValue();
                        return response;
                    }
                }
                response = Request.CreateResponse(HttpStatusCode.NotFound, "You are not authorize to update account info!");
                response.Headers.CacheControl = new CacheControlHeaderValue();
                return response;
            }
            response = Request.CreateResponse(HttpStatusCode.NotFound, "Please login!");
            response.Headers.CacheControl = new CacheControlHeaderValue();
            return response;
        }

        // DELETE: api/Accounts/5
        public void Delete(int id)
        {

        }

        // LOGIN
        [HttpPost]
        [AllowAnonymous]
        [Route("login")]
        public HttpResponseMessage Login([FromBody] Account account)
        {
            var salt = new byte[128 / 8];

            string pswTemp = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: account.Password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 256 / 8));

            using(var context = new LearningEntities4())
            {
                HttpResponseMessage response;
                var data = context.Accounts.Where(x => x.Password.Equals(pswTemp) && x.Email.Equals(account.Email)).SingleOrDefault();
                if (data != null)
                {
                    string jwtToken = GetToken(data);
                    if(jwtToken != null)
                    {
                        //var session = HttpContext.Current.Session;
                        //Session["token"] = jwtToken;
                        HttpContext.Current.Session["token"] = jwtToken;
                        HttpContext.Current.Session["account"] = data;
                        Object responseData = new { account = data, token = jwtToken, message = "Login successfully!" };
                        response = Request.CreateResponse(HttpStatusCode.OK, responseData);
                        response.Headers.CacheControl = new CacheControlHeaderValue();
                        return response;
                    }
                    response = Request.CreateResponse(HttpStatusCode.NotFound, "Please try again");
                    response.Headers.CacheControl = new CacheControlHeaderValue();
                    return response;

                } else
                {
                    Object responseData = new { account = data, message = "Incorrect email or password!" };
                    response = Request.CreateResponse(HttpStatusCode.NotFound, responseData);
                    response.Headers.CacheControl = new CacheControlHeaderValue();
                    return response;
                }
            }
        }

        [HttpPost]
        [Route("logout")]
        public void Logout()
        {
            HttpContext.Current.Session.Clear();
        }

        [HttpGet]
        [Route("checkEmail")]
        public bool CheckEmailViaRequest(string email)
        {
            using(var content = new LearningEntities4())
            {
                var data = content.Accounts.Where(x => x.Email.Equals(email)).SingleOrDefault();
                if(data != null)
                {
                    return true;
                }     
            }
            return false;
        }

        public string GetToken(Account account)
        {
            var key = ConfigurationManager.AppSettings["JwtKey"];

            var issuer = ConfigurationManager.AppSettings["JwtIssuer"];

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            //Create a List of Claims, Keep claims name short    
            var permClaims = new List<Claim>();
            permClaims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            permClaims.Add(new Claim("account", JsonConvert.SerializeObject(account)));

            //Create Security Token object by giving required parameters    
            var token = new JwtSecurityToken(issuer, //Issure    
                            issuer,  //Audience    
                            permClaims,
                            expires: DateTime.Now.AddHours(8),
                            signingCredentials: credentials);
            var jwt_token = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt_token.ToString();
        }

        private string GetHeaderToken()
        {
            string token = Request.Headers.Authorization.ToString();
            token = token.Replace("Bearer ", "");
            return token;
        }

        private string GetSessionToken()
        {
            return HttpContext.Current.Session["token"].ToString();
        }

        private Account DecodeTokenHeader()
        {
            string token = GetHeaderToken();

            var jwt_token = new JwtSecurityTokenHandler().ReadToken(token) as JwtSecurityToken;
            if(jwt_token != null)
            {
                var data = jwt_token.Claims.First(claim => claim.Type == "account").Value;
                var time = jwt_token.Claims.First(claim => claim.Type == "exp").Value;

                if(jwt_token.ValidTo > DateTime.Now)
                {
                    var account = JsonConvert.DeserializeObject<Account>(data);
                    return account;
                }
            }
            return null;
        }

        private Account DecodeTokenSession()
        {
            string token = GetSessionToken();
            var jwt_token = new JwtSecurityTokenHandler().ReadToken(token) as JwtSecurityToken;
            if (jwt_token != null)
            {
                var data = jwt_token.Claims.First(claim => claim.Type == "account").Value;
                var time = jwt_token.Claims.First(claim => claim.Type == "exp").Value;

                if (jwt_token.ValidTo > DateTime.Now)
                {
                    var account = JsonConvert.DeserializeObject<Account>(data);
                    return account;
                }
            }
            return null;
        }

        private bool checkSession()
        {
            if(HttpContext.Current.Session == null || HttpContext.Current.Session["token"] == null)
            {
                return false;
            }
            return true;
        }

    }
}
