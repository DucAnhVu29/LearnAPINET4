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
        public IEnumerable<Account> Get()
        {
            using (var context = new LearningEntities4())
            {
                var data = context.Accounts.ToList();
                return data;
            }
        }

        // GET: api/Accounts/5

        public Account Get(int id)
        {
            using (var context = new LearningEntities4())
            {
                var data = context.Accounts.Where(x => x.ID == id).SingleOrDefault();
                return data;
            }
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
            Account account = DecodeToken();
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
        public void Put(int id, [FromBody]string value)
        {
            
        }

        // DELETE: api/Accounts/5
        public void Delete(int id)
        {

        }

        // LOGIN
        [HttpPost]
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
                var data = context.Accounts.Where(x => x.Password.Equals(pswTemp) && x.Email.Equals(account.Email)).SingleOrDefault();
                if (data != null)
                {
                    Object responseData = new {account = data , token = GetToken(data), message = "Login successfully!"};
                    HttpResponseMessage response = Request.CreateResponse(HttpStatusCode.OK, responseData);
                    response.Headers.CacheControl = new CacheControlHeaderValue();
                    return response;
                } else
                {
                    Object responseData = new { account = data, message = "Incorrect email or password!" };
                    HttpResponseMessage response = Request.CreateResponse(HttpStatusCode.NotFound, responseData);
                    response.Headers.CacheControl = new CacheControlHeaderValue();
                    return response;
                }
            }
        }

        [HttpGet]
        [Route("checkEmail")]
        public bool CheckEmail(string email)
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

        public string GetHeaderToken()
        {
            string token = Request.Headers.Authorization.ToString();
            token = token.Replace("Bearer ", "");
            return token;
        }

        public Account DecodeToken()
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
    }
}
