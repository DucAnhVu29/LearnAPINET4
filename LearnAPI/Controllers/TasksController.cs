using Microsoft.Build.Framework;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Data.Entity.Migrations;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;

namespace LearnAPI.Controllers
{
    [RoutePrefix("api/tasks")]
    public class TasksController : ApiController
    {
        // GET: api/Task
        public IEnumerable<Task> Get()
        {
            using (var context = new LearningEntities4())
            {
                return context.Tasks.ToList();
            }
        }

        // GET: api/Task/5
        public Task Get(int id)
        {
            using (var context = new LearningEntities4())
            {
                var data = context.Tasks.Where(x => x.ID == id).SingleOrDefault();
                return data;
            }
        }

        // POST: api/Task
        public void Post([FromBody]Task task)
        {
            using (var context = new LearningEntities4())
            {
                context.Tasks.Add(task);

                context.SaveChanges();
            }
        }

        // PUT: api/Task/5
        public void Put(int id, [FromBody]Task task)
        {
            Console.WriteLine(Request);
            using(var context = new LearningEntities4())
            {
                var data = context.Tasks.Where(x => x.ID == id).SingleOrDefault();

                //data.Name = task.Name;
                //data.Description = task.Description;
                //data.StartDate = task.StartDate;
                //data.DueDate = task.DueDate;
                //data.Status = task.Status;
                data.Name =  !string.IsNullOrEmpty(task.Name) ? task.Name : data.Name;
                data.Description = !string.IsNullOrEmpty(task.Description) ? task.Description : data.Description;
                data.StartDate = (task.StartDate != null) ? task.StartDate : data.StartDate;
                data.DueDate = (task.DueDate != null) ? task.DueDate : data.DueDate;
                data.Status = !string.IsNullOrEmpty(task.Status) ? task.Status : data.Status;

                context.SaveChanges();
            }
        }

        // DELETE: api/Task/5
        public void Delete(int id)
        {
            using(var context = new LearningEntities4())
            {
                var data = context.Tasks.Where(x => x.ID == id).SingleOrDefault();
                context.Tasks.Remove(data);
                context.SaveChanges();
            }
        }
    }
}
