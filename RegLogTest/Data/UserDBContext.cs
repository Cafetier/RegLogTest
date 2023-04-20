using Microsoft.EntityFrameworkCore;
using RegLogTest.Models;

namespace RegLogTest.Data
{
    public class UserDBContext : DbContext
    {
        public UserDBContext(DbContextOptions<UserDBContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
    }
}
