using Microsoft.EntityFrameworkCore;
using Patient_Registration.Models;

namespace Patient_Registration.Data
{
    public class RegisterDb :DbContext
    {
        public RegisterDb(DbContextOptions<RegisterDb>options):base(options)
        {
                
        }
        public DbSet<Patient_Registration.Models.Call_Users> Call_Users { get; set; }
        public DbSet<Patient_Registration.Models.Call_Patients> Call_Patients { get; set; }
           
        public DbSet<Patient_Registration.Models.Call_Guardian> Call_Guardian { get; set; }

        public DbSet<Patient_Registration.Models.Call_LoyaltyPrograms> Call_LoyaltyPrograms { get; set; }


    }
}
