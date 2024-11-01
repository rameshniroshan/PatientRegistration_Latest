using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace Patient_Registration.Models
{
    public class Call_LoyaltyPrograms
    {
        [Key]
        [Required]
        [Column(Order = 1)]
        public int Id { get; set; }

        [Required]
        [Column(Order = 2)]
        [Display(Name = "Loyalty Program Name:")]
        public string LoyaltyName { get; set; }

        [Column(Order = 3)]
        [Display(Name = "Description:")]
        public string? LoyaltyDescription { get; set; }

        [Column(Order = 4)]
        [Display(Name = "Active:")]
        public string Active { get; set; }
    }
}
