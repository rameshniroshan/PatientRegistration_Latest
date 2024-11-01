using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Patient_Registration.Migrations
{
    /// <inheritdoc />
    public partial class createdbfirst : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Call_LoyaltyPrograms",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    LoyaltyName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    LoyaltyDescription = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    Active = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Call_LoyaltyPrograms", x => x.Id);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Call_LoyaltyPrograms");
        }
    }
}
