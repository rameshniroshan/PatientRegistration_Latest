using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Patient_Registration.Migrations
{
    /// <inheritdoc />
    public partial class createdbfirstdb : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<bool>(
                name: "Active",
                table: "Call_Patients",
                type: "bit",
                nullable: false,
                oldClrType: typeof(bool),
                oldType: "bit")
                .Annotation("Relational:ColumnOrder", 23)
                .OldAnnotation("Relational:ColumnOrder", 22);

            migrationBuilder.AddColumn<int>(
                name: "LoyaltyProgramId",
                table: "Call_Patients",
                type: "int",
                nullable: true)
                .Annotation("Relational:ColumnOrder", 22);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "LoyaltyProgramId",
                table: "Call_Patients");

            migrationBuilder.AlterColumn<bool>(
                name: "Active",
                table: "Call_Patients",
                type: "bit",
                nullable: false,
                oldClrType: typeof(bool),
                oldType: "bit")
                .Annotation("Relational:ColumnOrder", 22)
                .OldAnnotation("Relational:ColumnOrder", 23);
        }
    }
}
