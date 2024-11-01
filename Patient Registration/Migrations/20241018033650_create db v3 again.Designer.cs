﻿// <auto-generated />
using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Patient_Registration.Data;

#nullable disable

namespace Patient_Registration.Migrations
{
    [DbContext(typeof(RegisterDb))]
    [Migration("20241018033650_create db v3 again")]
    partial class createdbv3again
    {
        /// <inheritdoc />
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "8.0.10")
                .HasAnnotation("Relational:MaxIdentifierLength", 128);

            SqlServerModelBuilderExtensions.UseIdentityColumns(modelBuilder);

            modelBuilder.Entity("Patient_Registration.Models.Call_Guardian", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("Id"));

                    b.Property<string>("GuardianPatientName")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("MobileNo")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.HasKey("Id");

                    b.ToTable("Call_Guardian");
                });

            modelBuilder.Entity("Patient_Registration.Models.Call_Patients", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int")
                        .HasColumnOrder(1);

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("Id"));

                    b.Property<bool>("Active")
                        .HasColumnType("bit")
                        .HasColumnOrder(22);

                    b.Property<string>("DOB")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(8);

                    b.Property<string>("Designation")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(5);

                    b.Property<string>("Email")
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(18);

                    b.Property<int?>("FamilyId")
                        .HasColumnType("int")
                        .HasColumnOrder(21);

                    b.Property<string>("Gender")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(9);

                    b.Property<int>("GuardianID")
                        .HasColumnType("int")
                        .HasColumnOrder(13);

                    b.Property<string>("GuardianName")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(14);

                    b.Property<string>("LoyaltyNo")
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(16);

                    b.Property<string>("MemberID")
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(17);

                    b.Property<string>("MobileNo")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(2);

                    b.Property<string>("NIC")
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(3);

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(6);

                    b.Property<string>("Nationality")
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(11);

                    b.Property<string>("PassportNo")
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(4);

                    b.Property<string>("RelationGuardian")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(15);

                    b.Property<string>("Religion")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(12);

                    b.Property<string>("ResidentArea")
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(10);

                    b.Property<string>("SocialId")
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(20);

                    b.Property<string>("SpecialConditions")
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(19);

                    b.Property<string>("Surname")
                        .HasColumnType("nvarchar(max)")
                        .HasColumnOrder(7);

                    b.HasKey("Id");

                    b.ToTable("Call_Patients");
                });

            modelBuilder.Entity("Patient_Registration.Models.Call_Users", b =>
                {
                    b.Property<int>("UserId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("UserId"));

                    b.Property<bool>("Active")
                        .HasColumnType("bit");

                    b.Property<string>("Password")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<int>("Type")
                        .HasColumnType("int");

                    b.Property<string>("UserName")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.HasKey("UserId");

                    b.ToTable("Call_Users");
                });
#pragma warning restore 612, 618
        }
    }
}