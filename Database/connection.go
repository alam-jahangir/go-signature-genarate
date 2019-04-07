package Database

import (
	"Configuration"
	"database/sql"
)

type Database struct {
	Driver   string
	Host     string
	Username string
	Password string
	Name     string
	Port     string
}

type DbAdapter struct {
	DriverName string
	DbConn *sql.DB
}

func Connection(config Configuration.Config) (DbAdapter, error) {

	var db DbAdapter
	var err error
	var dbConnection *sql.DB

	dbSetting := Database{
		config.Database.Driver,
		config.Database.Host,
		config.Database.Username,
		config.Database.Password,
		config.Database.Name,
		config.Database.Port}

	db.DriverName = config.Database.Driver

	switch config.Database.Driver {

	case "mysql":
		dbConnection, err = MysqlConnection(dbSetting)
		break

	case "mongo":
		// TO DO
		break

	case "postgresql":
		// TO DO
		break

	default:
		//nothing
	}

	db.DbConn = dbConnection
	return db, err
}
