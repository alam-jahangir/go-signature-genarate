package Database

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	//"log"
)


func MysqlConnection(config Database) (*sql.DB, error) {

	db, err := sql.Open(
		config.Driver,
		config.Username+":"+config.Password+"@tcp("+config.Host+")/"+config.Name)

	//if err != nil {
	//	panic(err.Error())
	//}

	return db, err
}
