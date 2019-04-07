package Configuration

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	Database struct {
		Driver	 string `json:"driver"`
		Host     string `json:"host"`
		Username string `json:"username"`
		Password string `json:"password"`
		Name string `json:"name"`
		Port string `json:"port"`
	} `json:"database"`
	Redis struct{
		Host string `json:"host"`
		Port string `json:"port"`
	} `json:"redis"`
	ElasticSearch struct{
		Host string `json:"host"`
		Port string `json:"port"`
	} `json:"elasticsearch"`
	Host string `json:"host"`
	Port string `json:"port"`
}

func LoadConfiguration(file string) Config {
	var config Config
	configFile, err := os.Open(file)
	defer configFile.Close()
	if err != nil {
		fmt.Println(err.Error())
	}
	jsonParser := json.NewDecoder(configFile)
	jsonParser.Decode(&config)
	return config
}
