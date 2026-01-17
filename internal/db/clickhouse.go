package db

import (
	"github.com/ClickHouse/clickhouse-go/v2"
	"time"
)

func Connect() (clickhouse.Conn, error) {
	return clickhouse.Open(&clickhouse.Options{
		Addr: []string{"127.0.0.1:9000"},
		Auth: clickhouse.Auth{
			Database: "scanning",
		},
		DialTimeout: time.Second * 30,
		MaxOpenConns: 20,
	})
}