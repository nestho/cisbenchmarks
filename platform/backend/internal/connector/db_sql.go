package connector

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/microsoft/go-mssqldb"
)

type DBType string

const (
	DBPostgreSQL DBType = "postgres"
	DBMySQL      DBType = "mysql"
	DBMSSQL      DBType = "mssql"
)

type DBConfig struct {
	Type     DBType
	Host     string
	Port     int
	User     string
	Password string
	Database string
	SSLMode  string // disable, require, verify-ca, verify-full
	Timeout  time.Duration
}

type SQLConnector struct {
	cfg DBConfig
	db  *sql.DB
}

func NewSQLConnector(cfg DBConfig) (*SQLConnector, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.Database == "" {
		switch cfg.Type {
		case DBPostgreSQL:
			cfg.Database = "postgres"
		case DBMySQL:
			cfg.Database = "mysql"
		case DBMSSQL:
			cfg.Database = "master"
		}
	}

	var dsn string
	var driverName string

	switch cfg.Type {
	case DBPostgreSQL:
		driverName = "pgx"
		if cfg.Port == 0 {
			cfg.Port = 5432
		}
		ssl := cfg.SSLMode
		if ssl == "" {
			ssl = "prefer"
		}
		dsn = fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s&connect_timeout=%d",
			url.QueryEscape(cfg.User),
			url.QueryEscape(cfg.Password),
			cfg.Host,
			cfg.Port,
			cfg.Database,
			ssl,
			int(cfg.Timeout.Seconds()),
		)

	case DBMySQL:
		driverName = "mysql"
		if cfg.Port == 0 {
			cfg.Port = 3306
		}
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?timeout=%s&readTimeout=%s",
			cfg.User,
			cfg.Password,
			cfg.Host,
			cfg.Port,
			cfg.Database,
			cfg.Timeout,
			cfg.Timeout,
		)

	case DBMSSQL:
		driverName = "sqlserver"
		if cfg.Port == 0 {
			cfg.Port = 1433
		}
		query := url.Values{}
		query.Add("database", cfg.Database)
		query.Add("connection timeout", fmt.Sprintf("%d", int(cfg.Timeout.Seconds())))
		if cfg.SSLMode == "disable" {
			query.Add("encrypt", "disable")
		} else {
			query.Add("encrypt", "true")
			query.Add("TrustServerCertificate", "true")
		}
		u := &url.URL{
			Scheme:   "sqlserver",
			User:     url.UserPassword(cfg.User, cfg.Password),
			Host:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			RawQuery: query.Encode(),
		}
		dsn = u.String()

	default:
		return nil, fmt.Errorf("unsupported database type: %s", cfg.Type)
	}

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open db driver: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("database connection failed (%s:%d): %w", cfg.Host, cfg.Port, err)
	}

	return &SQLConnector{cfg: cfg, db: db}, nil
}

// Run executes a read-only audit SQL query and formats the output
func (c *SQLConnector) Run(query string) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout)
	defer cancel()

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Sprintf("SQL ERROR: %v", err), 1, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return "", 1, err
	}

	var sb strings.Builder
	sb.WriteString(strings.Join(cols, " | "))
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("-", len(cols)*16))
	sb.WriteString("\n")

	count := 0
	for rows.Next() {
		count++
		values := make([]any, len(cols))
		scanArgs := make([]any, len(cols))
		for i := range values {
			scanArgs[i] = &values[i]
		}
		if err := rows.Scan(scanArgs...); err != nil {
			return sb.String(), 1, err
		}

		rowStr := make([]string, len(cols))
		for i, val := range values {
			if val == nil {
				rowStr[i] = "NULL"
			} else {
				switch v := val.(type) {
				case []byte:
					rowStr[i] = string(v)
				default:
					rowStr[i] = fmt.Sprintf("%v", v)
				}
			}
		}
		sb.WriteString(strings.Join(rowStr, " | "))
		sb.WriteString("\n")
	}

	if err := rows.Err(); err != nil {
		return sb.String(), 1, err
	}

	if count == 0 {
		sb.WriteString("(0 rows returned)\n")
	}

	return sb.String(), 0, nil
}

func (c *SQLConnector) ReadFile(path string) (string, error) {
	return "", fmt.Errorf("file reading not supported on direct database connection")
}

func (c *SQLConnector) Close() {
	if c.db != nil {
		c.db.Close()
	}
}
