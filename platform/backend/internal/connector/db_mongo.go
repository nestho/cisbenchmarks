package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	AuthDB   string
	Timeout  time.Duration
}

type MongoConnector struct {
	cfg    MongoConfig
	client *mongo.Client
	db     *mongo.Database
}

func NewMongoConnector(cfg MongoConfig) (*MongoConnector, error) {
	if cfg.Port == 0 {
		cfg.Port = 27017
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.Database == "" {
		cfg.Database = "admin"
	}
	if cfg.AuthDB == "" {
		cfg.AuthDB = "admin"
	}

	var uri string
	if cfg.User != "" && cfg.Password != "" {
		uri = fmt.Sprintf("mongodb://%s:%s@%s:%d/%s?authSource=%s",
			url.QueryEscape(cfg.User),
			url.QueryEscape(cfg.Password),
			cfg.Host,
			cfg.Port,
			cfg.Database,
			cfg.AuthDB,
		)
	} else {
		uri = fmt.Sprintf("mongodb://%s:%d/%s", cfg.Host, cfg.Port, cfg.Database)
	}

	clientOpts := options.Client().ApplyURI(uri).SetTimeout(cfg.Timeout)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	client, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mongodb: %w", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("mongodb ping failed (%s:%d): %w", cfg.Host, cfg.Port, err)
	}

	return &MongoConnector{
		cfg:    cfg,
		client: client,
		db:     client.Database(cfg.Database),
	}, nil
}

// Run executes an administrative command or query against MongoDB
func (m *MongoConnector) Run(cmdStr string) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
	defer cancel()

	trimmed := strings.TrimSpace(cmdStr)
	var cmdDoc bson.D

	// Handle JSON input e.g. {"getParameter": 1, "auditLog": 1}
	if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") {
		var raw map[string]any
		if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
			return fmt.Sprintf("JSON parse error: %v", err), 1, err
		}
		for k, v := range raw {
			cmdDoc = append(cmdDoc, bson.E{Key: k, Value: v})
		}
	} else {
		// Handle shorthand syntax e.g. "getParameter: auditLog" or "serverStatus: 1"
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if v == "1" {
				cmdDoc = bson.D{{Key: k, Value: 1}}
			} else {
				cmdDoc = bson.D{{Key: k, Value: v}}
			}
		} else {
			cmdDoc = bson.D{{Key: trimmed, Value: 1}}
		}
	}

	var result bson.M
	err := m.db.RunCommand(ctx, cmdDoc).Decode(&result)
	if err != nil {
		return fmt.Sprintf("MONGO ERROR: %v", err), 1, err
	}

	outBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", result), 0, nil
	}
	return string(outBytes), 0, nil
}

func (m *MongoConnector) ReadFile(path string) (string, error) {
	return "", fmt.Errorf("file reading not supported on direct mongodb connection")
}

func (m *MongoConnector) Close() {
	if m.client != nil {
		_ = m.client.Disconnect(context.Background())
	}
}
