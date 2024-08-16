package config

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

type Config_type int

const (
	CFG_ETCD Config_type = iota
)

type ConfigReader interface {
	GetReader() (io.Reader, error)
}

func GetRemoteConfigManager(cfgtype Config_type, endpoint string, path string) (ConfigReader, error) {
	switch cfgtype {
	case CFG_ETCD:
		return &ConfigEtcdReader{
			endpoint: endpoint,
			path:     path,
		}, nil
	default:
		return nil, fmt.Errorf("unsupport remote config type: %d", cfgtype)
	}
}

type ConfigEtcdReader struct {
	endpoint string
	path     string
}

var _ ConfigReader = (*ConfigEtcdReader)(nil)

func (cr *ConfigEtcdReader) GetReader() (io.Reader, error) {
	timeout := 5 * time.Second
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{cr.endpoint},
		DialTimeout: timeout,
	})
	if err != nil {
		return nil, err
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	res, err := cli.Get(ctx, cr.path)
	cancel()
	if err != nil {
		return nil, err
	}
	if res.Count != 1 {
		return nil, fmt.Errorf("getting from etcd with key [%s], res count %d not equal to 1", cr.path, res.Count)
	}
	return bytes.NewReader(res.Kvs[0].Value), nil
}
