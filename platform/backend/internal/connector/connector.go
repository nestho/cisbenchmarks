package connector

type Connector interface {
	Run(cmd string) (string, int, error)
	ReadFile(path string) (string, error)
	Close()
}
