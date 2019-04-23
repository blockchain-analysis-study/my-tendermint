package db

import (
	"fmt"
	"strings"
)

//----------------------------------------
// Main entry

type DBBackendType string

const (
	/**

	TODO 超级重要 DB类型
	这里有5中类型
	但其实是6中DB实例
	 */
	LevelDBBackend   DBBackendType = "leveldb" // legacy, defaults to goleveldb unless +gcc
	CLevelDBBackend  DBBackendType = "cleveldb"
	GoLevelDBBackend DBBackendType = "goleveldb"
	MemDBBackend     DBBackendType = "memdb"
	FSDBBackend      DBBackendType = "fsdb" // using the filesystem naively
)

type dbCreator func(name string, dir string) (DB, error)

var backends = map[DBBackendType]dbCreator{}

/**
TODO 重要
目前有 ：
c_level_db (2种)
go_level_db (2种)
mem_db
fsdb

等6种 DB
 */
func registerDBCreator(backend DBBackendType, creator dbCreator, force bool) {
	_, ok := backends[backend]
	if !force && ok {
		return
	}

	// 这里目前会被注册 6中db
	backends[backend] = creator
}

// NewDB creates a new database of type backend with the given name.
// NOTE: function panics if:
//   - backend is unknown (not registered)
//   - creator function, provided during registration, returns error
func NewDB(name string, backend DBBackendType, dir string) DB {
	dbCreator, ok := backends[backend]
	if !ok {
		keys := make([]string, len(backends))
		i := 0
		for k := range backends {
			keys[i] = string(k)
			i++
		}
		panic(fmt.Sprintf("Unknown db_backend %s, expected either %s", backend, strings.Join(keys, " or ")))
	}

	db, err := dbCreator(name, dir)
	if err != nil {
		panic(fmt.Sprintf("Error initializing DB: %v", err))
	}
	return db
}
